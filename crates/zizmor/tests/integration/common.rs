use anyhow::{Context as _, Result};
use camino::{Utf8Path, Utf8PathBuf};
use regex::{Captures, Regex};
use std::{env::current_dir, fs, io::ErrorKind, sync::LazyLock};
use tempfile::TempDir;

use assert_cmd::{Command, cargo};

/// The absolute path to the zizmor crate's root directory.
static ZIZMOR_ROOT: LazyLock<Utf8PathBuf> =
    LazyLock::new(|| Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR")));

/// The absolute path to the repository's root directory.
///
/// This is `ZIZMOR_ROOT/../..` since the `zizmor` crate
/// lives at `repo_root/crates/zizmor`.
static REPO_ROOT: LazyLock<Utf8PathBuf> =
    LazyLock::new(|| ZIZMOR_ROOT.parent().unwrap().parent().unwrap().into());

static CURRENT_DIR: LazyLock<Utf8PathBuf> = LazyLock::new(|| {
    let current_dir = current_dir().expect("Cannot figure out current directory");
    Utf8PathBuf::try_from(current_dir).expect("Cannot create UTF-8 path from current directory")
});

static TEST_PREFIX: LazyLock<Utf8PathBuf> = LazyLock::new(|| {
    let file_path = ZIZMOR_ROOT
        .join("tests")
        .join("integration")
        .join("test-data");

    if !file_path.exists() {
        panic!("Cannot find test data directory: {file_path}");
    }

    Utf8PathBuf::try_from(file_path).expect("Cannot create UTF-8 path from test data directory")
});

const CONFIG_PLACEHOLDER: &str = "@@CONFIG@@";
const INPUT_PLACEHOLDER: &str = "@@INPUT@@";
const REPO_ROOT_PLACEHOLDER: &str = "@@REPO_ROOT@@";
const WORKING_DIR_PLACEHOLDER: &str = "@@WORKING_DIR@@";
const TEST_PREFIX_PLACEHOLDER: &str = "@@TEST_PREFIX@@";
const VERSION_PLACEHOLDER: &str = "@@VERSION@@";

/// Matches any `@@PLACEHOLDER@@` — including the custom ones introduced by
/// [`Zizmor::add_filter`] — and any path-like suffix trailing it.
/// Used for Windows separator normalization; see [`Zizmor::scrub`].
static PLACEHOLDER_PATH_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"@@\w+@@[\\/\w.-]*").unwrap());

pub fn input_under_test(name: &str) -> Utf8PathBuf {
    let file_path = TEST_PREFIX.join(name);

    if !file_path.exists() {
        panic!("Cannot find input under test: {file_path}");
    }

    file_path
}

pub enum OutputMode {
    Stdout,
    #[allow(dead_code, reason = "currently not used by any integration test")]
    Stderr,
    Both,
}

#[derive(Default)]
pub enum NetworkMode {
    /// The zizmor run is implicitly offline or online, i.e. depends
    /// on whether `--gh-token`, etc.
    Implicit,
    /// The `zizmor` run is explicitly offline, i.e. runs 100% offline
    /// regardless of any other flags or state.
    #[default]
    ExplicitOffline,
    AssertOnline,
}

pub struct Zizmor {
    cmd: Command,
    stdin: Option<String>,
    unbuffer: bool,
    offline: NetworkMode,
    gh_token: bool,
    inputs: Vec<Utf8PathBuf>,
    working_dir: Utf8PathBuf,
    config: Option<String>,
    no_config: bool,
    output: OutputMode,
    expects_failure: Option<i32>,
    show_audit_urls: bool,
    filters: Vec<(String, String)>,
}

/// Environment variables that influence zizmor's behavior or output, scrubbed
/// from the child's inherited environment so runs are deterministic regardless
/// of the ambient environment. A test that exercises one of these sets it back
/// explicitly (e.g. `RUST_LOG` via [`Zizmor::setenv`], `GH_TOKEN` when online).
const SCRUBBED_ENV_VARS: &[&str] = &[
    "CI",
    "RUST_LOG",
    "NO_COLOR",
    "FORCE_COLOR",
    "CLICOLOR",
    "CLICOLOR_FORCE",
    "GIT_CEILING_DIRECTORIES",
];

/// Environment variable prefixes scrubbed for the same reason as
/// [`SCRUBBED_ENV_VARS`]. Covers the token/host vars (`GH_TOKEN`, `GH_HOST`,
/// `GITHUB_TOKEN`, `ZIZMOR_GITHUB_TOKEN`), every `ZIZMOR_*` CLI env alias, and
/// the ambient GitHub Actions context (`GITHUB_*`, `RUNNER_*`, `ACTIONS_*`).
const SCRUBBED_ENV_PREFIXES: &[&str] = &["GH_", "GITHUB_", "ZIZMOR_", "RUNNER_", "ACTIONS_"];

impl Zizmor {
    /// Create a new zizmor runner.
    pub fn new() -> Self {
        let mut cmd = Command::new(cargo::cargo_bin!());

        // Scrub our environment of any pre-existing variables
        // that would influence our tests. Individual tests
        // will re-add these as necessary.
        for (key, _) in std::env::vars_os() {
            let scrub = key.to_str().is_some_and(|name| {
                SCRUBBED_ENV_VARS.contains(&name)
                    || SCRUBBED_ENV_PREFIXES
                        .iter()
                        .any(|prefix| name.starts_with(prefix))
            });
            if scrub {
                cmd.env_remove(&key);
            }
        }

        Self {
            cmd,
            stdin: None,
            unbuffer: false,
            offline: NetworkMode::default(),
            gh_token: true,
            inputs: vec![],
            working_dir: CURRENT_DIR.clone(),
            config: None,
            no_config: false,
            output: OutputMode::Stdout,
            expects_failure: None,
            show_audit_urls: false,
            filters: vec![],
        }
    }

    pub fn stdin(mut self, input: impl Into<String>) -> Self {
        self.stdin = Some(input.into());
        self
    }

    pub fn args<'a>(mut self, args: impl IntoIterator<Item = &'a str>) -> Self {
        self.cmd.args(args);
        self
    }

    pub fn setenv(mut self, key: &str, value: &str) -> Self {
        self.cmd.env(key, value);
        self
    }

    pub fn input(mut self, input: impl Into<Utf8PathBuf>) -> Self {
        self.inputs.push(input.into());
        self
    }

    pub fn config(mut self, config: impl Into<String>) -> Self {
        self.config = Some(config.into());
        self
    }

    pub fn no_config(mut self, flag: bool) -> Self {
        self.no_config = flag;
        self
    }

    pub fn unbuffer(mut self, flag: bool) -> Self {
        self.unbuffer = flag;
        self
    }

    pub fn offline(mut self, flag: NetworkMode) -> Self {
        self.offline = flag;
        self
    }

    pub fn gh_token(mut self, flag: bool) -> Self {
        self.gh_token = flag;
        self
    }

    pub fn output(mut self, output: OutputMode) -> Self {
        self.output = output;
        self
    }

    pub fn expects_failure(mut self, code: i32) -> Self {
        self = self.output(OutputMode::Both);
        self.expects_failure = Some(code);
        self
    }

    pub fn show_audit_urls(mut self, flag: bool) -> Self {
        self.show_audit_urls = flag;
        self
    }

    pub fn working_dir(mut self, dir: impl Into<Utf8PathBuf>) -> Self {
        self.working_dir = dir.into();
        self.cmd.current_dir(&self.working_dir);
        self
    }

    pub fn add_filter(mut self, needle: impl Into<String>, replacement: impl Into<String>) -> Self {
        let replacement = format!("@@{replacement}@@", replacement = replacement.into());
        self.filters.push((needle.into(), replacement));
        self
    }

    pub fn run(mut self) -> Result<String> {
        if let Some(stdin) = &self.stdin {
            self.cmd.write_stdin(stdin.as_bytes());
        }

        match self.offline {
            NetworkMode::Implicit => (),
            NetworkMode::ExplicitOffline => {
                self.cmd.arg("--offline");
            }
            NetworkMode::AssertOnline => {
                // If we're running in online mode, we pre-assert the
                // presence of GH_TOKEN to make configuration failures more obvious.
                let token =
                    std::env::var("GH_TOKEN").context("online tests require GH_TOKEN to be set")?;

                if self.gh_token {
                    self.cmd.env("GH_TOKEN", token);
                }
            }
        }

        if self.no_config && self.config.is_some() {
            anyhow::bail!("API misuse: cannot set both --no-config and --config");
        }

        if self.no_config {
            self.cmd.arg("--no-config");
        }

        if let Some(config) = &self.config {
            self.cmd.arg("--config").arg(config);
        }

        if !self.unbuffer {
            // NOTE(ww): We explicitly disable progress bars in test runs
            // because of a tracing-indicatif bug that surfaces when we have
            // multiple spans and no terminal.
            // We only hit this when not using `unbuffer`, because `unbuffer`
            // simulates a TTY.
            // See: https://github.com/emersonford/tracing-indicatif/issues/24
            self.cmd.arg("--no-progress");
        }

        if self.show_audit_urls {
            self.cmd.arg("--show-audit-urls=always");
        } else {
            self.cmd.arg("--show-audit-urls=never");
        }

        for input in &self.inputs {
            self.cmd.arg(input);
        }

        let output = if self.unbuffer {
            // If we're using unbuffer, we need to rebuild the `Command`
            // from `zizmor args...` to `unbuffer zizmor args...`.
            let mut cmd = Command::new("unbuffer");
            let cmd = cmd.arg(self.cmd.get_program()).args(self.cmd.get_args());

            for (env, value) in self.cmd.get_envs() {
                match value {
                    Some(value) => {
                        cmd.env(env, value);
                    }
                    None => {
                        cmd.env_remove(env);
                    }
                }
            }

            match cmd.output() {
                Ok(output) => output,
                Err(err) => match err.kind() {
                    // Specialize the not found case, to make configuration failures
                    // more obvious.
                    ErrorKind::NotFound => {
                        panic!("TTY tests require `unbuffer` to be installed");
                    }
                    _ => panic!("error running `unbuffer`: {err}"),
                },
            }
        } else {
            self.cmd.output()?
        };

        let raw = String::from_utf8(match self.output {
            OutputMode::Stdout => output.stdout,
            OutputMode::Stderr => output.stderr,
            OutputMode::Both => [output.stderr, output.stdout].concat(),
        })?;

        if let Some(exit_code) = output.status.code() {
            // There are other nonzero exit codes that don't indicate failure;
            // these do. 1/2 are general errors, 3 is a collection error, 101 is Rust's panic exit code.
            let is_failure = matches!(exit_code, 1 | 2 | 3 | 101);
            match self.expects_failure {
                Some(expected_code) if is_failure => {
                    if exit_code != expected_code {
                        anyhow::bail!(
                            "zizmor exited with unexpected code {exit_code} (expected {expected_code}): {raw}"
                        );
                    }
                }
                Some(_) if !is_failure => {
                    anyhow::bail!("zizmor exited successfully but failure was expected: {raw}")
                }
                None if is_failure => {
                    anyhow::bail!("zizmor unexpectedly exited with code {exit_code}: {raw}")
                }
                _ => {}
            }
        }

        Ok(self.scrub(raw))
    }

    /// Scrubs `raw` into its snapshot-stable form: every host-specific path
    /// is redacted down to a `@@PLACEHOLDER@@`, and (on Windows) native
    /// separators are normalized to `/`.
    ///
    /// Pass order matters: each pass only sees what previous passes left
    /// behind. In particular, inputs are redacted before the repository root
    /// so that an input always redacts as a single `@@INPUT@@` token,
    /// never as `@@REPO_ROOT@@/@@INPUT@@`.
    fn scrub(&self, mut raw: String) -> String {
        // On Windows, canonicalized paths surface with a `\\?\` verbatim prefix
        // that has no cross-platform analogue (e.g. zizmor logs canonicalized
        // config-discovery candidates). Strip it (in both its plain and
        // Debug-escaped spellings) up front so the paths below redact cleanly
        // and match the Unix snapshots.
        if cfg!(windows) {
            raw = raw.replace(r"\\\\?\\", "");
            raw = raw.replace(r"\\?\", "");
        }

        if let Some(config) = &self.config {
            // The config is often an `input_under_test(..)` path, so it needs
            // the same multi-spelling treatment as the inputs below.
            redact(&mut raw, Utf8Path::new(config), CONFIG_PLACEHOLDER, &[]);
        }

        // Some output formats (GitHub, SARIF) emit repo-root-relative
        // identifiers, so redact each input's repo-root-relative spellings too.
        for input in &self.inputs {
            redact(&mut raw, input, INPUT_PLACEHOLDER, &[REPO_ROOT.as_path()]);
        }

        // Replace any references to the discovered repository (i.e. Git)
        // root that remain after input redaction.
        //
        // TODO: This currently does the lazy thing and looks for
        // `.git` in each parent. We should probably dedupe this with
        // `InputGroup::discover_root` at some point.
        for input in &self.inputs {
            let mut parent = if input.is_dir() {
                Some(input.as_path())
            } else {
                input.parent()
            };

            while let Some(candidate) = parent {
                if candidate.join(".git").is_dir() {
                    redact(&mut raw, candidate, REPO_ROOT_PLACEHOLDER, &[]);
                }

                parent = candidate.parent();
            }
        }

        redact(
            &mut raw,
            &self.working_dir,
            WORKING_DIR_PLACEHOLDER,
            &[REPO_ROOT.as_path()],
        );

        // Fallback: replace any lingering test prefix paths.
        redact(
            &mut raw,
            &TEST_PREFIX,
            TEST_PREFIX_PLACEHOLDER,
            &[REPO_ROOT.as_path(), ZIZMOR_ROOT.as_path()],
        );

        raw = raw.replace(env!("CARGO_PKG_VERSION"), VERSION_PLACEHOLDER);

        // Apply any configured filters. This happens before separator
        // normalization below so that path suffixes trailing a filter's
        // placeholder (e.g. `@@WORKSPACE_PATH@@\zizmor.yml`) get
        // normalized as well.
        for (needle, replacement) in &self.filters {
            redact(&mut raw, Utf8Path::new(needle), replacement, &[]);
        }

        // On Windows, zizmor emits host-native `\` separators where the Unix
        // snapshots have `/`. Now that every path is redacted to a placeholder,
        // normalize the separators that follow any placeholder — including
        // consecutive ones like `@@WORKING_DIR@@\@@TEST_PREFIX@@\...`, whose `\`
        // came from the joined absolute path rather than from a redacted needle.
        if cfg!(windows) {
            raw = PLACEHOLDER_PATH_REGEX
                .replace_all(&raw, |captures: &Captures| {
                    // Collapse Debug-escaped separators (`\\` meaning one `\`)
                    // first, then any remaining lone separators.
                    captures
                        .get(0)
                        .unwrap()
                        .as_str()
                        .replace(r"\\", "/")
                        .replace('\\', "/")
                })
                .into_owned();
        }

        raw
    }
}

/// Redacts every plausible on-disk spelling of `needle` in `haystack`,
/// replacing each occurrence with `placeholder`.
///
/// Spellings of `needle` relative to each root in `roots` are redacted
/// as well.
fn redact(haystack: &mut String, needle: &Utf8Path, placeholder: &str, roots: &[&Utf8Path]) {
    // `input_under_test` produces an absolute/canonical path, but other
    // needles might not be canonical/absolute. Do that opportunistically.
    // Canonicalization yields a `\\?\` verbatim prefix on Windows; that
    // prefix has already been stripped from the haystack, so strip it here
    // too or this spelling can never match.
    let canonical = needle.canonicalize_utf8().ok().map(|canonical| {
        Utf8PathBuf::from(
            canonical
                .as_str()
                .strip_prefix(r"\\?\")
                .unwrap_or(canonical.as_str()),
        )
    });

    let mut spellings = vec![];
    for base in std::iter::once(needle).chain(canonical.as_deref()) {
        spellings.extend(spellings_of(base));

        for root in roots {
            if let Ok(relative) = base.strip_prefix(root) {
                spellings.extend(spellings_of(relative));
            }
        }
    }

    // Guard against empty spellings (e.g. an empty `needle`, or a `needle`
    // equal to one of `roots`): `str::replace("", ..)` would splice the
    // placeholder in between every character.
    spellings.retain(|spelling| !spelling.is_empty());
    spellings.sort_unstable();
    spellings.dedup();

    for spelling in &spellings {
        *haystack = haystack.replace(spelling.as_str(), placeholder);
        // serde_json and tracing escape '\' as '\\'; redact that spelling too.
        if spelling.contains('\\') {
            let escaped = spelling.replace('\\', r"\\");
            *haystack = haystack.replace(escaped.as_str(), placeholder);
        }
    }
}

/// Returns the plausible spellings of `path` as it might appear in zizmor's
/// output.
///
/// A single logical path can surface under several different spellings,
/// especially on Windows. This attempts to cover all of them: verbatim,
/// host-native separators, and forward-slash separators.
fn spellings_of(path: &Utf8Path) -> Vec<String> {
    let verbatim = path.as_str();

    // The host-native spelling, matching `InputKey::native_path`. `components()`
    // drops a trailing separator, so restore it when `verbatim` had one: an
    // input passed as `foo/bar/` should still consume the separator in
    // `foo/bar/baz.yml` -> `@@INPUT@@baz.yml`, exactly as it does on Unix.
    let mut native = path.components().collect::<Utf8PathBuf>().into_string();
    if verbatim.ends_with(['/', '\\']) && !native.is_empty() {
        native.push(std::path::MAIN_SEPARATOR);
    }

    vec![
        verbatim.to_owned(),
        verbatim.replace('\\', "/"),
        native.replace('\\', "/"),
        native,
    ]
}

pub fn zizmor() -> Zizmor {
    Zizmor::new()
}

/// Represents a runtime-constructured workspace, i.e. a testcase for zizmor.
///
/// Workspaces are built using [`WorkspaceBuilder`] and are used for tests
/// that have nontrivial path/layout conditions, such as needing to imitate
/// Git or other state.
pub struct Workspace {
    path: Utf8PathBuf,
    /// Solely to retain ownership of the tempdir/prevent cleanup until drop.
    #[allow(dead_code)]
    tempdir: TempDir,
}

impl Workspace {
    pub fn path(&self) -> &Utf8Path {
        self.path.as_path()
    }

    /// Add a file named `name` to the workspace with contents `contents`.
    ///
    /// Any intermediate directories in `name` are created if they don't already exist.
    pub fn add_file<'a>(&self, name: impl Into<&'a Utf8Path>, contents: &str) {
        let name = name.into();

        if let Some(parent) = name.parent() {
            fs::create_dir_all(&parent).expect("failed to create parent directories: {parent}");
        }

        let destination = self.path().join(name);
        fs::write(destination, contents).expect("failed to write contents to {destination}");
    }

    /// Copy the contents of `source` into `dest`.
    ///
    /// `source` can be a directory, in which case it's copied recursively.
    ///
    /// `dest` will be joined to the workspace's root.
    pub fn copy<'a>(&self, source: impl Into<&'a Utf8Path>, dest: impl Into<&'a Utf8Path>) {
        let source = source.into();
        let dest = self.path().join(dest.into());

        if source.is_file() {
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent).unwrap();
            }

            fs::copy(source, &dest).unwrap();
        } else {
            for entry in walkdir::WalkDir::new(source) {
                let entry = entry.unwrap();
                let path = Utf8Path::from_path(entry.path()).unwrap();

                // Strip the source prefix to find the relative path inside the tree
                let relative_path = path.strip_prefix(&source).unwrap();
                let dest_path = dest.join(relative_path);

                if entry.file_type().is_dir() {
                    fs::create_dir_all(&dest_path).unwrap();
                } else {
                    fs::copy(path, &dest_path).unwrap();
                }
            }
        }
    }
}

pub struct WorkspaceBuilder {
    root_name: Option<String>,
    git_repo: bool,
}

impl WorkspaceBuilder {
    pub fn new() -> Self {
        Self {
            root_name: None,
            git_repo: false,
        }
    }

    pub fn root_name(mut self, name: impl Into<String>) -> Self {
        self.root_name = Some(name.into());
        self
    }

    pub fn is_git_repo(mut self, is_git_repo: bool) -> Self {
        self.git_repo = is_git_repo;
        self
    }

    pub fn build(self) -> anyhow::Result<Workspace> {
        let tempdir = tempfile::tempdir()?;
        let mut root = tempdir.path().to_path_buf();

        if let Some(root_name) = self.root_name.as_deref() {
            root = root.join(root_name);
            fs::create_dir(&root)?;
        }

        if self.git_repo {
            fs::create_dir(root.join(".git/"))?;
        }

        Ok(Workspace {
            path: Utf8PathBuf::try_from(root)?,
            tempdir,
        })
    }
}
