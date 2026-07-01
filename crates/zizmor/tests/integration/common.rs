use anyhow::{Context as _, Result};
use camino::{Utf8Path, Utf8PathBuf};
use regex::{Captures, Regex};
use std::{env::current_dir, io::ErrorKind, sync::LazyLock};

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

pub struct Zizmor {
    cmd: Command,
    stdin: Option<String>,
    unbuffer: bool,
    offline: bool,
    gh_token: bool,
    inputs: Vec<Utf8PathBuf>,
    working_dir: Utf8PathBuf,
    config: Option<String>,
    no_config: bool,
    output: OutputMode,
    expects_failure: Option<i32>,
    show_audit_urls: bool,
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
            offline: true,
            gh_token: true,
            inputs: vec![],
            working_dir: CURRENT_DIR.clone(),
            config: None,
            no_config: false,
            output: OutputMode::Stdout,
            expects_failure: None,
            show_audit_urls: false,
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

    pub fn offline(mut self, flag: bool) -> Self {
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

    pub fn working_dir(mut self, dir: impl Into<String>) -> Self {
        self.cmd.current_dir(dir.into());
        self
    }

    pub fn run(mut self) -> Result<String> {
        if let Some(stdin) = &self.stdin {
            self.cmd.write_stdin(stdin.as_bytes());
        }

        if self.offline {
            self.cmd.arg("--offline");
        } else {
            // If we're running in online mode, we pre-assert the
            // presence of GH_TOKEN to make configuration failures more obvious.
            let token =
                std::env::var("GH_TOKEN").context("online tests require GH_TOKEN to be set")?;

            if self.gh_token {
                self.cmd.env("GH_TOKEN", token);
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

        let mut raw = String::from_utf8(match self.output {
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

            // if is_failure != self.expects_failure {
            //     anyhow::bail!("zizmor exited with unexpected code {exit_code}: {raw}");
            // }
        }

        // On Windows, canonicalized paths surface with a `\\?\` verbatim prefix
        // that has no cross-platform analogue (e.g. zizmor logs canonicalized
        // config-discovery candidates). Strip it up front so the paths below
        // redact cleanly and match the Unix snapshots.
        if cfg!(windows) {
            raw = raw.replace(r"\\?\", "");
        }

        if let Some(config) = &self.config {
            // The config is often an `input_under_test(..)` path, so it needs
            // the same multi-spelling treatment as the inputs below.
            redact(&mut raw, Utf8Path::new(config), "@@CONFIG@@");
        }

        let input_placeholder = "@@INPUT@@";
        for input in &self.inputs {
            redact(&mut raw, input, input_placeholder);

            // Some output formats (GitHub, SARIF) emit repo-root-relative
            // identifiers; redact those too. Canonicalization yields a `\\?\`
            // prefix on Windows, so strip it before comparing against the
            // (non-verbatim) repo root.
            if let Ok(abs) = input.canonicalize_utf8() {
                let abs = abs.as_str().strip_prefix(r"\\?\").unwrap_or(abs.as_str());
                if let Ok(relative) = Utf8Path::new(abs).strip_prefix(&*REPO_ROOT) {
                    redact(&mut raw, relative, input_placeholder);
                }
            }
        }

        let working_dir_placeholder = "@@WORKING_DIR@@";
        // Replace any absolute references to the working directory.
        redact(&mut raw, &self.working_dir, working_dir_placeholder);

        // Replace any relative references to the working directory.
        if let Ok(relative) = self.working_dir.strip_prefix(&*REPO_ROOT) {
            redact(&mut raw, relative, working_dir_placeholder);
        }

        // Fallback: replace any lingering test prefix paths.
        // TODO: Maybe just use this everywhere instead of the special
        // replacements above?
        let test_prefix_placeholder = "@@TEST_PREFIX@@";
        redact(&mut raw, &*TEST_PREFIX, test_prefix_placeholder);

        if let Ok(relative) = TEST_PREFIX.strip_prefix(&*REPO_ROOT) {
            redact(&mut raw, relative, test_prefix_placeholder);
        }

        if let Ok(relative) = TEST_PREFIX.strip_prefix(&*ZIZMOR_ROOT) {
            redact(&mut raw, relative, test_prefix_placeholder);
        }

        let version_placeholder = "@@VERSION@@";
        raw = raw.replace(env!("CARGO_PKG_VERSION"), version_placeholder);

        // On Windows, zizmor emits host-native `\` separators where the Unix
        // snapshots have `/`. Now that every path is redacted to a placeholder,
        // normalize the separators that follow any path placeholder — including
        // consecutive ones like `@@WORKING_DIR@@\@@TEST_PREFIX@@\...`, whose `\`
        // came from the joined absolute path rather than from a redacted needle.
        if cfg!(windows) {
            let placeholder_path_regex =
                Regex::new(r"(@@INPUT@@|@@WORKING_DIR@@|@@TEST_PREFIX@@|@@CONFIG@@)[\\/\w.-]*")?;
            raw = placeholder_path_regex
                .replace_all(&raw, |captures: &Captures| {
                    captures.get(0).unwrap().as_str().replace('\\', "/")
                })
                .into_owned();
        }

        Ok(raw)
    }
}

/// Redacts every on-disk spelling of `needle` in `haystack`, replacing each
/// occurrence with `placeholder`.
///
/// A single logical path can surface in zizmor's output under several different
/// spellings, especially on Windows. This attempts to handle all of them.
fn redact(haystack: &mut String, needle: &Utf8Path, placeholder: &str) {
    let verbatim = needle.as_str();
    if verbatim.is_empty() {
        // Guard against `str::replace("", ..)`, which would splice the
        // placeholder in between every character.
        return;
    }

    // The host-native spelling, matching `InputKey::native_path`. `components()`
    // drops a trailing separator, so restore it when `verbatim` had one: an
    // input passed as `foo/bar/` should still consume the separator in
    // `foo/bar/baz.yml` -> `@@INPUT@@baz.yml`, exactly as it does on Unix.
    let mut native = needle.components().collect::<Utf8PathBuf>().into_string();
    if verbatim.ends_with(['/', '\\']) && !native.is_empty() {
        native.push(std::path::MAIN_SEPARATOR);
    }

    let mut forms = vec![
        verbatim.to_owned(),
        native.clone(),
        verbatim.replace('\\', "/"),
        native.replace('\\', "/"),
    ];
    forms.sort_unstable();
    forms.dedup();

    for form in &forms {
        *haystack = haystack.replace(form.as_str(), placeholder);
        // serde_json escapes '\' as '\\'; redact that spelling too.
        if form.contains('\\') {
            let escaped = form.replace('\\', r"\\");
            *haystack = haystack.replace(escaped.as_str(), placeholder);
        }
    }
}

pub fn zizmor() -> Zizmor {
    Zizmor::new()
}
