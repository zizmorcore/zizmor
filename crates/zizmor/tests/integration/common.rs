use anyhow::{Context as _, Result};
use camino::Utf8PathBuf;
use regex::{Captures, Regex};
use std::{env::current_dir, io::ErrorKind, sync::LazyLock};

use assert_cmd::{Command, cargo};

static TEST_PREFIX: LazyLock<Utf8PathBuf> = LazyLock::new(|| {
    let current_dir = current_dir().expect("Cannot figure out current directory");

    let file_path = current_dir
        .join("tests")
        .join("integration")
        .join("test-data");

    if !file_path.exists() {
        panic!("Cannot find test data directory: {}", file_path.display());
    }

    Utf8PathBuf::try_from(file_path).expect("Cannot create UTF-8 path from test data directory")
});

pub fn input_under_test(name: &str) -> String {
    let file_path = TEST_PREFIX.join(name);

    if !file_path.exists() {
        panic!("Cannot find input under test: {file_path}");
    }

    file_path.to_string()
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
    inputs: Vec<String>,
    config: Option<String>,
    no_config: bool,
    output: OutputMode,
    expects_failure: bool,
    show_audit_urls: bool,
}

impl Zizmor {
    /// Create a new zizmor runner.
    pub fn new() -> Self {
        let mut cmd = Command::new(cargo::cargo_bin!());

        // Our child `zizmor` process starts with a clean environment, to
        // ensure we explicitly test interactions with things like `CI`
        // and `GH_TOKEN`.
        cmd.env_clear();

        Self {
            cmd,
            stdin: None,
            unbuffer: false,
            offline: true,
            gh_token: true,
            inputs: vec![],
            config: None,
            no_config: false,
            output: OutputMode::Stdout,
            expects_failure: false,
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

    pub fn input(mut self, input: impl Into<String>) -> Self {
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

    pub fn expects_failure(mut self, flag: bool) -> Self {
        if flag {
            self = self.output(OutputMode::Both);
        }
        self.expects_failure = flag;
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
            // these do. 1/2 are general errors, 101 is Rust's panic exit code.
            let is_failure = matches!(exit_code, 1 | 2 | 101);
            if is_failure != self.expects_failure {
                anyhow::bail!("zizmor exited with unexpected code {exit_code}: {raw}");
            }
        }

        let config_placeholder = "@@CONFIG@@";
        if let Some(config) = &self.config {
            raw = raw.replace(config, config_placeholder);
        }

        let input_placeholder = "@@INPUT@@";
        for input in &self.inputs {
            raw = raw.replace(input, input_placeholder);
        }

        // Normalize Windows '\' file paths to using '/', to get consistent snapshot test outputs
        if cfg!(windows) {
            let input_path_regex = Regex::new(&format!(r"{input_placeholder}[\\/\w.-]+"))?;
            raw = input_path_regex
                .replace_all(&raw, |captures: &Captures| {
                    captures.get(0).unwrap().as_str().replace("\\", "/")
                })
                .into_owned();
        }

        // Fallback: replace any lingering absolute paths.
        // TODO: Maybe just use this everywhere instead of the special
        // replacements above?
        let test_prefix_placeholder = "@@TEST_PREFIX@@";
        raw = raw.replace(TEST_PREFIX.as_str(), test_prefix_placeholder);

        let version_placeholder = "@@VERSION@@";
        raw = raw.replace(env!("CARGO_PKG_VERSION"), version_placeholder);

        Ok(raw)
    }
}

pub fn zizmor() -> Zizmor {
    Zizmor::new()
}
