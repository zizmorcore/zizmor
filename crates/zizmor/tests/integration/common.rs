use anyhow::{Context as _, Result};
use regex::{Captures, Regex};
use std::{env::current_dir, io::ErrorKind};

use assert_cmd::Command;

pub fn input_under_test(name: &str) -> String {
    let current_dir = current_dir().expect("Cannot figure out current directory");

    let file_path = current_dir
        .join("tests")
        .join("integration")
        .join("test-data")
        .join(name);

    if !file_path.exists() {
        panic!("Cannot find input under test: {}", file_path.display());
    }

    file_path
        .to_str()
        .expect("Cannot create string reference for file path")
        .to_string()
}

pub enum OutputMode {
    Stdout,
    #[allow(dead_code, reason = "currently not used by any integration test")]
    Stderr,
    Both,
}

pub struct Zizmor {
    cmd: Command,
    unbuffer: bool,
    offline: bool,
    inputs: Vec<String>,
    config: Option<String>,
    output: OutputMode,
    expects_failure: bool,
}

impl Zizmor {
    /// Create a new zizmor runner.
    pub fn new() -> Self {
        let cmd = Command::cargo_bin("zizmor").unwrap();

        Self {
            cmd,
            unbuffer: false,
            offline: true,
            inputs: vec![],
            config: None,
            output: OutputMode::Stdout,
            expects_failure: false,
        }
    }

    pub fn args<'a>(mut self, args: impl IntoIterator<Item = &'a str>) -> Self {
        self.cmd.args(args);
        self
    }

    pub fn setenv(mut self, key: &str, value: &str) -> Self {
        self.cmd.env(key, value);
        self
    }

    pub fn unsetenv(mut self, key: &str) -> Self {
        self.cmd.env_remove(key);
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

    pub fn unbuffer(mut self, flag: bool) -> Self {
        self.unbuffer = flag;
        self
    }

    pub fn offline(mut self, flag: bool) -> Self {
        self.offline = flag;
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

    pub fn run(mut self) -> Result<String> {
        if self.offline {
            self.cmd.arg("--offline");
        } else {
            // If we're running in online mode, we pre-assert the
            // presence of GH_TOKEN to make configuration failures more obvious.
            std::env::var("GH_TOKEN").context("online tests require GH_TOKEN to be set")?;
        }

        if let Some(config) = self.config {
            self.cmd.arg("--config").arg(config);
        } else {
            self.cmd.arg("--no-config");
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
            // 1 is our only failure code.
            let is_failure = exit_code == 1;
            if is_failure != self.expects_failure {
                anyhow::bail!("zizmor exited with unexpected code {exit_code}");
            }
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

        Ok(raw)
    }
}

pub fn zizmor() -> Zizmor {
    Zizmor::new()
}
