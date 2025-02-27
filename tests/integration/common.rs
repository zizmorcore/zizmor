use anyhow::{Context as _, Result};
use std::env::current_dir;

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
    Stderr,
    Both,
}

pub struct Zizmor {
    cmd: Command,
    offline: bool,
    inputs: Vec<String>,
    output: OutputMode,
}

impl Zizmor {
    /// Create a new zizmor runner.
    pub fn new() -> Self {
        let cmd = Command::cargo_bin("zizmor").unwrap();

        Self {
            cmd,
            offline: true,
            inputs: vec![],
            output: OutputMode::Stdout,
        }
    }

    pub fn args<'a>(mut self, args: impl IntoIterator<Item = &'a str>) -> Self {
        self.cmd.args(args);
        self
    }

    // pub fn setenv(mut self, key: &str, value: &str) -> Self {
    //     self.cmd.env(key, value);
    //     self
    // }

    pub fn unsetenv(mut self, key: &str) -> Self {
        self.cmd.env_remove(key);
        self
    }

    pub fn input(mut self, input: impl Into<String>) -> Self {
        self.inputs.push(input.into());
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

    pub fn run(mut self) -> Result<String> {
        if self.offline {
            self.cmd.arg("--offline");
        } else {
            // If we're running in online mode, we pre-assert the
            // presence of GH_TOKEN to make configuration failures more obvious.
            std::env::var("GH_TOKEN").context("online tests require GH_TOKEN to be set")?;
        }

        for input in &self.inputs {
            self.cmd.arg(input);
        }

        let output = self.cmd.output()?;

        let mut raw = String::from_utf8(match self.output {
            OutputMode::Stdout => output.stdout,
            OutputMode::Stderr => output.stderr,
            OutputMode::Both => [output.stderr, output.stdout].concat(),
        })?;

        for input in &self.inputs {
            raw = raw.replace(input, "@@INPUT@@");
        }

        Ok(raw)
    }
}

pub fn zizmor() -> Zizmor {
    Zizmor::new()
}
