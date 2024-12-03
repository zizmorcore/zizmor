use anyhow::Result;
use assert_cmd::Command;
use common::workflow_under_test;

mod common;

#[allow(dead_code)]
pub(crate) enum OutputMode {
    Stdout,
    Stderr,
    Both,
}

pub(crate) struct Zizmor {
    workflow: Option<String>,
    args: Vec<String>,
    output: OutputMode,
}

impl Zizmor {
    fn new() -> Self {
        Self {
            workflow: None,
            args: vec!["--offline".into()],
            output: OutputMode::Stdout,
        }
    }

    fn args<'a>(mut self, args: impl IntoIterator<Item = &'a str>) -> Self {
        self.args.extend(args.into_iter().map(Into::into));

        self
    }

    fn workflow(mut self, workflow: impl Into<String>) -> Self {
        let workflow = workflow.into();
        self.args.push(workflow.clone());
        self.workflow = Some(workflow);

        self
    }

    #[allow(dead_code)]
    fn output(mut self, output: OutputMode) -> Self {
        self.output = output;
        self
    }

    fn run(self) -> Result<String> {
        let mut cmd = Command::cargo_bin("zizmor")?;
        cmd.args(self.args);

        let output = cmd.output()?;

        let mut raw = String::from_utf8(match self.output {
            OutputMode::Stdout => output.stdout,
            OutputMode::Stderr => output.stderr,
            OutputMode::Both => [output.stdout, output.stderr].concat(),
        })?;

        if let Some(workflow) = self.workflow {
            raw = raw.replace(&workflow, "@@INPUT@@");
        }

        Ok(raw)
    }
}

pub(crate) fn zizmor() -> Zizmor {
    Zizmor::new()
}

#[test]
fn artipacked() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("artipacked.yml"))
        .args(["--persona=pedantic"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("artipacked.yml"))
        .run()?);

    Ok(())
}

#[test]
fn self_hosted() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("self-hosted.yml"))
        .args(["--persona=auditor"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("self-hosted.yml"))
        .run()?);

    Ok(())
}

#[test]
fn unpinned_uses() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("unpinned-uses.yml"))
        .args(["--pedantic"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("unpinned-uses.yml"))
        .run()?);

    Ok(())
}
