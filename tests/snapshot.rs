use anyhow::Result;
use assert_cmd::Command;
use common::workflow_under_test;

mod common;

fn zizmor(workflow: Option<&str>, args: &[&str], stderr: bool) -> Result<String> {
    let mut cmd = Command::cargo_bin("zizmor")?;
    // All tests are currently offline.
    cmd.args(["--offline"]);
    cmd.args(args);

    if let Some(workflow) = workflow {
        cmd.arg(workflow);
    }

    let output = cmd.output()?;
    let mut raw = if stderr {
        String::from_utf8(output.stderr)?
    } else {
        String::from_utf8(output.stdout)?
    };

    // Normalize/replace any workflow paths to make them
    // reproducible across different machines.
    if let Some(workflow) = workflow {
        raw = raw.replace(workflow, "@@INPUT@@");
    }

    Ok(raw)
}

#[test]
fn self_hosted() -> Result<()> {
    insta::assert_snapshot!(zizmor(
        Some(&workflow_under_test("self-hosted.yml")),
        &["--pedantic"],
        false
    )?);

    Ok(insta::assert_snapshot!(zizmor(
        Some(&workflow_under_test("self-hosted.yml")),
        &[],
        false
    )?))
}
