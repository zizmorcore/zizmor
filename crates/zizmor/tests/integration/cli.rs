use crate::common::zizmor;

/// Test that `-` reads a workflow from stdin.
#[test]
fn test_stdin_workflow() -> anyhow::Result<()> {
    let workflow = "\
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
";
    // NOTE: We use .args(["-"]) instead of .input("-") because the
    // test harness replaces all occurrences of the input string in the
    // output, and `-` would corrupt arrows, flags, etc.
    insta::assert_snapshot!(zizmor().stdin(workflow).no_config(true).args(["-"]).run()?);

    Ok(())
}

/// Test that `-` reads an action definition from stdin.
#[test]
fn test_stdin_action() -> anyhow::Result<()> {
    let action = "\
name: My Action
description: Test action
runs:
  using: composite
  steps:
    - uses: actions/checkout@v3
";
    insta::assert_snapshot!(zizmor().stdin(action).no_config(true).args(["-"]).run()?);

    Ok(())
}

/// Test that `-` reads a Dependabot config from stdin.
#[test]
fn test_stdin_dependabot() -> anyhow::Result<()> {
    let dependabot = "\
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
";
    insta::assert_snapshot!(
        zizmor()
            .stdin(dependabot)
            .no_config(true)
            .args(["-"])
            .run()?
    );

    Ok(())
}

/// Test that `-` cannot be combined with other inputs.
#[test]
fn test_stdin_with_other_inputs() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .stdin("on: push")
            .no_config(true)
            .expects_failure(2)
            .args(["-", "some-dir/"])
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    error: `-` (stdin) cannot be combined with other inputs

    Usage: zizmor [OPTIONS] <INPUTS>...

    For more information, try '--help'.
    "
    );

    Ok(())
}

/// Test that `--fix` cannot be used with `-`.
#[test]
fn test_stdin_with_fix() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .stdin("on: push")
            .no_config(true)
            .expects_failure(2)
            .args(["--fix", "-"])
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    error: `--fix` cannot be used with `-` (stdin)

    Usage: zizmor [OPTIONS] <INPUTS>...

    For more information, try '--help'.
    "
    );

    Ok(())
}

/// Test that invalid YAML on stdin produces a helpful error.
#[test]
fn test_stdin_invalid_yaml() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .stdin("{[invalid")
            .no_config(true)
            .expects_failure(3)
            .args(["-"])
            .run()?,
    );

    Ok(())
}

/// Test that invalid YAML on stdin with `--strict-collection` fails.
#[test]
fn test_stdin_invalid_yaml_strict() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .stdin("{[invalid")
            .no_config(true)
            .expects_failure(1)
            .args(["--strict-collection", "-"])
            .run()?,
    );

    Ok(())
}
