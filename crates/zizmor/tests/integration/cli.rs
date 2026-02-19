use crate::common::zizmor;

/// Test that `--gh-token` and `--github-token` conflict with each other.
#[test]
fn test_gh_token_github_token_conflict() -> anyhow::Result<()> {
    // As CLI flags.
    insta::assert_snapshot!(
        zizmor()
            .offline(true)
            .expects_failure(2)
            .args(["--gh-token=x", "--github-token=x"])
            .run()?,
        @r"
    error: the argument '--gh-token <GH_TOKEN>' cannot be used with '--github-token <GITHUB_TOKEN>'

    Usage: zizmor --gh-token <GH_TOKEN> --offline --no-progress --show-audit-urls <SHOW_AUDIT_URLS> <INPUTS>...

    For more information, try '--help'.
    "
    );

    // As environment variables.
    insta::assert_snapshot!(
        zizmor()
            .offline(true)
            .expects_failure(2)
            .setenv("GH_TOKEN", "x")
            .setenv("GITHUB_TOKEN", "x")
            .run()?,
        @r"
    error: the argument '--gh-token <GH_TOKEN>' cannot be used with '--github-token <GITHUB_TOKEN>'

    Usage: zizmor --offline --no-progress --show-audit-urls <SHOW_AUDIT_URLS> --gh-token <GH_TOKEN> <INPUTS>...

    For more information, try '--help'.
    "
    );

    Ok(())
}

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
    insta::assert_snapshot!(
        zizmor().stdin(workflow).no_config(true).args(["-"]).run()?,
        @r"
    warning[artipacked]: credential persistence through GitHub Actions artifacts
     --> <stdin>:6:9
      |
    6 |       - uses: actions/checkout@v3
      |         ^^^^^^^^^^^^^^^^^^^^^^^^^ does not set persist-credentials: false
      |
      = note: audit confidence → Low
      = note: this finding has an auto-fix

    warning[excessive-permissions]: overly broad permissions
     --> <stdin>:3:3
      |
    3 | /   test:
    4 | |     runs-on: ubuntu-latest
    5 | |     steps:
    6 | |       - uses: actions/checkout@v3
      | |                                  ^
      | |                                  |
      | |__________________________________this job
      |                                    default permissions used due to no permissions: block
      |
      = note: audit confidence → Medium

    error[unpinned-uses]: unpinned action reference
     --> <stdin>:6:15
      |
    6 |       - uses: actions/checkout@v3
      |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
      |
      = note: audit confidence → High

    7 findings (4 suppressed): 0 informational, 0 low, 2 medium, 1 high
    "
    );

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
    insta::assert_snapshot!(
        zizmor().stdin(action).no_config(true).args(["-"]).run()?,
        @r"
    warning[artipacked]: credential persistence through GitHub Actions artifacts
     --> <stdin>:6:7
      |
    6 |     - uses: actions/checkout@v3
      |       ^^^^^^^^^^^^^^^^^^^^^^^^^ does not set persist-credentials: false
      |
      = note: audit confidence → Low
      = note: this finding has an auto-fix

    error[unpinned-uses]: unpinned action reference
     --> <stdin>:6:13
      |
    6 |     - uses: actions/checkout@v3
      |             ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
      |
      = note: audit confidence → High

    2 findings: 0 informational, 0 low, 1 medium, 1 high
    "
    );

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
            .run()?,
        @r"
    warning[dependabot-cooldown]: insufficient cooldown in Dependabot updates
     --> <stdin>:3:5
      |
    3 |   - package-ecosystem: github-actions
      |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ missing cooldown configuration
      |
      = note: audit confidence → High
      = note: this finding has an auto-fix

    1 finding: 0 informational, 0 low, 1 medium, 0 high
    "
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
        @r"
    🌈 zizmor v@@VERSION@@
     WARN collect_inputs: zizmor::registry::input: stdin: failed to load <stdin> as workflow
    fatal: no audit was performed
    error: no inputs collected
      |
      = help: collection yielded no auditable inputs
      = help: inputs must contain at least one valid workflow, action, or Dependabot config

    Caused by:
        no inputs collected
    "
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
        @r###"
    🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    failed to load <stdin> as workflow

    Caused by:
        0: invalid YAML syntax: did not find expected ',' or ']' at line 2 column 1, while parsing a flow sequence at line 1 column 2
        1: did not find expected ',' or ']' at line 2 column 1, while parsing a flow sequence at line 1 column 2
    "###
    );

    Ok(())
}

/// Test that empty stdin produces a collection error.
#[test]
fn test_stdin_empty() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .stdin("")
            .no_config(true)
            .expects_failure(3)
            .args(["-"])
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
     WARN collect_inputs: zizmor::registry::input: stdin: could not parse as any known input type: failed to load <stdin> as workflow
    fatal: no audit was performed
    error: no inputs collected
      |
      = help: collection yielded no auditable inputs
      = help: inputs must contain at least one valid workflow, action, or Dependabot config

    Caused by:
        no inputs collected
    "
    );

    Ok(())
}

/// Test that SARIF output works with stdin input.
#[test]
fn test_stdin_sarif_output() -> anyhow::Result<()> {
    let workflow = "\
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
";
    let output = zizmor()
        .stdin(workflow)
        .no_config(true)
        .args(["--format=sarif", "-"])
        .run()?;

    // Verify the output is valid JSON and contains <stdin> as the artifact.
    assert!(output.contains("\"artifactLocation\""));
    assert!(output.contains("<stdin>"));

    Ok(())
}

/// Test that valid YAML matching no known schema produces a collection error.
#[test]
fn test_stdin_valid_yaml_unknown_schema() -> anyhow::Result<()> {
    let unknown = "foo: bar\nbaz: 42\n";
    insta::assert_snapshot!(
        zizmor()
            .stdin(unknown)
            .no_config(true)
            .expects_failure(3)
            .args(["-"])
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
     WARN collect_inputs: zizmor::registry::input: stdin: could not parse as any known input type: failed to load <stdin> as workflow
    fatal: no audit was performed
    error: no inputs collected
      |
      = help: collection yielded no auditable inputs
      = help: inputs must contain at least one valid workflow, action, or Dependabot config

    Caused by:
        no inputs collected
    "
    );

    Ok(())
}

/// Test that valid YAML matching no known schema fails in strict mode.
#[test]
fn test_stdin_valid_yaml_unknown_schema_strict() -> anyhow::Result<()> {
    let unknown = "foo: bar\nbaz: 42\n";
    insta::assert_snapshot!(
        zizmor()
            .stdin(unknown)
            .no_config(true)
            .expects_failure(1)
            .args(["--strict-collection", "-"])
            .run()?,
        @r###"
    🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    failed to load <stdin> as workflow

    Caused by:
        0: input does not match expected validation schema
        1: "on" is a required property
           "jobs" is a required property
           Additional properties are not allowed ('baz', 'foo' were unexpected)
    "###
    );

    Ok(())
}
