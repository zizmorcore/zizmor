use crate::common::{input_under_test, zizmor};
use anyhow::Result;

#[test]
fn test_self_hosted_auditor() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("self-hosted.yml"))
            .args(["--persona=auditor"])
            .run()?,
        @r#"
    warning[self-hosted-runner]: runs on a self-hosted runner
      --> @@INPUT@@:17:5
       |
    17 |     runs-on: [self-hosted, my-ubuntu-box]
       |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ self-hosted runner used here
       |
       = note: audit confidence → High

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:15:3
       |
    15 | /   whops:
    16 | |     name: whops
    17 | |     runs-on: [self-hosted, my-ubuntu-box]
    ...  |
    20 | |       - run: echo "hello from a self-hosted runner"
       | |____________________________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    2 findings: 0 informational, 1 low, 1 medium, 0 high
    "#
    );

    Ok(())
}

#[test]
fn test_self_hosted_default() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("self-hosted.yml"))
            .run()?,
        @"No findings to report. Good job! (2 suppressed)"
    );

    Ok(())
}

#[test]
fn test_self_hosted_runner_label() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("self-hosted/self-hosted-runner-label.yml"))
            .args(["--persona=auditor"])
            .run()?,
        @r#"
    warning[self-hosted-runner]: runs on a self-hosted runner
      --> @@INPUT@@:15:5
       |
    15 |     runs-on: [self-hosted, linux, arm64]
       |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ self-hosted runner used here
       |
       = note: audit confidence → High

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:13:3
       |
    13 | /   whops:
    14 | |     name: whops
    15 | |     runs-on: [self-hosted, linux, arm64]
    ...  |
    18 | |       - run: echo \"hello from a self-hosted runner\"
       | |______________________________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    2 findings: 0 informational, 1 low, 1 medium, 0 high
    "#
    );

    Ok(())
}

#[test]
fn test_self_hosted_runner_group() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("self-hosted/self-hosted-runner-group.yml"))
            .args(["--persona=auditor"])
            .run()?,
        @r#"
    warning[self-hosted-runner]: runs on a self-hosted runner
      --> @@INPUT@@:15:5
       |
    15 | /     runs-on:
    16 | |       group: ubuntu-runners
       | |___________________________^ runner group implies self-hosted runner
       |
       = note: audit confidence → Low

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:13:3
       |
    13 | /   whops:
    14 | |     name: whops
    15 | |     runs-on:
    16 | |       group: ubuntu-runners
    17 | |
    18 | |     steps:
    19 | |       - run: echo \"hello from a self-hosted runner\"
       | |______________________________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    2 findings: 0 informational, 1 low, 1 medium, 0 high
    "#
    );

    Ok(())
}

#[test]
fn test_self_hosted_matrix_dimension() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "self-hosted/self-hosted-matrix-dimension.yml"
            ))
            .args(["--persona=auditor"])
            .run()?,
        @r#"
    warning[self-hosted-runner]: runs on a self-hosted runner
      --> @@INPUT@@:15:5
       |
    15 |       runs-on: ${{ matrix.os }}
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^ expression may expand into a self-hosted runner
    16 |
    17 | /     strategy:
    18 | |       matrix:
    19 | |         os: [self-hosted, ubuntu-latest]
       | |________________________________________- matrix declares self-hosted runner
       |
       = note: audit confidence → High

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:13:3
       |
    13 | /   whops:
    14 | |     name: whops
    15 | |     runs-on: ${{ matrix.os }}
    ...  |
    20 | |     steps:
    21 | |       - run: echo \"hello from a self-hosted runner\"
       | |______________________________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    2 findings: 0 informational, 1 low, 1 medium, 0 high
    "#
    );

    Ok(())
}

#[test]
fn test_self_hosted_matrix_inclusion() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "self-hosted/self-hosted-matrix-inclusion.yml"
            ))
            .args(["--persona=auditor"])
            .run()?,
        @r#"
    warning[self-hosted-runner]: runs on a self-hosted runner
      --> @@INPUT@@:15:5
       |
    15 |       runs-on: ${{ matrix.os }}
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^ expression may expand into a self-hosted runner
    16 |
    17 | /     strategy:
    18 | |       matrix:
    19 | |         os: [macOS-latest, ubuntu-latest]
    20 | |         include:
    21 | |           - os: self-hosted
       | |___________________________- matrix declares self-hosted runner
       |
       = note: audit confidence → High

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:13:3
       |
    13 | /   whops:
    14 | |     name: whops
    15 | |     runs-on: ${{ matrix.os }}
    ...  |
    22 | |     steps:
    23 | |       - run: echo \"hello from a self-hosted runner\"
       | |______________________________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    2 findings: 0 informational, 1 low, 1 medium, 0 high
    "#
    );

    Ok(())
}

#[test]
fn test_self_hosted_matrix_exclusion() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "self-hosted/self-hosted-matrix-exclusion.yml"
            ))
            .args(["--persona=auditor"])
            .run()?,
        @r#"
    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:15:3
       |
    15 | /   ok:
    16 | |     name: ok
    17 | |     runs-on: ${{ matrix.os }}
    ...  |
    24 | |     steps:
    25 | |       - run: echo \"hello from a Github runner\"
       | |_________________________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    1 finding: 0 informational, 1 low, 0 medium, 0 high
    "#
    );

    Ok(())
}

/// Fixed regressions
#[test]
fn test_issue_283_repro() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("self-hosted/issue-283-repro.yml"))
            .args(["--persona=auditor"])
            .run()?,
        @r#"
    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:16:3
       |
    16 | /   deploy:
    17 | |     name: deploy
    18 | |     runs-on: ${{inputs.os}}
    19 | |     steps:
    20 | |       - run: echo "Hello world"
       | |________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    1 finding: 0 informational, 1 low, 0 medium, 0 high
    "#
    );

    Ok(())
}
