use crate::common::{input_under_test, zizmor};

#[test]
fn test_regular_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor().input(input_under_test("artipacked.yml")).run()?,
        @"
    warning[artipacked]: credential persistence through GitHub Actions artifacts
      --> @@INPUT@@:22:9
       |
    22 |       - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # tag=v4.2.2
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ does not set persist-credentials: false
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    4 findings (3 suppressed, 1 fixable): 0 informational, 0 low, 1 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_pedantic_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("artipacked.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @"
    warning[artipacked]: credential persistence through GitHub Actions artifacts
      --> @@INPUT@@:22:9
       |
    22 |       - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # tag=v4.2.2
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ does not set persist-credentials: false
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:18:3
       |
    18 | /   artipacked:
    19 | |     name: artipacked
    20 | |     runs-on: ubuntu-latest
    21 | |     steps:
    22 | |       - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # tag=v4.2.2
       | |____________________________________________________________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:24:3
       |
    24 | /   pedantic:
    25 | |     name: pedantic
    26 | |     runs-on: ubuntu-latest
    27 | |     steps:
    28 | |       - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # tag=v4.2.2
    29 | |         with:
    30 | |           persist-credentials: true
       | |____________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    4 findings (1 suppressed, 1 fixable): 0 informational, 2 low, 1 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_auditor_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("artipacked.yml"))
            .args(["--persona=auditor"])
            .run()?,
        @"
    warning[artipacked]: credential persistence through GitHub Actions artifacts
      --> @@INPUT@@:22:9
       |
    22 |       - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # tag=v4.2.2
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ does not set persist-credentials: false
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    warning[artipacked]: credential persistence through GitHub Actions artifacts
      --> @@INPUT@@:28:9
       |
    28 |         - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # tag=v4.2.2
       |  _________^
    29 | |         with:
    30 | |           persist-credentials: true
       | |____________________________________^ does not set persist-credentials: false
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:18:3
       |
    18 | /   artipacked:
    19 | |     name: artipacked
    20 | |     runs-on: ubuntu-latest
    21 | |     steps:
    22 | |       - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # tag=v4.2.2
       | |____________________________________________________________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:24:3
       |
    24 | /   pedantic:
    25 | |     name: pedantic
    26 | |     runs-on: ubuntu-latest
    27 | |     steps:
    28 | |       - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # tag=v4.2.2
    29 | |         with:
    30 | |           persist-credentials: true
       | |____________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    4 findings (2 fixable): 0 informational, 2 low, 2 medium, 0 high
    "
    );

    Ok(())
}

/// Bug #447: Ensure "true" and "false" (strings) are handled correctly
/// as boolean values in YAML inputs.
///
/// See: <https://github.com/zizmorcore/zizmor/issues/447>
#[test]
fn test_issue_447() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("artipacked/issue-447-repro.yml"))
            .args(["--persona=auditor"])
            .run()?,
        @r#"
    warning[artipacked]: credential persistence through GitHub Actions artifacts
      --> @@INPUT@@:24:9
       |
    24 |         - name: true-positive
       |  _________^
    25 | |         uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
    26 | |         with:
    27 | |           # finding in auditor mode only
    28 | |           persist-credentials: "true"
       | |______________________________________^ does not set persist-credentials: false
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:13:3
       |
    13 | /   issue-447-repro:
    14 | |     name: issue-447-repro
    15 | |     runs-on: ubuntu-latest
    ...  |
    27 | |           # finding in auditor mode only
    28 | |           persist-credentials: "true"
       | |______________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    2 findings (1 fixable): 0 informational, 1 low, 1 medium, 0 high
    "#
    );

    Ok(())
}

/// Ensures that the artipacked audit works correctly on composite actions.
#[test]
fn test_composite_action() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("artipacked/demo-action/action.yml"))
            .args(["--persona=auditor"])
            .run()?,
        @r"
    warning[artipacked]: credential persistence through GitHub Actions artifacts
      --> @@INPUT@@:9:7
       |
     9 |       - name: true-positive-1
       |  _______^
    10 | |       uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # tag=v4.2.2
       | |__________________________________________________________________________________^ does not set persist-credentials: false
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    warning[artipacked]: credential persistence through GitHub Actions artifacts
      --> @@INPUT@@:12:7
       |
    12 |       - name: true-positive-2-pedantic
       |  _______^
    13 | |       uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # tag=v4.2.2
    14 | |       with:
    15 | |         persist-credentials: true
       | |__________________________________^ does not set persist-credentials: false
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    2 findings (2 fixable): 0 informational, 0 low, 2 medium, 0 high
    "
    );

    Ok(())
}
