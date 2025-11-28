use crate::common::{input_under_test, zizmor};

#[test]
fn test_regular_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor().input(input_under_test("artipacked.yml")).run()?,
        @r"
    warning[artipacked]: credential persistence through GitHub Actions artifacts
      --> @@INPUT@@:22:9
       |
    22 |       - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # tag=v4.2.2
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ does not set persist-credentials: false
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    2 findings (1 suppressed, 1 fixable): 0 informational, 0 low, 1 medium, 0 high
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
        @r"
    warning[artipacked]: credential persistence through GitHub Actions artifacts
      --> @@INPUT@@:22:9
       |
    22 |       - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # tag=v4.2.2
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ does not set persist-credentials: false
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    2 findings (1 suppressed, 1 fixable): 0 informational, 0 low, 1 medium, 0 high
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
        @r"
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

    2 findings (2 fixable): 0 informational, 0 low, 2 medium, 0 high
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

    1 findings (1 fixable): 0 informational, 0 low, 1 medium, 0 high
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
