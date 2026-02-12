use crate::common::{input_under_test, zizmor};

#[test]
fn test_missing() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("missing-timeout/missing.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @r#"
    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:10:3
       |
    10 | /   build:
    11 | |     name: build
    12 | |     runs-on: ubuntu-latest
    13 | |     steps:
    14 | |       - run: echo "hello"
       | |__________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    1 finding: 0 informational, 1 low, 0 medium, 0 high
    "#
    );

    Ok(())
}

#[test]
fn test_has_timeout() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("missing-timeout/has-timeout.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @"No findings to report. Good job!"
    );

    Ok(())
}

#[test]
fn test_expr_timeout() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("missing-timeout/expr-timeout.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @"No findings to report. Good job!"
    );

    Ok(())
}

#[test]
fn test_reusable() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("missing-timeout/reusable.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
     --> @@INPUT@@:7:11
      |
    7 |     uses: org/repo/.github/workflows/reusable.yml@main
      |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
      |
      = note: audit confidence → High

    1 finding: 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

#[test]
fn test_mixed() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("missing-timeout/mixed.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @r#"
    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:17:3
       |
    17 | /   without-timeout:
    18 | |     name: no-timeout
    19 | |     runs-on: ubuntu-latest
    20 | |     steps:
    21 | |       - run: echo "missing"
       | |____________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    1 finding: 0 informational, 1 low, 0 medium, 0 high
    "#
    );

    Ok(())
}
