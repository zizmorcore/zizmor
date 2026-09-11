use crate::common::{input_under_test, zizmor};

#[test]
fn secrets_inherit() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("secrets-inherit.yml"))
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:10:11
       |
    10 |     uses: octo-org/example-repo/.github/workflows/called-workflow.yml@main
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:16:11
       |
    16 |     uses: octo-org/example-repo/.github/workflows/called-workflow.yml@main
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:23:11
       |
    23 |     uses: octo-org/example-repo/.github/workflows/called-workflow.yml@main
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:28:11
       |
    28 |     uses: octo-org/example-repo/.github/workflows/called-workflow.yml@main
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    warning[secrets-inherit]: secrets unconditionally inherited by called workflow
      --> @@INPUT@@:10:11
       |
    10 |     uses: octo-org/example-repo/.github/workflows/called-workflow.yml@main
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this reusable workflow
    11 |     # NOT OK: unconditionally inherits
    12 |     secrets: inherit
       |     ---------------- inherits all parent secrets
       |
       = note: audit confidence → High

    5 findings: 0 informational, 0 low, 1 medium, 4 high
    "
    );

    Ok(())
}

#[test]
fn secrets_inherit_callee() -> anyhow::Result<()> {
    // A reusable workflow that declares `on.workflow_call.secrets: inherit`
    // is flagged, since it forces every caller to over-scope.
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("secrets-inherit-callee.yml"))
            .run()?,
        @"
    warning[secrets-inherit]: secrets unconditionally inherited by called workflow
     --> @@INPUT@@:4:5
      |
    4 |     secrets: inherit
      |     ^^^^^^^^^^^^^^^^ this reusable workflow inherits all caller secrets
      |
      = note: audit confidence → High

    1 finding: 0 informational, 0 low, 1 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn secrets_inherit_callee_ok() -> anyhow::Result<()> {
    // A reusable workflow that explicitly declares its secrets is not flagged.
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("secrets-inherit-callee-ok.yml"))
            .run()?,
        @"No findings to report. Good job!"
    );

    Ok(())
}
