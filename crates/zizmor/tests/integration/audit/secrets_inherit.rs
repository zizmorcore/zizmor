use crate::common::{input_under_test, zizmor};

#[test]
fn secrets_inherit() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("secrets-inherit.yml"))
            .run()?,
        @r"
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
