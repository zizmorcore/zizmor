use crate::common::{WorkspaceBuilder, input_under_test, zizmor};

#[test]
fn test_basic() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("self-repository.yml"))
            .run()?,
        @"
    help[self-repository]: use GitHub's dedicated self-repository syntax
      --> @@INPUT@@:18:15
       |
    17 |       - name: uses-local-composite-action
       |         --------------------------------- this step
    18 |         uses: ./some-action
       |               ^^^^^^^^^^^^^ use '$/...' instead of './...'
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[self-repository]: use GitHub's dedicated self-repository syntax
      --> @@INPUT@@:23:11
       |
    22 |     name: uses-reusable-workflow
       |     ---------------------------- this job
    23 |     uses: ./.github/workflows/reuse.yml
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ use '$/...' instead of './...'
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    2 findings (2 safe fixes): 0 informational, 2 low, 0 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_fix() -> anyhow::Result<()> {
    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.copy(
        &*input_under_test("self-repository.yml"),
        ".github/workflows/self-repository.yml",
    );

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/self-repository.yml", |workspace| {
            zizmor()
                .args(["--fix=safe"])
                .input(workspace.path())
                .run()
        })?,
        @"
    -        uses: ./some-action
    +        uses: $/some-action
    -    uses: ./.github/workflows/reuse.yml
    +    uses: $/.github/workflows/reuse.yml
    "
    );

    Ok(())
}
