use crate::common::{input_under_test, zizmor};

#[test]
fn test_issue_746_repro() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unsound-ternary/issue-746-repro.yml"))
            .run()?,
        @r"
    help[unsound-ternary]: unsound pseudo-ternary expression
      --> @@INPUT@@:11:30
       |
    11 |       - run: echo ${{ foo && '' || 'bar' }}
       |                              ^^ pseudo-ternary has falsy true value
       |
       = note: audit confidence → High

    5 findings (4 suppressed): 0 informational, 1 low, 0 medium, 0 high
    "
    );

    Ok(())
}
