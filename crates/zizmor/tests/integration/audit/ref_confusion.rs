use crate::common::{input_under_test, zizmor};
use anyhow::Result;

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_ref_confusion() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("ref-confusion.yml"))
            .offline(false)
            .run()?,
        @r"
    warning[ref-confusion]: git ref for action with ambiguous ref type
      --> @@INPUT@@:11:9
       |
    11 |       - uses: woodruffw/gha-hazmat/ref-confusion@confusable # zizmor: ignore[unpinned-uses]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ uses a ref that's provided by both the branch and tag namespaces
       |
       = note: audit confidence → High

    4 findings (1 ignored, 2 suppressed): 0 informational, 0 low, 1 medium, 0 high
    "
    );

    Ok(())
}

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_issue_518_repro() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("ref-confusion/issue-518-repro.yml"))
            .offline(false)
            .run()?,
        @"No findings to report. Good job! (1 ignored, 1 suppressed)"
    );

    Ok(())
}
