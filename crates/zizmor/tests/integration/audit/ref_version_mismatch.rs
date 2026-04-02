use crate::common::{input_under_test, zizmor};
use anyhow::Result;

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_ref_version_mismatch() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .output(crate::common::OutputMode::Both)
            .input(input_under_test("ref-version-mismatch.yml"))
            .run()?,
        @""
    );

    Ok(())
}

/// SHA-pinned actions without version comments produce a pedantic finding.
#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_missing_version_comment_pedantic() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .args(["--persona=pedantic"])
            .input(input_under_test("ref-version-mismatch.yml"))
            .run()?,
        @""
    );

    Ok(())
}

/// Tags that point to other tags are handled correctly.
#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_nested_annotated_tags() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .input(input_under_test(
                "ref-version-mismatch/nested-annotated-tags.yml"
            ))
            .run()?,
        @"No findings to report. Good job! (1 suppressed)"
    );

    Ok(())
}

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_issue_1853() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .input(input_under_test("ref-version-mismatch/issue-1853-repro.yml"))
            .run()?,
        @"
    warning[ref-version-mismatch]: action's hash pin does not match version comment
      --> @@INPUT@@:14:75
       |
    14 |         uses: actions/setup-go@4a3601121dd01d1626a1e23e37211e3254c1c06c # v9.9.9
       |         ---------------------------------------------------------------   ^^^^^^ points to unknown ref
       |         |
       |         is pointed to by tag v6.4.0
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    2 findings (1 suppressed, 1 fixable): 0 informational, 0 low, 1 medium, 0 high
    "
    );

    Ok(())
}

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_issue_1869() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .input(input_under_test("ref-version-mismatch/issue-1869-repro.yml"))
            .run()?,
        @"No findings to report. Good job! (1 suppressed)"
    );

    Ok(())
}
