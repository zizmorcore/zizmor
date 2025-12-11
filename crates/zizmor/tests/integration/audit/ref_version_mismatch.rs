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
        @r"
    🌈 zizmor v@@VERSION@@
     INFO audit: zizmor: 🌈 completed @@INPUT@@
    warning[ref-version-mismatch]: detects commit SHAs that don't match their version comment tags
      --> @@INPUT@@:22:77
       |
    22 |       - uses: actions/setup-node@1a4442cacd436585916779262731d5b162bc6ec7 # v3.8.1
       |         -----------------------------------------------------------------   ^^^^^^ points to commit 5e21ff4d9bc1
       |         |
       |         is pointed to by tag v3.8.2
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    2 findings (1 suppressed, 1 fixable): 0 informational, 0 low, 1 medium, 0 high
    "
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
