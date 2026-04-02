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
        @"
    🌈 zizmor v@@VERSION@@
     INFO audit: zizmor: 🌈 completed @@INPUT@@
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:19:15
       |
    19 |       - uses: actions/setup-node@v3.8.2 # v3.8.2
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    warning[ref-version-mismatch]: action's hash pin does not match version comment
      --> @@INPUT@@:22:77
       |
    22 |       - uses: actions/setup-node@1a4442cacd436585916779262731d5b162bc6ec7 # v3.8.1
       |         -----------------------------------------------------------------   ^^^^^^ points to commit 5e21ff4d9bc1
       |         |
       |         is pointed to by tag v3.8.2
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    warning[ref-version-mismatch]: action's hash pin does not match version comment
      --> @@INPUT@@:25:77
       |
    25 |       - uses: actions/setup-node@1a4442cacd436585916779262731d5b162bc6ec7 # v300000.8.1
       |         -----------------------------------------------------------------   ^^^^^^^^^^^ points to unknown ref
       |         |
       |         is pointed to by tag v3.8.2
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    4 findings (1 suppressed, 3 fixable): 0 informational, 0 low, 2 medium, 1 high
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
