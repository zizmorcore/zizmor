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
     INFO zizmor: 🌈 zizmor v@@VERSION@@
     INFO audit: zizmor: 🌈 completed @@INPUT@@
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:22:15
       |
    22 |       - uses: actions/setup-node@v3.8.2 # v3.8.2
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    warning[ref-version-mismatch]: action's hash pin has mismatched or missing version comment
      --> @@INPUT@@:25:77
       |
    25 |       - uses: actions/setup-node@1a4442cacd436585916779262731d5b162bc6ec7 # v3.8.1
       |         -----------------------------------------------------------------   ^^^^^^ points to commit 5e21ff4d9bc1
       |         |
       |         is pointed to by tag v3.8.2
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    warning[ref-version-mismatch]: action's hash pin has mismatched or missing version comment
      --> @@INPUT@@:28:77
       |
    28 |       - uses: actions/setup-node@1a4442cacd436585916779262731d5b162bc6ec7 # v300000.8.1
       |         -----------------------------------------------------------------   ^^^^^^^^^^^ points to unknown ref
       |         |
       |         is pointed to by tag v3.8.2
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    6 findings (3 suppressed, 3 unsafe fixes): 0 informational, 0 low, 2 medium, 1 high
    "
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
        @"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:22:15
       |
    22 |       - uses: actions/setup-node@v3.8.2 # v3.8.2
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[ref-version-mismatch]: action's hash pin has mismatched or missing version comment
      --> @@INPUT@@:16:9
       |
    16 |       - uses: actions/setup-node@1a4442cacd436585916779262731d5b162bc6ec7
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ missing version comment
       |
       = note: audit confidence → High
       = tip: add version comment '# v3.8.2'
       = note: this finding has an auto-fix

    help[ref-version-mismatch]: action's hash pin has mismatched or missing version comment
      --> @@INPUT@@:19:9
       |
    19 |       - uses: actions/setup-node@1a4442cacd436585916779262731d5b162bc6ec7 # some comment
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ comment does not contain a version
       |
       = note: audit confidence → High
       = tip: rewrite comment to include '# v3.8.2'

    warning[ref-version-mismatch]: action's hash pin has mismatched or missing version comment
      --> @@INPUT@@:25:77
       |
    25 |       - uses: actions/setup-node@1a4442cacd436585916779262731d5b162bc6ec7 # v3.8.1
       |         -----------------------------------------------------------------   ^^^^^^ points to commit 5e21ff4d9bc1
       |         |
       |         is pointed to by tag v3.8.2
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    warning[ref-version-mismatch]: action's hash pin has mismatched or missing version comment
      --> @@INPUT@@:28:77
       |
    28 |       - uses: actions/setup-node@1a4442cacd436585916779262731d5b162bc6ec7 # v300000.8.1
       |         -----------------------------------------------------------------   ^^^^^^^^^^^ points to unknown ref
       |         |
       |         is pointed to by tag v3.8.2
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[concurrency-limits]: insufficient job-level concurrency limits
     --> @@INPUT@@:3:1
      |
    3 | on: [push]
      | ^^^^^^^^^^ workflow is missing concurrency setting
    ...
    9 |     name: ref-version-mismatch
      |     -------------------------- job affected by missing workflow concurrency
      |
      = note: audit confidence → High

    6 findings (4 unsafe fixes): 0 informational, 3 low, 2 medium, 1 high
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
    warning[ref-version-mismatch]: action's hash pin has mismatched or missing version comment
      --> @@INPUT@@:14:75
       |
    14 |         uses: actions/setup-go@4a3601121dd01d1626a1e23e37211e3254c1c06c # v9.9.9
       |         ---------------------------------------------------------------   ^^^^^^ points to unknown ref
       |         |
       |         is pointed to by tag v6.4.0
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    3 findings (1 ignored, 1 suppressed, 1 unsafe fixes): 0 informational, 0 low, 1 medium, 0 high
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

/// Bug #1899: version comments like `# 1.2.3` (without a `v` prefix) should be detected correctly.
#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_issue_1899() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .input(input_under_test("ref-version-mismatch/issue-1899-repro.yml"))
            .run()?,
        @"No findings to report. Good job!"
    );

    Ok(())
}

/// Bug #1938: version comments like `# create-github-app-token/v0.2.2` should be detected correctly.
#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_issue_1938() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .args(["--persona=pedantic"])
            .input(input_under_test("ref-version-mismatch/issue-1938-repro.yml"))
            .run()?, @"No findings to report. Good job!");

    Ok(())
}

/// Bug #2039: version comments like `# 1.2.3rc1` should be detected correctly.
#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_issue_2039() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .input(input_under_test("ref-version-mismatch/issue-2039-repro.yml"))
            .run()?,
        @"No findings to report. Good job!"
    );

    Ok(())
}

/// Bug #2165: ignore comments not correctly handled elsewhere on the same step.
#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_issue_2165() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .input(input_under_test("ref-version-mismatch/issue-2165-repro.yml"))
            .run()?,
        @"No findings to report. Good job! (1 ignored, 1 suppressed)"
    );

    Ok(())
}
