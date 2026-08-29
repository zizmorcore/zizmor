use crate::common::{NetworkMode, input_under_test, zizmor};
use anyhow::Result;

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_ref_version_mismatch() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(NetworkMode::AssertOnline)
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
       |               -----------------------------------------------------------   ^^^^^^ tag points to commit 5e21ff4d9bc1
       |               |
       |               is pointed to by tag v3.8.2
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    warning[ref-version-mismatch]: action's hash pin has mismatched or missing version comment
      --> @@INPUT@@:28:77
       |
    28 |       - uses: actions/setup-node@1a4442cacd436585916779262731d5b162bc6ec7 # v300000.8.1
       |               -----------------------------------------------------------   ^^^^^^^^^^^ points to unknown ref
       |               |
       |               is pointed to by tag v3.8.2
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
            .offline(NetworkMode::AssertOnline)
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
      --> @@INPUT@@:16:15
       |
    16 |       - uses: actions/setup-node@1a4442cacd436585916779262731d5b162bc6ec7
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ missing version comment
       |
       = note: audit confidence → High
       = tip: add version comment '# v3.8.2'
       = note: this finding has an auto-fix

    help[ref-version-mismatch]: action's hash pin has mismatched or missing version comment
      --> @@INPUT@@:19:15
       |
    19 |       - uses: actions/setup-node@1a4442cacd436585916779262731d5b162bc6ec7 # some comment
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ comment does not contain a version
       |
       = note: audit confidence → High
       = tip: rewrite comment to include '# v3.8.2'

    warning[ref-version-mismatch]: action's hash pin has mismatched or missing version comment
      --> @@INPUT@@:25:77
       |
    25 |       - uses: actions/setup-node@1a4442cacd436585916779262731d5b162bc6ec7 # v3.8.1
       |               -----------------------------------------------------------   ^^^^^^ tag points to commit 5e21ff4d9bc1
       |               |
       |               is pointed to by tag v3.8.2
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    warning[ref-version-mismatch]: action's hash pin has mismatched or missing version comment
      --> @@INPUT@@:28:77
       |
    28 |       - uses: actions/setup-node@1a4442cacd436585916779262731d5b162bc6ec7 # v300000.8.1
       |               -----------------------------------------------------------   ^^^^^^^^^^^ points to unknown ref
       |               |
       |               is pointed to by tag v3.8.2
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
            .offline(NetworkMode::AssertOnline)
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
            .offline(NetworkMode::AssertOnline)
            .input(input_under_test("ref-version-mismatch/issue-1853-repro.yml"))
            .run()?,
        @"
    warning[ref-version-mismatch]: action's hash pin has mismatched or missing version comment
      --> @@INPUT@@:14:75
       |
    14 |         uses: actions/setup-go@4a3601121dd01d1626a1e23e37211e3254c1c06c # v9.9.9
       |               ---------------------------------------------------------   ^^^^^^ points to unknown ref
       |               |
       |               is pointed to by tag v6.4.0
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
            .offline(NetworkMode::AssertOnline)
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
            .offline(NetworkMode::AssertOnline)
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
            .offline(NetworkMode::AssertOnline)
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
            .offline(NetworkMode::AssertOnline)
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
            .offline(NetworkMode::AssertOnline)
            .input(input_under_test("ref-version-mismatch/issue-2165-repro.yml"))
            .run()?,
        @"No findings to report. Good job! (1 ignored, 1 suppressed)"
    );

    Ok(())
}

/// Bug #2321: comment diagnostic didn't specify the kind of reference,
/// leading to a confusing "v1 does not match v1" render.
///
/// See: <https://github.com/zizmorcore/zizmor/issues/2321>
#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_issue_2321() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(NetworkMode::AssertOnline)
            .input(input_under_test("ref-version-mismatch/issue-2321-repro.yml"))
            .run()?,
        @"
    warning[ref-version-mismatch]: action's hash pin has mismatched or missing version comment
      --> @@INPUT@@:14:87
       |
    14 |         uses: Azure/static-web-apps-deploy@1a947af9992250f3bc2e68ad0754c0b0c11566c9 # v1
       |               ---------------------------------------------------------------------   ^^ branch points to commit 4d27395796ac
       |               |
       |               is pointed to by tag v1
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    2 findings (1 suppressed, 1 unsafe fixes): 0 informational, 0 low, 1 medium, 0 high
    "
    );

    Ok(())
}

/// Bug #2324: ref-version-mismatch should support reusable workflow calls.
///
/// See: <https://github.com/zizmorcore/zizmor/issues/2324>
#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_issue_2324() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(NetworkMode::AssertOnline)
            .input(input_under_test("ref-version-mismatch/issue-2324-repro.yml"))
            .run()?,
        @"
    warning[ref-version-mismatch]: action's hash pin has mismatched or missing version comment
      --> @@INPUT@@:11:104
       |
    11 |     uses: docker/github-builder/.github/workflows/build.yml@58cb9f5b71b1836d6f690c1e95effdeb9b98cb8a # v1.16.0
       |           ------------------------------------------------------------------------------------------   ^^^^^^^ tag points to commit a492c6d04fd3
       |           |
       |           is pointed to by tag v1.17.0
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    1 findings (1 unsafe fixes): 0 informational, 0 low, 1 medium, 0 high
    "
    );

    Ok(())
}

#[cfg(feature = "gh-token-tests")]
#[test]
fn test_fix_add_version_comment_composite_action() -> anyhow::Result<()> {
    use crate::common::WorkspaceBuilder;

    let action_content = r#"
name: Test Missing Version Comment
description: Test Missing Version Comment
runs:
  using: composite
  steps:
    - name: Checkout without version comment
      uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      with:
        persist-credentials: false
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file("action/action.yml", action_content);

    insta::assert_snapshot!(
        &workspace.diff("action/action.yml", |workspace| {
            zizmor()
                .args(["--fix=all", "--persona=pedantic"])
                .offline(NetworkMode::AssertOnline)
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -7,3 +7,3 @@
         - name: Checkout without version comment
    -      uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
    +      uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
           with:
    "
    );

    Ok(())
}

#[cfg(feature = "gh-token-tests")]
#[test]
fn test_fix_add_version_comment_workflow() -> anyhow::Result<()> {
    use crate::common::WorkspaceBuilder;

    let workflow_content = r#"
name: Test Missing Version Comment
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout without version comment
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          persist-credentials: false
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .args(["--fix=all", "--persona=pedantic"])
                .offline(NetworkMode::AssertOnline)
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -9,3 +9,3 @@
           - name: Checkout without version comment
    -        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
    +        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
             with:
    "
    );

    Ok(())
}

#[cfg(feature = "gh-token-tests")]
#[test]
fn test_fix_version_comment_mismatch() -> anyhow::Result<()> {
    use crate::common::WorkspaceBuilder;

    let workflow_content = r#"
name: Test Version Comment Mismatch
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout with mismatched version comment
        uses: actions/checkout@722adc63f1aa60a57ec37892e133b1d319cae598 # v3.0.0
        with:
          persist-credentials: false
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .args(["--fix=all", "--persona=pedantic"])
                .offline(NetworkMode::AssertOnline)
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -9,3 +9,3 @@
           - name: Checkout with mismatched version comment
    -        uses: actions/checkout@722adc63f1aa60a57ec37892e133b1d319cae598 # v3.0.0
    +        uses: actions/checkout@722adc63f1aa60a57ec37892e133b1d319cae598 # v2.0.0
             with:
    "
    );

    Ok(())
}

#[cfg(feature = "gh-token-tests")]
#[test]
fn test_fix_version_comment_mismatch_crlf() -> anyhow::Result<()> {
    use crate::common::WorkspaceBuilder;

    let workflow_content = r#"
name: Test Version Comment Mismatch
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout with mismatched version comment
        uses: actions/checkout@722adc63f1aa60a57ec37892e133b1d319cae598 # v3.0.0
        with:
          persist-credentials: false
"#
    .replace('\n', "\r\n");

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", &workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .args(["--fix=all", "--persona=pedantic"])
                .offline(NetworkMode::AssertOnline)
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -9,3 +9,3 @@
           - name: Checkout with mismatched version comment
    -        uses: actions/checkout@722adc63f1aa60a57ec37892e133b1d319cae598 # v3.0.0
    +        uses: actions/checkout@722adc63f1aa60a57ec37892e133b1d319cae598 # v2.0.0
             with:
    "
    );

    Ok(())
}

#[cfg(feature = "gh-token-tests")]
#[test]
fn test_fix_version_comment_mismatch_bizarre_formatting() -> anyhow::Result<()> {
    use crate::common::WorkspaceBuilder;

    let workflow_content = r#"
name: Test Missing Version Comment
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      -
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          persist-credentials: false
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", &workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .args(["--fix=all", "--persona=pedantic"])
                .offline(NetworkMode::AssertOnline)
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -9,3 +9,3 @@
           -
    -        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
    +        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
             with:
    "
    );

    Ok(())
}

#[cfg(feature = "gh-token-tests")]
#[test]
fn test_fix_version_comment_different_formats() -> anyhow::Result<()> {
    use crate::common::WorkspaceBuilder;

    let workflow_content = r#"
name: Test Different Version Formats
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Tag format
        uses: actions/checkout@722adc63f1aa60a57ec37892e133b1d319cae598 # tag=v3.0.0
        with:
          persist-credentials: false
      - name: Simple format
        uses: actions/checkout@722adc63f1aa60a57ec37892e133b1d319cae598 # v3.0.0
        with:
          persist-credentials: false
      - name: Version format
        uses: actions/checkout@722adc63f1aa60a57ec37892e133b1d319cae598 # version: v3.0.0
        with:
          persist-credentials: false
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", &workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .args(["--fix=all", "--persona=pedantic"])
                .offline(NetworkMode::AssertOnline)
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -9,3 +9,3 @@
           - name: Tag format
    -        uses: actions/checkout@722adc63f1aa60a57ec37892e133b1d319cae598 # tag=v3.0.0
    +        uses: actions/checkout@722adc63f1aa60a57ec37892e133b1d319cae598 # v2.0.0
             with:
    @@ -13,3 +13,3 @@
           - name: Simple format
    -        uses: actions/checkout@722adc63f1aa60a57ec37892e133b1d319cae598 # v3.0.0
    +        uses: actions/checkout@722adc63f1aa60a57ec37892e133b1d319cae598 # v2.0.0
             with:
    @@ -17,3 +17,3 @@
           - name: Version format
    -        uses: actions/checkout@722adc63f1aa60a57ec37892e133b1d319cae598 # version: v3.0.0
    +        uses: actions/checkout@722adc63f1aa60a57ec37892e133b1d319cae598 # v2.0.0
             with:
    "
    );

    Ok(())
}

#[cfg(feature = "gh-token-tests")]
#[test]
fn test_fix_version_comment_nonexistent_ref() -> anyhow::Result<()> {
    use crate::common::WorkspaceBuilder;

    let workflow_content = r#"
name: nonexistent

on:
  push:

permissions: {}

jobs:
  test:
    name: test
    runs-on: ubuntu-latest
    steps:
      - name: Setup Go
        uses: actions/setup-go@4a3601121dd01d1626a1e23e37211e3254c1c06c # v9.9.9
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", &workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .args(["--fix=all", "--persona=pedantic"])
                .offline(NetworkMode::AssertOnline)
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -14,2 +14,2 @@
           - name: Setup Go
    -        uses: actions/setup-go@4a3601121dd01d1626a1e23e37211e3254c1c06c # v9.9.9
    +        uses: actions/setup-go@4a3601121dd01d1626a1e23e37211e3254c1c06c # v6.4.0
    "
    );

    Ok(())
}

#[cfg(feature = "gh-token-tests")]
#[test]
fn test_fix_reusable_workflow() -> anyhow::Result<()> {
    use crate::common::WorkspaceBuilder;

    let workflow_content = r#"
name: reusable

on:
  workflow_dispatch:

permissions: {}

jobs:
  job1:
    name: job1
    uses: docker/github-builder/.github/workflows/build.yml@58cb9f5b71b1836d6f690c1e95effdeb9b98cb8a # v1.16.0
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", &workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .args(["--fix=all", "--persona=pedantic"])
                .offline(NetworkMode::AssertOnline)
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -11,2 +11,2 @@
         name: job1
    -    uses: docker/github-builder/.github/workflows/build.yml@58cb9f5b71b1836d6f690c1e95effdeb9b98cb8a # v1.16.0
    +    uses: docker/github-builder/.github/workflows/build.yml@58cb9f5b71b1836d6f690c1e95effdeb9b98cb8a # v1.17.0
    "
    );

    Ok(())
}
