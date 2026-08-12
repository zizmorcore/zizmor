use anyhow::Result;

use crate::common::{NetworkMode, input_under_test, zizmor};

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_default_persona() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(NetworkMode::AssertOnline)
            .input(input_under_test("known-vulnerable-actions/setup-php.yml"))
            .run()?,
        @"
    warning[known-vulnerable-actions]: action has a known vulnerability
      --> @@INPUT@@:17:9
       |
    17 |       - uses: shivammathur/setup-php@accd6127cb78bee3e8082180cb391013d204ef9f # 2.37.0
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ GHSA-5wxr-w449-57cm
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    warning[known-vulnerable-actions]: action has a known vulnerability
      --> @@INPUT@@:17:9
       |
    17 |       - uses: shivammathur/setup-php@accd6127cb78bee3e8082180cb391013d204ef9f # 2.37.0
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ GHSA-pqwm-q9pv-ph8r
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    2 findings (2 unsafe fixes): 0 informational, 0 low, 2 medium, 0 high
    "
    );

    Ok(())
}

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_config_allow() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(NetworkMode::AssertOnline)
            .input(input_under_test("known-vulnerable-actions/setup-php.yml"))
            .config(input_under_test(
                "known-vulnerable-actions/configs/allow.yml"
            ))
            .run()?,
        @"No findings to report. Good job!"
    );

    Ok(())
}

#[cfg(feature = "gh-token-tests")]
#[test]
fn test_fix_version_pin() -> anyhow::Result<()> {
    use crate::common::WorkspaceBuilder;

    // Note: this ignores `unpinned-uses` because of bug #2286.
    // See: <https://github.com/zizmorcore/zizmor/issues/2286>
    let workflow_content = r#"
name: Test
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Commit pinned action
        uses: actions/download-artifact@v4.0.0 # zizmor: ignore[unpinned-uses]
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .args(["--fix=all"])
                .offline(NetworkMode::AssertOnline)
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -9,2 +9,2 @@
           - name: Commit pinned action
    -        uses: actions/download-artifact@v4.0.0 # zizmor: ignore[unpinned-uses]
    +        uses: actions/download-artifact@v4.1.3 # zizmor: ignore[unpinned-uses]
    "
    );

    Ok(())
}

#[cfg(feature = "gh-token-tests")]
#[test]
fn test_fix_commit_pin() -> anyhow::Result<()> {
    use crate::common::WorkspaceBuilder;

    let workflow_content = r#"
name: Test
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Commit pinned action
        uses: actions/download-artifact@7a1cd3216ca9260cd8022db641d960b1db4d1be4  # v4.0.0
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .args(["--fix=all"])
                .offline(NetworkMode::AssertOnline)
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -9,2 +9,2 @@
           - name: Commit pinned action
    -        uses: actions/download-artifact@7a1cd3216ca9260cd8022db641d960b1db4d1be4  # v4.0.0
    +        uses: actions/download-artifact@87c55149d96e628cc2ef7e6fc2aab372015aec85  # v4.1.3
    "
    );

    Ok(())
}

// TODO: test_fix_commit_pin_subpath

#[cfg(feature = "gh-token-tests")]
#[test]
fn test_fix_commit_pin_no_comment() -> anyhow::Result<()> {
    use crate::common::WorkspaceBuilder;

    let workflow_content = r#"
name: Test
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Commit pinned action
        uses: actions/download-artifact@7a1cd3216ca9260cd8022db641d960b1db4d1be4
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .args(["--fix=all"])
                .offline(NetworkMode::AssertOnline)
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -9,2 +9,2 @@
           - name: Commit pinned action
    -        uses: actions/download-artifact@7a1cd3216ca9260cd8022db641d960b1db4d1be4
    +        uses: actions/download-artifact@87c55149d96e628cc2ef7e6fc2aab372015aec85
    "
    );

    Ok(())
}
