use crate::common::{input_under_test, zizmor};
use anyhow::Result;

#[test]
fn test_unpinned_uses_pedantic() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses.yml"))
            .args(["--pedantic"])
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:16:15
       |
    16 |       - uses: actions/checkout@v3
       |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    1 finding: 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

#[test]
fn test_unpinned_uses_default() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses.yml"))
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:16:15
       |
    16 |       - uses: actions/checkout@v3
       |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    1 finding: 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

#[test]
fn test_action_pedantic() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses/action.yml"))
            .args(["--pedantic"])
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:12:13
       |
    12 |       uses: asdf-vm/actions/setup@v3
       |             ^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:15:13
       |
    15 |       uses: asdf-vm/actions/setup@main
       |             ^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    2 findings: 0 informational, 0 low, 0 medium, 2 high
    "
    );

    Ok(())
}

#[test]
fn test_issue_433_repro() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses/issue-433-repro.yml"))
            .args(["--pedantic"])
            .run()?,
        @"No findings to report. Good job!"
    );

    Ok(())
}

/// Should not crash.
#[test]
fn test_issue_659_repro() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses/issue-659-repro.yml"))
            .args(["--pedantic"])
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:24:15
       |
    24 |         uses: actions/setup-node@v4
       |               ^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    1 finding: 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

/// Reproduction case for #1543:
/// `uses:` clauses that use block-style YAML strings should be handled
/// correctly and shouldn't cause crashes in subfeature extraction.
#[test]
fn test_issue_1543_repro() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses/issue-1543-repro.yml"))
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:18:11
       |
    18 |           actions/checkout@v4
       |           ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    2 findings (1 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

/// Default policies (no explicit config).
#[test]
fn test_default_config() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:12:15
       |
    12 |       - uses: actions/setup-python@v4
       |               ^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:14:15
       |
    14 |       - uses: actions/checkout@v3
       |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:22:15
       |
    22 |       - uses: pypa/gh-action-pypi-publish@release/v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:24:15
       |
    24 |       - uses: github/codeql-action/init@v3
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:26:15
       |
    26 |       - uses: github/codeql-action/upload-sarif@v3
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    6 findings (1 suppressed): 0 informational, 0 low, 0 medium, 5 high
    "
    );

    Ok(())
}

/// Require all uses to be hash-pinned.
#[test]
fn test_hash_pin_everything_config() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .config(input_under_test(
                "unpinned-uses/configs/hash-pin-everything.yml"
            ))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:12:15
       |
    12 |       - uses: actions/setup-python@v4
       |               ^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:14:15
       |
    14 |       - uses: actions/checkout@v3
       |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:22:15
       |
    22 |       - uses: pypa/gh-action-pypi-publish@release/v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:24:15
       |
    24 |       - uses: github/codeql-action/init@v3
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:26:15
       |
    26 |       - uses: github/codeql-action/upload-sarif@v3
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    6 findings (1 suppressed): 0 informational, 0 low, 0 medium, 5 high
    "
    );

    Ok(())
}

/// Require all uses to be ref-pinned.
#[test]
fn test_ref_pin_everything_config() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .config(input_under_test(
                "unpinned-uses/configs/ref-pin-everything.yml"
            ))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @"No findings to report. Good job! (1 suppressed)"
    );

    Ok(())
}

#[test]
fn test_composite_config() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .config(input_under_test("unpinned-uses/configs/composite.yml"))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:12:15
       |
    12 |       - uses: actions/setup-python@v4
       |               ^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by actions/setup-python policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:24:15
       |
    24 |       - uses: github/codeql-action/init@v3
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:26:15
       |
    26 |       - uses: github/codeql-action/upload-sarif@v3
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    4 findings (1 suppressed): 0 informational, 0 low, 0 medium, 3 high
    "
    );

    Ok(())
}

#[test]
fn test_composite_config_2() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .config(input_under_test("unpinned-uses/configs/composite-2.yml"))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:24:15
       |
    24 |       - uses: github/codeql-action/init@v3
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by github/codeql-action/init policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:26:15
       |
    26 |       - uses: github/codeql-action/upload-sarif@v3
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by github/codeql-action/upload-sarif policy)
       |
       = note: audit confidence → High

    3 findings (1 suppressed): 0 informational, 0 low, 0 medium, 2 high
    "
    );

    Ok(())
}

#[test]
fn test_empty_config() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .config(input_under_test("unpinned-uses/configs/empty.yml"))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:12:15
       |
    12 |       - uses: actions/setup-python@v4
       |               ^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:14:15
       |
    14 |       - uses: actions/checkout@v3
       |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:22:15
       |
    22 |       - uses: pypa/gh-action-pypi-publish@release/v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:24:15
       |
    24 |       - uses: github/codeql-action/init@v3
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:26:15
       |
    26 |       - uses: github/codeql-action/upload-sarif@v3
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    6 findings (1 suppressed): 0 informational, 0 low, 0 medium, 5 high
    "
    );

    Ok(())
}

#[test]
fn test_invalid_wrong_policy_object() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(1)
            .config(input_under_test(
                "unpinned-uses/configs/invalid-wrong-policy-object.yml"
            ))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @"
     INFO zizmor: 🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@
      |
      = help: check the configuration for the 'unpinned-uses' rule
      = help: see: https://docs.zizmor.sh/audits/#unpinned-uses-configuration

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid syntax for audit `unpinned-uses`
        2: invalid type: sequence, expected a map
    "
    );

    Ok(())
}

#[test]
fn test_invalid_policy_syntax_1() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(1)
            .config(input_under_test(
                "unpinned-uses/configs/invalid-policy-syntax-1.yml"
            ))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @"
     INFO zizmor: 🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@
      |
      = help: check the configuration for the 'unpinned-uses' rule
      = help: see: https://docs.zizmor.sh/audits/#unpinned-uses-configuration

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid syntax for audit `unpinned-uses`
        2: invalid pattern: lol
    "
    );

    Ok(())
}

#[test]
fn test_invalid_policy_syntax_2() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(1)
            .config(input_under_test(
                "unpinned-uses/configs/invalid-policy-syntax-2.yml"
            ))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @"
     INFO zizmor: 🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@
      |
      = help: check the configuration for the 'unpinned-uses' rule
      = help: see: https://docs.zizmor.sh/audits/#unpinned-uses-configuration

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid syntax for audit `unpinned-uses`
        2: invalid pattern: foo/
    "
    );

    Ok(())
}

#[test]
fn test_invalid_policy_syntax_3() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(1)
            .config(input_under_test(
                "unpinned-uses/configs/invalid-policy-syntax-3.yml"
            ))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @"
     INFO zizmor: 🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@
      |
      = help: check the configuration for the 'unpinned-uses' rule
      = help: see: https://docs.zizmor.sh/audits/#unpinned-uses-configuration

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid syntax for audit `unpinned-uses`
        2: invalid pattern: */foo
    "
    );

    Ok(())
}

#[test]
fn test_invalid_policy_syntax_4() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(1)
            .config(input_under_test(
                "unpinned-uses/configs/invalid-policy-syntax-4.yml"
            ))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @"
     INFO zizmor: 🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@
      |
      = help: check the configuration for the 'unpinned-uses' rule
      = help: see: https://docs.zizmor.sh/audits/#unpinned-uses-configuration

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid syntax for audit `unpinned-uses`
        2: invalid pattern: foo/b*r
    "
    );

    Ok(())
}

#[test]
fn test_invalid_policy_syntax_5() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(1)
            .config(input_under_test(
                "unpinned-uses/configs/invalid-policy-syntax-5.yml"
            ))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @"
     INFO zizmor: 🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@
      |
      = help: check the configuration for the 'unpinned-uses' rule
      = help: see: https://docs.zizmor.sh/audits/#unpinned-uses-configuration

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid syntax for audit `unpinned-uses`
        2: unknown variant `does not exist`, expected one of `any`, `ref-pin`, `hash-pin`
    "
    );

    Ok(())
}

#[test]
fn test_invalid_policy_syntax_6() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(1)
            .config(input_under_test(
                "unpinned-uses/configs/invalid-policy-syntax-6.yml"
            ))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @"
     INFO zizmor: 🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid `unpinned-uses` config
        2: cannot use exact ref patterns here: `foo/bar@v1`
    "
    );

    Ok(())
}

#[test]
fn test_reusable_workflow_unpinned() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses/reusable-workflow-unpinned.yml"))
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:17:11
       |
    17 |     uses: owner/repo/.github/workflows/reusable.yml@main
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:21:11
       |
    21 |     uses: owner/repo/.github/workflows/reusable.yml@v1
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    help[self-repository]: use GitHub's dedicated self-repository syntax
      --> @@INPUT@@:13:11
       |
    12 |   local-workflow:
       |   -------------- this job
    13 |     uses: ./.github/workflows/local.yml
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ use '$/...' instead of './...'
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    3 findings (1 safe fixes): 0 informational, 1 low, 0 medium, 2 high
    "
    );

    Ok(())
}

#[cfg(feature = "gh-token-tests")]
#[test]
fn test_fix() -> anyhow::Result<()> {
    use crate::common::{NetworkMode, WorkspaceBuilder};

    let workflow_content = r#"
name: Test
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout with ref-pin
        uses: actions/checkout@v6.0.1
        with:
          persist-credentials: false
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", &workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .offline(NetworkMode::AssertOnline)
                .output(crate::common::OutputMode::Both)
                .args(["--fix=all"])
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -9,3 +9,3 @@
           - name: Checkout with ref-pin
    -        uses: actions/checkout@v6.0.1
    +        uses: actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1
             with:
    "
    );

    Ok(())
}

#[cfg(feature = "gh-token-tests")]
#[test]
fn test_fix_crlf() -> anyhow::Result<()> {
    use crate::common::{NetworkMode, WorkspaceBuilder};

    let workflow_content = r#"
name: Test
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout with ref-pin
        uses: actions/checkout@v6.0.1
        with:
          persist-credentials: false
"#
    .replace("\n", "\r\n");

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", &workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .offline(NetworkMode::AssertOnline)
                .output(crate::common::OutputMode::Both)
                .args(["--fix=all"])
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -9,3 +9,3 @@
           - name: Checkout with ref-pin
    -        uses: actions/checkout@v6.0.1
    +        uses: actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1
             with:
    "
    );

    Ok(())
}

#[cfg(feature = "gh-token-tests")]
#[test]
fn test_fix_overwrites_comment() -> anyhow::Result<()> {
    use crate::common::{NetworkMode, WorkspaceBuilder};

    let workflow_content = r#"
name: Test
on: push
permissions: {}
jobs:
    test:
        runs-on: ubuntu-latest
        steps:
        - name: Checkout with ref-pin
          uses: actions/checkout@v6.0.1 # old comment
          with:
            persist-credentials: false
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", &workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .offline(NetworkMode::AssertOnline)
                .output(crate::common::OutputMode::Both)
                .args(["--fix=all"])
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -9,3 +9,3 @@
             - name: Checkout with ref-pin
    -          uses: actions/checkout@v6.0.1 # old comment
    +          uses: actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1
               with:
    "
    );

    Ok(())
}

#[cfg(feature = "gh-token-tests")]
#[test]
fn test_fix_bizarre_formatting() -> anyhow::Result<()> {
    use crate::common::{NetworkMode, WorkspaceBuilder};

    let workflow_content = r#"
name: Test
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      -
        uses: actions/checkout@v6.0.1
        with:
          persist-credentials: false
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", &workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .offline(NetworkMode::AssertOnline)
                .output(crate::common::OutputMode::Both)
                .args(["--fix=all"])
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -9,3 +9,3 @@
           -
    -        uses: actions/checkout@v6.0.1
    +        uses: actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1
             with:
    "
    );

    Ok(())
}

#[cfg(feature = "gh-token-tests")]
#[test]
fn test_fix_preserves_subpath() -> anyhow::Result<()> {
    use crate::common::{NetworkMode, WorkspaceBuilder};

    let workflow_content = r#"
name: Test
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: bytecodealliance/actions/wasmtime/setup@v1.1.3
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", &workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .offline(NetworkMode::AssertOnline)
                .output(crate::common::OutputMode::Both)
                .args(["--fix=all"])
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -8,2 +8,2 @@
         steps:
    -      - uses: bytecodealliance/actions/wasmtime/setup@v1.1.3
    +      - uses: bytecodealliance/actions/wasmtime/setup@9152e710e9f7182e4c29ad218e4f335a7b203613 # v1.1.3
    "
    );

    Ok(())
}

/// Tests that we expand a major version ref like `@v1` to the full version `v1.2.0`
/// in the fix's inserted comment.
#[cfg(feature = "gh-token-tests")]
#[test]
fn test_fix_major_version_pins_to_full_version() -> anyhow::Result<()> {
    use crate::common::{NetworkMode, WorkspaceBuilder};

    let workflow_content = r#"
name: Test
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout with major-only ref
        uses: actions/checkout@v1
        with:
          persist-credentials: false
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", &workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .offline(NetworkMode::AssertOnline)
                .output(crate::common::OutputMode::Both)
                .args(["--fix=all"])
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -9,3 +9,3 @@
           - name: Checkout with major-only ref
    -        uses: actions/checkout@v1
    +        uses: actions/checkout@50fbc622fc4ef5163becd7fab6573eac35f8462e # v1.2.0
             with:
    "
    );

    Ok(())
}
