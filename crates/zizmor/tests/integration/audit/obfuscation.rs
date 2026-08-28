use crate::common::{WorkspaceBuilder, input_under_test, zizmor};
use anyhow::Result;

#[test]
fn test_obfuscation() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("obfuscation.yml"))
            .run()?,
        @"
    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:13:9
       |
    13 |       - uses: actions/checkout/@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ actions reference contains empty component
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:16:9
       |
    16 |       - uses: actions/checkout////@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
       |         |
       |         actions reference contains empty component
       |         actions reference contains empty component
       |         actions reference contains empty component
       |         actions reference contains empty component
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:19:9
       |
    19 |       - uses: github/codeql-action/./init@b8d3b6e8af63cde30bdc382c0bc28114f4346c88 # v2.28.1
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ actions reference contains '.'
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:20:9
       |
    20 |       - uses: actions/checkout/.@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ actions reference contains '.'
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:23:9
       |
    23 |       - uses: actions/cache/save/../save@0057852bfaa89a56745cba8c7296529d2fc39830 # v4.3.0
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ actions reference contains '..'
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:26:9
       |
    26 |       - uses: actions/cache/../../save@0057852bfaa89a56745cba8c7296529d2fc39830 # v4.3.0
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
       |         |
       |         actions reference contains '..'
       |         actions reference contains '..'
       |
       = note: audit confidence → High

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:34:20
       |
    34 |           echo ${{ '' }}
       |                    ^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:35:20
       |
    35 |           echo ${{ 'a' }}
       |                    ^^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:36:20
       |
    36 |           echo ${{ true }}
       |                    ^^^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:37:20
       |
    37 |           echo ${{ true && false }}
       |                    ^^^^^^^^^^^^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:38:20
       |
    38 |           echo ${{ true || false }}
       |                    ^^^^^^^^^^^^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:39:20
       |
    39 |           echo ${{ 1 > 2 || true }}
       |                    ^^^^^^^^^^^^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:40:20
       |
    40 |           echo ${{ 1 != 2}}
       |                    ^^^^^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:44:20
       |
    44 |           echo ${{ format('{0}', 'abc') }}
       |                    ^^^^^^^^^^^^^^^^^^^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:45:20
       |
    45 |           echo ${{ format('{0} {1}', 'abc', 'def') }}
       |                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:46:20
       |
    46 |           echo ${{ format('{0} {1}', 'abc', format('{0}', 'def')) }}
       |                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:47:20
       |
    47 |           echo ${{ startsWith('abc', 'a') }}
       |                    ^^^^^^^^^^^^^^^^^^^^^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:48:20
       |
    48 |           echo ${{ ENDSWITH('abc', 'c') }}
       |                    ^^^^^^^^^^^^^^^^^^^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:53:60
       |
    53 |           echo ${{ format('{0}, {1}', github.event.number, format('{0}', 'abc')) }}
       |                                                            ^^^^^^^^^^^^^^^^^^^^ can be reduced to a constant
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:55:99
       |
    55 |           echo ${{ format('{0}, {1}', github.event.number, format('{0} {1}', github.event.number, true || false)) }}
       |                                                                                                   ^^^^^^^^^^^^^ can be reduced to a constant
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    37 findings (1 ignored, 16 suppressed, 19 safe fixes): 0 informational, 20 low, 0 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_computed_indices_pedantic() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("obfuscation/computed-indices.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @"
    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:18:23
       |
    18 |       - if: ${{ inputs[inputs.foo] }}
       |                       ^^^^^^^^^^^^ index expression is computed
       |
       = note: audit confidence → High

    1 finding: 0 informational, 1 low, 0 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_issue_1177_repro_pedantic() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("obfuscation/issue-1177-repro.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @"No findings to report. Good job!"
    );

    Ok(())
}

#[test]
fn test_issue_1769() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
        .input(input_under_test("obfuscation/issue-1769-repro.yml")).run()?,
        @"
    info[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:19:9
       |
    18 |       - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
       |         --------------------------------------------------------------- this action
    19 |         with: ${{ fromJson(steps.setup.outputs.options) }}
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ use of an expression for `with:` prevents analysis
       |
       = note: audit confidence → High

    1 finding: 1 informational, 0 low, 0 medium, 0 high
    "
    );

    Ok(())
}

/// Test that we correctly replace `${{ 'foo' }}` with `foo` instead of `${{ foo }}`.
///
/// Reproducer for #1578; see: <https://github.com/zizmorcore/zizmor/issues/1578>.
#[test]
fn test_fix_static_evaluation() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Test Workflow
on: push

permissions: {}

jobs:
  release-please:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          fetch-depth: 0 # ... because release-please scans historical commits to build releases, so we need all the history.
          persist-credentials: false
      - id: release
        uses: $/vendor/github.com/googleapis/release-please-action
        with:
          config-file: "tools/releasing/config.release-please.json"
          manifest-file: "tools/releasing/manifest.release-please.json"
          target-branch: "${{ inputs.rp_target_branch }}"
    outputs:
      iac/terraform/attribution.tfm--release_created: ${{ 'steps.release.outputs.iac/terraform/attribution.tfm--release_created' }}
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .args(["--fix=safe"])
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -21,2 +21,2 @@
         outputs:
    -      iac/terraform/attribution.tfm--release_created: ${{ 'steps.release.outputs.iac/terraform/attribution.tfm--release_created' }}
    +      iac/terraform/attribution.tfm--release_created: steps.release.outputs.iac/terraform/attribution.tfm--release_created
    "
    );

    Ok(())
}

#[test]
fn test_fix_uses_path_empty_components() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Test Workflow
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout////@v4
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .args(["--fix=safe"])
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -8,2 +8,2 @@
         steps:
    -      - uses: actions/checkout////@v4
    +      - uses: actions/checkout@v4
    "
    );

    Ok(())
}

#[test]
fn test_fix_uses_path_dot() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Test Workflow
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: github/codeql-action/./init@v2
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .args(["--fix=safe"])
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -8,2 +8,2 @@
         steps:
    -      - uses: github/codeql-action/./init@v2
    +      - uses: github/codeql-action/init@v2
    "
    );

    Ok(())
}

#[test]
fn test_fix_uses_path_double_dot() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Test Workflow
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache/save/../save@v4
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .args(["--fix=safe"])
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -8,2 +8,2 @@
         steps:
    -      - uses: actions/cache/save/../save@v4
    +      - uses: actions/cache/save@v4
    "
    );

    Ok(())
}
