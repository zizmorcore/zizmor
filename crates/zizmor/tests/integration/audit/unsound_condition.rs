use crate::common::{WorkspaceBuilder, input_under_test, zizmor};

#[test]
fn test_normal_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unsound-condition.yml"))
            .run()?,
        @r#"
    error[unsound-condition]: unsound conditional expression
      --> @@INPUT@@:27:9
       |
    27 | /         if: |
    28 | |           ${{ some.context }}
       | |_____________________________^ condition always evaluates to true
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[unsound-condition]: unsound conditional expression
      --> @@INPUT@@:33:9
       |
    33 | /         if: >
    34 | |           ${{ some.context }}
       | |_____________________________^ condition always evaluates to true
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[unsound-condition]: unsound conditional expression
      --> @@INPUT@@:60:9
       |
    60 | /         if: |
    61 | |           ${{ some.context
    62 | |             && other.context
    63 | |           }}
       | |____________^ condition always evaluates to true
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[unsound-condition]: unsound conditional expression
      --> @@INPUT@@:68:9
       |
    68 |         if: true && ${{ false }} # zizmor: ignore[obfuscation]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^ condition always evaluates to true
       |
       = note: audit confidence → High

    error[unsound-condition]: unsound conditional expression
      --> @@INPUT@@:73:9
       |
    73 |         if: ${{ false }} && true # zizmor: ignore[obfuscation]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^ condition always evaluates to true
       |
       = note: audit confidence → High

    error[unsound-condition]: unsound conditional expression
      --> @@INPUT@@:78:9
       |
    78 |         if: ${{ false }} lol # zizmor: ignore[obfuscation]
       |         ^^^^^^^^^^^^^^^^^^^^ condition always evaluates to true
       |
       = note: audit confidence → High

    error[unsound-condition]: unsound conditional expression
      --> @@INPUT@@:83:9
       |
    83 |         if: lol ${{ false }} # zizmor: ignore[obfuscation]
       |         ^^^^^^^^^^^^^^^^^^^^ condition always evaluates to true
       |
       = note: audit confidence → High

    error[unsound-condition]: unsound conditional expression
      --> @@INPUT@@:88:9
       |
    88 |         if: "${{ false }} " # zizmor: ignore[obfuscation]
       |         ^^^^^^^^^^^^^^^^^^^ condition always evaluates to true
       |
       = note: audit confidence → High

    error[unsound-condition]: unsound conditional expression
      --> @@INPUT@@:93:9
       |
    93 |         if: " ${{ false }}" # zizmor: ignore[obfuscation]
       |         ^^^^^^^^^^^^^^^^^^^ condition always evaluates to true
       |
       = note: audit confidence → High

    16 findings (6 ignored, 1 suppressed, 3 safe fixes): 0 informational, 0 low, 0 medium, 9 high
    "#
    );

    Ok(())
}

#[test]
fn test_fix_simple_literal_block() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: simple case
        if: |
          ${{ github.event_name == 'push' }}
        run: echo "test"
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .output(crate::common::OutputMode::Both)
                .args(["--fix=all"])
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -8,3 +8,3 @@
           - name: simple case
    -        if: |
    +        if: |-
               ${{ github.event_name == 'push' }}
    "
    );

    Ok(())
}

#[test]
fn test_fix_folded_block() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: folded case
        if: >
          ${{ github.actor == 'dependabot[bot]' }}
        run: echo "test"
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .output(crate::common::OutputMode::Both)
                .args(["--fix=all"])
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -8,3 +8,3 @@
           - name: folded case
    -        if: >
    +        if: >-
               ${{ github.actor == 'dependabot[bot]' }}
    "
    );

    Ok(())
}

#[test]
fn test_fix_multiline_expression() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: multiline case
        if: |
          ${{ github.event_name == 'push'
            && github.ref == 'refs/heads/main' }}
        run: echo "test"
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .output(crate::common::OutputMode::Both)
                .args(["--fix=all"])
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -8,3 +8,3 @@
           - name: multiline case
    -        if: |
    +        if: |-
               ${{ github.event_name == 'push'
    "
    );

    Ok(())
}

#[test]
fn test_fix_complex_multiline_expression() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: complex case
        if: |
          ${{
            github.event_name == 'push' &&
            (github.ref == 'refs/heads/main' ||
             startsWith(github.ref, 'refs/heads/release/'))
          }}
        run: echo "test"
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .output(crate::common::OutputMode::Both)
                .args(["--fix=all"])
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -8,3 +8,3 @@
           - name: complex case
    -        if: |
    +        if: |-
               ${{
    "
    );

    Ok(())
}

#[test]
fn test_fix_reusable_job() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Test
on: push
jobs:
  reusable-job:
    if: |
      ${{ github.event_name == 'pull_request' }}
    uses: $/.github/workflows/reusable.yml
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            zizmor()
                .output(crate::common::OutputMode::Both)
                .args(["--fix=all"])
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -5,3 +5,3 @@
       reusable-job:
    -    if: |
    +    if: |-
           ${{ github.event_name == 'pull_request' }}
    "
    );

    Ok(())
}
