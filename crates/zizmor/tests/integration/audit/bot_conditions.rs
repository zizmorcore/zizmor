use crate::common::{WorkspaceBuilder, input_under_test, zizmor};

#[test]
fn test_regular_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("bot-conditions.yml"))
            .run()?,
        @"
    error[dangerous-triggers]: use of fundamentally insecure workflow trigger
     --> @@INPUT@@:1:1
      |
    1 | on: pull_request_target
      | ^^^^^^^^^^^^^^^^^^^^^^^ pull_request_target is almost always used insecurely
      |
      = note: audit confidence → Medium

    error[bot-conditions]: spoofable bot actor check
      --> @@INPUT@@:11:9
       |
     9 |     name: hackme
       |     ------------ this job
    10 |     runs-on: ubuntu-latest
    11 |     if: github.actor == 'dependabot[bot]'
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ actor context may be spoofable
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[bot-conditions]: spoofable bot actor check
      --> @@INPUT@@:15:17
       |
    13 |       - name: vulnerable-1
       |         ------------------ this step
    14 |         run: echo hello
    15 |         if: ${{ github.actor == 'dependabot[bot]' }}
       |                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ actor context may be spoofable
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[bot-conditions]: spoofable bot actor check
      --> @@INPUT@@:19:17
       |
    17 |       - name: vulnerable-2
       |         ------------------ this step
    18 |         run: echo hello
    19 |         if: ${{ github.actor == 'dependabot[bot]' && github.repository == 'example/example' }}
       |                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ actor context may be spoofable
       |
       = note: audit confidence → Medium
       = note: this finding has an auto-fix

    error[bot-conditions]: spoofable bot actor check
      --> @@INPUT@@:23:13
       |
    21 |       - name: vulnerable-3
       |         ------------------ this step
    22 |         run: echo hello
    23 |         if: github.actor == 'renovate[bot]'
       |             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ actor context may be spoofable
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[bot-conditions]: spoofable bot actor check
      --> @@INPUT@@:32:13
       |
    29 |       - name: vulnerable-5
       |         ------------------ this step
    ...
    32 |         if: github.ACTOR == 'dependabot[bot]'
       |             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ actor context may be spoofable
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[bot-conditions]: spoofable bot actor check
      --> @@INPUT@@:37:13
       |
    34 |       - name: vulnerable-6
       |         ------------------ this step
    ...
    37 |         if: github.actor == 'mystery[bot]'
       |             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ actor context may be spoofable
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[bot-conditions]: spoofable bot actor check
      --> @@INPUT@@:42:13
       |
    39 |       - name: vulnerable-7
       |         ------------------ this step
    ...
    42 |         if: github['actor'] == 'dependabot[bot]'
       |             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ actor context may be spoofable
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[bot-conditions]: spoofable bot actor check
      --> @@INPUT@@:47:13
       |
    44 |       - name: vulnerable-8
       |         ------------------ this step
    ...
    47 |         if: github['ACTOR'] == 'dependabot[bot]'
       |             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ actor context may be spoofable
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[bot-conditions]: spoofable bot actor check
      --> @@INPUT@@:52:13
       |
    49 |       - name: vulnerable-9
       |         ------------------ this step
    ...
    52 |         if: github.actor_id == 49699333
       |             ^^^^^^^^^^^^^^^^^^^^^^^^^^^ actor context may be spoofable
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[bot-conditions]: spoofable bot actor check
      --> @@INPUT@@:56:13
       |
    54 |       - name: vulnerable-10
       |         ------------------- this step
    55 |         run: echo hello
    56 |         if: github['ACTOR_ID'] == 49699333
       |             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ actor context may be spoofable
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[bot-conditions]: spoofable bot actor check
      --> @@INPUT@@:60:17
       |
    58 |       - name: vulnerable-11
       |         ------------------- this step
    59 |         run: echo hello
    60 |         if: ${{ github.actor_id == '49699333' }}
       |                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ actor context may be spoofable
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    13 findings (1 suppressed, 11 safe fixes): 0 informational, 0 low, 0 medium, 12 high
    "
    );

    Ok(())
}

#[test]
fn test_fix_replace_actor() -> anyhow::Result<()> {
    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(
        ".github/workflows/bot-conditions.yml",
        r#"
name: Test Workflow
on:
  pull_request_target:

jobs:
  test:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]'
    steps:
      - name: Test Step
        if: github.actor == 'dependabot[bot]'
        run: echo "hello"
"#,
    );

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/bot-conditions.yml", |workspace| {
            zizmor()
                .args(["--fix=all"])
                .input(workspace.path())
                .run()
        })?,
        @r#"
    @@ -8,6 +8,6 @@
         runs-on: ubuntu-latest
    -    if: github.actor == 'dependabot[bot]'
    +    if: github.event.pull_request.user.login == 'dependabot[bot]'
         steps:
           - name: Test Step
    -        if: github.actor == 'dependabot[bot]'
    +        if: github.event.pull_request.user.login == 'dependabot[bot]'
             run: echo "hello"
    "#
    );

    Ok(())
}

#[test]
fn test_fix_issue_comment_trigger() -> anyhow::Result<()> {
    let issue_comment_workflow = r#"
name: Test Issue Comment
on: issue_comment

jobs:
  test:
    runs-on: ubuntu-latest
    if: github.ACTOR == 'dependabot[bot]'
    steps:
      - name: Test Step
        if: github.actor == 'dependabot[bot]'
        run: echo "hello"
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(
        ".github/workflows/bot-conditions.yml",
        issue_comment_workflow,
    );

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/bot-conditions.yml", |workspace| {
            zizmor()
                .args(["--fix=all"])
                .input(workspace.path())
                .run()
        })?,
        @r#"
    @@ -7,6 +7,6 @@
         runs-on: ubuntu-latest
    -    if: github.ACTOR == 'dependabot[bot]'
    +    if: github.event.comment.user.login == 'dependabot[bot]'
         steps:
           - name: Test Step
    -        if: github.actor == 'dependabot[bot]'
    +        if: github.event.comment.user.login == 'dependabot[bot]'
             run: echo "hello"
    "#
    );

    Ok(())
}

#[test]
fn test_fix_pull_request_review_trigger() -> anyhow::Result<()> {
    let pr_review_workflow = r#"
name: Test PR Review
on: pull_request_review

jobs:
  test:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]'
    steps:
      - name: Test Step
        if: github.actor == 'dependabot[bot]'
        run: echo "hello"
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/bot-conditions.yml", pr_review_workflow);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/bot-conditions.yml", |workspace| {
            zizmor()
                .args(["--fix=all"])
                .input(workspace.path())
                .run()
        })?,
        @r#"
    @@ -7,6 +7,6 @@
         runs-on: ubuntu-latest
    -    if: github.actor == 'dependabot[bot]'
    +    if: github.event.review.user.login == 'dependabot[bot]'
         steps:
           - name: Test Step
    -        if: github.actor == 'dependabot[bot]'
    +        if: github.event.review.user.login == 'dependabot[bot]'
             run: echo "hello"
    "#
    );

    Ok(())
}

#[test]
fn test_fix_nontrivial_condition() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Test Workflow
on:
  pull_request_target:

jobs:
  test:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]' || github.actor == 'renovate[bot]'
    steps:
      - name: Test Step
        if: github.actor == 'dependabot[bot]' && contains(github.event.pull_request.title, 'chore')
        run: echo "hello"
"#;

    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/bot-conditions.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/bot-conditions.yml", |workspace| {
            zizmor()
                .args(["--fix=all"])
                .input(workspace.path())
                .run()
        })?,
        @r#"
    @@ -8,6 +8,6 @@
         runs-on: ubuntu-latest
    -    if: github.actor == 'dependabot[bot]' || github.actor == 'renovate[bot]'
    +    if: github.event.pull_request.user.login == 'dependabot[bot]' || github.actor == 'renovate[bot]'
         steps:
           - name: Test Step
    -        if: github.actor == 'dependabot[bot]' && contains(github.event.pull_request.title, 'chore')
    +        if: github.event.pull_request.user.login == 'dependabot[bot]' && contains(github.event.pull_request.title, 'chore')
             run: echo "hello"
    "#
    );

    Ok(())
}
