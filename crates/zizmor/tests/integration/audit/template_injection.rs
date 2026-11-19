use anyhow::Result;
use zizmor_dev::{WorkspaceBuilder, Zizmor, input_under_test};

#[test]
fn test_template_injection_static_matrix() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test(
                "template-injection/template-injection-static-matrix.yml"
            ))
            .args(["--persona=auditor"])
            .run()?,
        @r#"
    help[template-injection]: code injection via template expansion
      --> @@INPUT@@:25:36
       |
    24 |         run: |
       |         --- this run block
    25 |           echo "issue created: ${{ matrix.frob }}"
       |                                    ^^^^^^^^^^^ prefer passing this value through the environment
       |
       = note: audit confidence → High

    1 finding: 0 informational, 1 low, 0 medium, 0 high
    "#
    );

    Ok(())
}

#[test]
fn test_template_injection_dynamic_matrix() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test(
                "template-injection/template-injection-dynamic-matrix.yml"
            ))
            .args(["--persona=auditor"])
            .run()?,
        @r#"
    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:26:36
       |
    21 |         dynamic: ${{ github.event.client_payload.mystery_meat }}
       |         -------------------------------------------------------- matrix value defined here
    ...
    25 |         run: |
       |         --- this run block
    26 |           echo "doing a thing: ${{ matrix.dynamic }}"
       |                                    ^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    1 findings (1 unsafe fixes): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_issue_22_repro() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("template-injection/issue-22-repro.yml"))
            .run()?,
        @"No findings to report. Good job! (6 suppressed)"
    );

    Ok(())
}

#[test]
fn test_pr_317_repro() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("template-injection/pr-317-repro.yml"))
            .run()?,
        @"
    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:26:20
       |
    21 |           - bar: prefix-${{ github.event.pull_request.title }}
       |             -------------------------------------------------- matrix value defined here
    ...
    25 |       - run: |
       |         --- this run block
    26 |           echo ${{ matrix.bar }}
       |                    ^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    3 findings (2 suppressed, 1 unsafe fixes): 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

#[test]
fn test_static_env() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("template-injection/static-env.yml"))
            .run()?,
        @r#"
    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:31:21
       |
    25 |           STEP_TITLE: ${{ github.event.pull_request.title }}
       |           -------------------------------------------------- STEP_TITLE is defined here
    26 |         run: |
       |         --- this run block
    ...
    31 |           echo "${{ env.STEP_TITLE }}"
       |                     ^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:32:21
       |
    17 |       JOB_TITLE: ${{ github.event.pull_request.title }}
       |       ------------------------------------------------- JOB_TITLE is defined here
    ...
    26 |         run: |
       |         --- this run block
    ...
    32 |           echo "${{ env.JOB_TITLE }}"
       |                     ^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:33:21
       |
     7 |   WORKFLOW_TITLE: ${{ github.event.pull_request.title }}
       |   ------------------------------------------------------ WORKFLOW_TITLE is defined here
    ...
    26 |         run: |
       |         --- this run block
    ...
    33 |           echo "${{ env.WORKFLOW_TITLE }}"
       |                     ^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[template-injection]: code injection via template expansion
      --> @@INPUT@@:38:24
       |
     6 |   WORKFLOW_LITERAL: fixed
       |   -----------------------
       |   |
       |   an earlier step may overwrite WORKFLOW_LITERAL
       |   WORKFLOW_LITERAL is defined here
    ...
    38 |         run: echo "${{ env.WORKFLOW_LITERAL }}"
       |         ---            ^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |         |
       |         this run block
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    8 findings (4 suppressed, 4 unsafe fixes): 0 informational, 1 low, 0 medium, 3 high
    "#
    );

    Ok(())
}

#[test]
fn test_issue_339_repro() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("template-injection/issue-339-repro.yml"))
            .run()?,
        @r#"
    info[template-injection]: code injection via template expansion
      --> @@INPUT@@:30:28
       |
    29 |         run: |
       |         --- this run block
    30 |           echo "run-id=${{ fromJson(steps.runs.outputs.data).workflow_runs[0].id }}" >> "$GITHUB_OUTPUT"
       |                            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → Low

    2 findings (1 suppressed): 1 informational, 0 low, 0 medium, 0 high
    "#
    );

    Ok(())
}

/// Regression test for #418.
///
/// Fully static `${{ env.FOO }}` references should not be reported.
#[test]
fn test_issue_418_repro() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("template-injection/issue-418-repro.yml"))
            .run()?,
        @"No findings to report. Good job! (2 suppressed)"
    );

    Ok(())
}

#[test]
fn test_pr_425_backstop_action() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test(
                "template-injection/pr-425-backstop/action.yml"
            ))
            .run()?,
        @r#"
    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:16:19
       |
    13 |       run: |
       |       --- this run block
    ...
    16 |         hello ${{ inputs.expandme }}
       |                   ^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:22:29
       |
    20 |       uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea
       |       -------------------------------------------------------------------- action accepts arbitrary code
    21 |       with:
    22 |         script: return "${{ inputs.expandme }}"
       |         ------              ^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |         |
       |         via this input
       |
       = note: audit confidence → High

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:28:27
       |
    25 |       uses: azure/cli@089eac9d8cc39f5d003e94f8b65efc51076c9cbd
       |       -------------------------------------------------------- action accepts arbitrary code
    26 |       with:
    27 |         inlineScript: |
       |         ------------ via this input
    28 |           echo "hello ${{ inputs.expandme }}"
       |                           ^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:33:56
       |
    31 |       uses: azure/powershell@whatever
       |       ------------------------------- action accepts arbitrary code
    32 |       with:
    33 |         inlineScript: Get-AzVM -ResourceGroupName "${{ inputs.expandme }}"
       |         ------------ via this input                    ^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:31:13
       |
    31 |       uses: azure/powershell@whatever
       |             ^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    6 findings (1 suppressed, 1 unsafe fixes): 0 informational, 0 low, 0 medium, 5 high
    "#
    );

    Ok(())
}

#[test]
fn test_false_positive_menagerie() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test(
                "template-injection/false-positive-menagerie.yml"
            ))
            .run()?,
        @"No findings to report. Good job! (6 suppressed)"
    );

    Ok(())
}

#[test]
fn test_issue_749_repro() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("template-injection/issue-749-repro.yml"))
            .run()?,
        @"No findings to report. Good job! (2 suppressed)"
    );

    Ok(())
}

#[test]
fn test_codeql_sinks() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("template-injection/codeql-sinks.yml"))
            .run()?,
        @"
    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:17:20
       |
    15 |       - uses: mikefarah/yq@b534aa9ee5d38001fba3cd8fe254a037e4847b37 # v4.45.4
       |         ----------------------------------------------------------- action accepts arbitrary code
    16 |         with:
    17 |           cmd: ${{ github.event.pull_request.title }}
       |           ---      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |           |
       |           via this input
       |
       = note: audit confidence → High

    2 findings (1 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

#[test]
fn test_pwsh_script() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("template-injection/pwsh-script.yml"))
            .run()?,
        @r#"
    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:16:61
       |
    13 |       - uses: Amadevus/pwsh-script@97a8b211a5922816aa8a69ced41fa32f23477186 # v2.0.3
       |         ------------------------------------------------------------------- action accepts arbitrary code
    14 |         with:
    15 |           script: |
       |           ------ via this input
    16 |             Write-ActionDebug "Running for pull request ${{ github.event.pull_request.title }}"
       |                                                             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    2 findings (1 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_issue_883_repro_action() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test(
                "template-injection/issue-883-repro/action.yml"
            ))
            .run()?,
        @r#"
    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:56:53
       |
    42 |       uses: jannekem/run-python-script-action@bbfca66c612a28f3eeca0ae40e1f810265e2ea68 # v1.7
       |       -------------------------------------------------------------------------------- action accepts arbitrary code
    ...
    47 |         script: |
       |         ------ via this input
    ...
    56 |           chango_instance = get_chango_instance(${{ inputs.pyproject-toml }})
       |                                                     ^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:63:19
       |
    42 |       uses: jannekem/run-python-script-action@bbfca66c612a28f3eeca0ae40e1f810265e2ea68 # v1.7
       |       -------------------------------------------------------------------------------- action accepts arbitrary code
    43 |       env:
    44 |         CHANGE_DATA: ${{ inputs.data }}
       |         ------------------------------- CHANGE_DATA is defined here
    ...
    47 |         script: |
       |         ------ via this input
    ...
    63 |               ${{ toJson(env.CHANGE_DATA) }}
       |                   ^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:68:25
       |
    42 |       uses: jannekem/run-python-script-action@bbfca66c612a28f3eeca0ae40e1f810265e2ea68 # v1.7
       |       -------------------------------------------------------------------------------- action accepts arbitrary code
    ...
    47 |         script: |
       |         ------ via this input
    ...
    68 |               event=${{ toJson(github.event) }},
       |                         ^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    info[template-injection]: code injection via template expansion
       --> @@INPUT@@:113:33
        |
    105 |         CHANGE_NOTE_PATH: ${{ steps.create-chango-fragment.outputs.change_note_path }}
        |         ------------------------------------------------------------------------------ CHANGE_NOTE_PATH is defined here
    106 |         CHANGE_NOTE_CONTENT: ${{ steps.create-chango-fragment.outputs.change_note_content }}
    107 |       uses: jannekem/run-python-script-action@bbfca66c612a28f3eeca0ae40e1f810265e2ea68 # v1.7
        |       -------------------------------------------------------------------------------- action accepts arbitrary code
    108 |       with:
    109 |         script: |
        |         ------ via this input
    ...
    113 |           file_path = Path("${{ env.CHANGE_NOTE_PATH }}")
        |                                 ^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
        |
        = note: audit confidence → Low

    info[template-injection]: code injection via template expansion
       --> @@INPUT@@:114:34
        |
    106 |         CHANGE_NOTE_CONTENT: ${{ steps.create-chango-fragment.outputs.change_note_content }}
        |         ------------------------------------------------------------------------------------ CHANGE_NOTE_CONTENT is defined here
    107 |       uses: jannekem/run-python-script-action@bbfca66c612a28f3eeca0ae40e1f810265e2ea68 # v1.7
        |       -------------------------------------------------------------------------------- action accepts arbitrary code
    108 |       with:
    109 |         script: |
        |         ------ via this input
    ...
    114 |           encoded_content = "${{ env.CHANGE_NOTE_CONTENT }}"
        |                                  ^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
        |
        = note: audit confidence → Low

    6 findings (1 suppressed): 2 informational, 0 low, 0 medium, 3 high
    "#
    );

    Ok(())
}

#[test]
fn test_multiline_expression_pedantic() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test(
                "template-injection/multiline-expression.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?,
        @r#"
    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:24:13
       |
    22 |         - run: |
       |           --- this run block
    23 |             echo ${{
    24 | /             github.ref_type == 'branch'
    25 | |             && github.ref_name
    26 | |             || github.sha
       | |_________________________^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    help[template-injection]: code injection via template expansion
      --> @@INPUT@@:32:15
       |
    30 |           run: |
       |           --- this run block
    31 |             echo "TSAN_OPTIONS=log_path=${GITHUB_WORKSPACE}/tsan_log suppressions=${GITHUB_WORKSPACE}/Tools/tsan/suppressions${{
    32 | /               fromJSON(inputs.free-threading)
    33 | |               && '_free_threading'
    34 | |               || ''
       | |___________________^ prefer passing this value through the environment
       |
       = note: audit confidence → High

    2 findings: 0 informational, 1 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_issue_988_repro_pedantic() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("template-injection/issue-988-repro.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @r#"
    help[template-injection]: code injection via template expansion
      --> @@INPUT@@:19:29
       |
    16 |         run: |
       |         --- this run block
    ...
    19 |             event_name="${{ github.event_name }}"
       |                             ^^^^^^^^^^^^^^^^^ prefer passing this value through the environment
       |
       = note: audit confidence → High

    help[template-injection]: code injection via template expansion
      --> @@INPUT@@:30:57
       |
    28 |         run: |
       |         --- this run block
    29 |           curl -X POST https://api.example.com -H "Content-type: application/json" \
    30 |             -d "{\"text\":\"ドドド: https://github.com/${{ github.repository }}\"}"
       |                                                            ^^^^^^^^^^^^^^^^^ prefer passing this value through the environment
       |
       = note: audit confidence → High

    2 findings: 0 informational, 2 low, 0 medium, 0 high
    "#
    );

    Ok(())
}

/// Repro case for #1638: `github.triggering_actor` should not be considered an
/// injection risk in the default persona.
///
/// See: <https://github.com/zizmorcore/zizmor/issues/1638>
#[test]
fn test_issue_1638() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("template-injection/issue-1638-repro.yml"))
            .run()?,
        @"No findings to report. Good job! (1 suppressed)"
    );

    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("template-injection/issue-1638-repro.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @r#"
    help[template-injection]: code injection via template expansion
      --> @@INPUT@@:19:24
       |
    19 |         run: echo "${{ github.triggering_actor }}"
       |         ---            ^^^^^^^^^^^^^^^^^^^^^^^ prefer passing this value through the environment
       |         |
       |         this run block
       |
       = note: audit confidence → High

    1 finding: 0 informational, 1 low, 0 medium, 0 high
    "#
    );

    Ok(())
}

/// Repro case for #1664: expressions that span mulitiple lines within a folded YAML
/// block should have their subfeatures extracted correctly, without crashing.
///
/// See: <https://github.com/zizmorcore/zizmor/issues/1664>
#[test]
fn test_issue_1664() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("template-injection/issue-1664-repro.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @r#"
    help[template-injection]: code injection via template expansion
      --> @@INPUT@@:17:15
       |
    16 |           run: >
       |           --- this run block
    17 |             ${{ secrets.MY_SECRET
       |  _______________^
    18 | |           && 'true'
    19 | |           || 'echo "fallback"' }}
       | |______________________________^ prefer passing this value through the environment
       |
       = note: audit confidence → High

    help[concurrency-limits]: insufficient job-level concurrency limits
      --> @@INPUT@@:3:1
       |
     3 | / "on":
     4 | |   push:
     5 | |     branches:
     6 | |       - main
       | |____________^ workflow is missing concurrency setting
    ...
    12 |       name: Repro
       |       ----------- job affected by missing workflow concurrency
       |
       = note: audit confidence → High

    3 findings (1 suppressed): 0 informational, 2 low, 0 medium, 0 high
    "#
    );

    Ok(())
}

/// Repro case for #1802: `needs.*.result` expressions should not be considered injection risks in the default persona.
///
/// See: <https://github.com/zizmorcore/zizmor/issues/1802>
#[test]
fn test_issue_1802() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("template-injection/issue-1802-repro.yml"))
            .run()?,
        @"No findings to report. Good job! (3 suppressed)"
    );

    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("template-injection/issue-1802-repro.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @r#"
    help[template-injection]: code injection via template expansion
      --> @@INPUT@@:27:21
       |
    26 |       - run: |
       |         --- this run block
    27 |           test "${{ needs.test-matrix.result }}" = "success"
       |                     ^^^^^^^^^^^^^^^^^^^^^^^^ prefer passing this value through the environment
       |
       = note: audit confidence → High

    help[template-injection]: code injection via template expansion
      --> @@INPUT@@:28:21
       |
    26 |       - run: |
       |         --- this run block
    27 |           test "${{ needs.test-matrix.result }}" = "success"
    28 |           test "${{ needs['test-matrix']['result'] }}" = "success"
       |                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ prefer passing this value through the environment
       |
       = note: audit confidence → High

    help[template-injection]: code injection via template expansion
      --> @@INPUT@@:29:21
       |
    26 |       - run: |
       |         --- this run block
    ...
    29 |           test "${{ needs.TEST-MATRIX['result'] }}" = "success"
       |                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^ prefer passing this value through the environment
       |
       = note: audit confidence → High

    3 findings: 0 informational, 3 low, 0 medium, 0 high
    "#
    );

    Ok(())
}

/// Repro case for #1903: parenthesized compound expressions in context
/// position (e.g. `(a || b).foo`) should not crash zizmor.
///
/// See: <https://github.com/zizmorcore/zizmor/issues/1903>
#[test]
fn test_issue_1903() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("template-injection/issue-1903-repro.yml"))
            .run()?,
        @r#"
    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:23:21
       |
    21 |       - run: |
       |         --- this run block
    22 |           echo "${{ (github.event.pull_request || github.event.issue).number }}"
    23 |           echo "${{ (github.event.pull_request || github.event.issue).title }}"
       |                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    2 findings (1 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

/// Repro case for #2197: `steps.*.outcome` contexts should not be considered injection
/// risks in the default persona.
///
/// See: <https://github.com/zizmorcore/zizmor/issues/2197>
#[test]
fn test_issue_2197() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("template-injection/issue-2197-repro.yml"))
            .run()?,
        @"No findings to report. Good job! (1 suppressed)"
    );

    Ok(())
}

/// Repro case for #2490: contexts wrapped in `fromJSON(...)` should still be
/// considered for injection.
///
/// See: <https://github.com/zizmorcore/zizmor/issues/2490>
#[test]
fn test_issue_2490() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("template-injection/issue-2490-repro.yml"))
            .run()?,
        @r#"
    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:19:24
       |
    19 |       - run: echo "${{ fromJSON(toJSON(github.event.issue.title)) }}"
       |         ---            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |         |
       |         this run block
       |
       = note: audit confidence → High

    2 findings (1 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

/// Repro case for #2502: contexts in the value or default positions of
/// `case(...)` should still be considered for injection.
///
/// See: <https://github.com/zizmorcore/zizmor/issues/2502>
#[test]
fn test_issue_2502() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("template-injection/issue-2502-repro.yml"))
            .run()?,
        @r#"
    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:19:24
       |
    19 |       - run: echo "${{ case(github.event.action == 'opened', github.event.issue.title, 'x') }}"
       |         ---            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |         |
       |         this run block
       |
       = note: audit confidence → High

    2 findings (1 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_fix_github_ref_name() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Test Template Injection
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Vulnerable step
        run: echo "Branch is ${{ github.ref_name }}"
"#;

    let workspace = WorkspaceBuilder::default().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            Zizmor::cargo_bin()
                .args(["--fix=all"])
                .input(workspace.path())
                .run()
        })?,
        @r#"
    @@ -6,4 +6,4 @@
         runs-on: ubuntu-latest
         steps:
           - name: Vulnerable step
    -        run: echo "Branch is ${{ github.ref_name }}"
    +        run: echo "Branch is ${GITHUB_REF_NAME}"
    "#
    );

    Ok(())
}

#[test]
fn test_fix_github_actor() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Test Template Injection
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Vulnerable step
        run: |
          echo "Hello ${{ github.actor }}"
          echo "Processing user input"
"#;

    let workspace = WorkspaceBuilder::default().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            Zizmor::cargo_bin()
                .args(["--fix=all"])
                .input(workspace.path())
                .run()
        })?,
        @r#"
    @@ -7,5 +7,5 @@
         steps:
           - name: Vulnerable step
             run: |
    -          echo "Hello ${{ github.actor }}"
    +          echo "Hello ${GITHUB_ACTOR}"
               echo "Processing user input"
    "#
    );

    Ok(())
}

#[test]
fn test_fix_with_existing_env_name() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Test Template Injection
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Vulnerable step with existing env
        run: echo "Event name is ${{ github.event.head_commit.message }}"
        env:
          EXISTING_VAR: "existing_value"
"#;

    let workspace = WorkspaceBuilder::default().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            Zizmor::cargo_bin()
                .args(["--fix=all"])
                .input(workspace.path())
                .run()
        })?,
        @r#"
    @@ -6,6 +6,7 @@
         runs-on: ubuntu-latest
         steps:
           - name: Vulnerable step with existing env
    -        run: echo "Event name is ${{ github.event.head_commit.message }}"
    +        run: echo "Event name is ${GITHUB_EVENT_HEAD_COMMIT_MESSAGE}"
             env:
               EXISTING_VAR: "existing_value"
    +          GITHUB_EVENT_HEAD_COMMIT_MESSAGE: ${{ github.event.head_commit.message }}
    "#
    );

    Ok(())
}

#[test]
fn test_fix_multiple_expressions() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Test Multiple Template Injections
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Multiple vulnerable expressions
        # All expressions are replaced and environment variables are created in a single comprehensive fix
        run: |
          echo "User: ${{ github.actor }}"
          echo "Ref: ${{ github.ref_name }}"
          echo "Commit: ${{ github.event.head_commit.message }}"
"#;

    let workspace = WorkspaceBuilder::default().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            Zizmor::cargo_bin()
                .args(["--fix=all"])
                .input(workspace.path())
                .run()
        })?,
        @r#"
    @@ -8,6 +8,8 @@
           - name: Multiple vulnerable expressions
             # All expressions are replaced and environment variables are created in a single comprehensive fix
             run: |
    -          echo "User: ${{ github.actor }}"
    -          echo "Ref: ${{ github.ref_name }}"
    -          echo "Commit: ${{ github.event.head_commit.message }}"
    +          echo "User: ${GITHUB_ACTOR}"
    +          echo "Ref: ${GITHUB_REF_NAME}"
    +          echo "Commit: ${GITHUB_EVENT_HEAD_COMMIT_MESSAGE}"
    +        env:
    +          GITHUB_EVENT_HEAD_COMMIT_MESSAGE: ${{ github.event.head_commit.message }}
    "#
    );

    Ok(())
}

#[test]
fn test_fix_duplicate_expressions() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Test Duplicate Template Injections
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Duplicate vulnerable expressions
        run: |
          echo "User: ${{ github.actor }}"
          echo "User again: ${{ github.actor }}"
          echo "Ref: ${{ github.ref_name }}"
"#;

    let workspace = WorkspaceBuilder::default().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            Zizmor::cargo_bin()
                .args(["--fix=all"])
                .input(workspace.path())
                .run()
        })?,
        @r#"
    @@ -7,6 +7,6 @@
         steps:
           - name: Duplicate vulnerable expressions
             run: |
    -          echo "User: ${{ github.actor }}"
    -          echo "User again: ${{ github.actor }}"
    -          echo "Ref: ${{ github.ref_name }}"
    +          echo "User: ${GITHUB_ACTOR}"
    +          echo "User again: ${GITHUB_ACTOR}"
    +          echo "Ref: ${GITHUB_REF_NAME}"
    "#
    );

    Ok(())
}

#[test]
fn test_fix_equivalent_expressions() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Fix equivalent actor references
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Equivalent vulnerable expressions
        env:
          actor: ${{ github.actor }}
        run: |
          echo "User: ${{ github.actor }}"
          echo "User: ${{ github['ACTOR'] }}"
          echo "User: ${{ env.actor }}"
          echo "User: ${{ env['actor'] }}"
"#;

    let workspace = WorkspaceBuilder::default().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            Zizmor::cargo_bin()
                .output(zizmor_dev::OutputMode::Both)
                .args(["--fix=all", "--persona=pedantic"])
                .input(workspace.path())
                .run()
        })?,
        @r#"
    @@ -9,7 +9,7 @@
             env:
               actor: ${{ github.actor }}
             run: |
    -          echo "User: ${{ github.actor }}"
    -          echo "User: ${{ github['ACTOR'] }}"
    -          echo "User: ${{ env.actor }}"
    -          echo "User: ${{ env['actor'] }}"
    +          echo "User: ${GITHUB_ACTOR}"
    +          echo "User: ${GITHUB_ACTOR}"
    +          echo "User: ${actor}"
    +          echo "User: ${actor}"
    "#
    );

    Ok(())
}

/// Testcase for #1052.
///
/// See: <https://github.com/zizmorcore/zizmor/issues/1052>
#[test]
fn test_fix_no_env_overcorrection_issue_1052() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Fix a reference to a custom environment variable
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Read a custom environment variable
        env:
          THIS_IS_NOT_A_DEFAULT: octocat
        run: |
          echo "User: ${{ env.THIS_IS_NOT_A_DEFAULT }}"
"#;

    let workspace = WorkspaceBuilder::default().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            Zizmor::cargo_bin()
                .output(zizmor_dev::OutputMode::Both)
                .args(["--fix=all", "--persona=pedantic"])
                .input(workspace.path())
                .run()
        })?,
        @r#"
    @@ -9,4 +9,4 @@
             env:
               THIS_IS_NOT_A_DEFAULT: octocat
             run: |
    -          echo "User: ${{ env.THIS_IS_NOT_A_DEFAULT }}"
    +          echo "User: ${THIS_IS_NOT_A_DEFAULT}"
    "#
    );

    Ok(())
}

#[test]
fn test_fix_bash_shell_full_path() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Test Template Injection - Bash
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Vulnerable step with bash shell
        shell: /bin/bash
        run: echo "User is ${{ github.actor }}"
"#;

    let workspace = WorkspaceBuilder::default().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            Zizmor::cargo_bin()
                .output(zizmor_dev::OutputMode::Both)
                .args(["--fix=all", "--persona=pedantic"])
                .input(workspace.path())
                .run()
        })?,
        @r#"
    @@ -7,4 +7,4 @@
         steps:
           - name: Vulnerable step with bash shell
             shell: /bin/bash
    -        run: echo "User is ${{ github.actor }}"
    +        run: echo "User is ${GITHUB_ACTOR}"
    "#
    );

    Ok(())
}

#[test]
fn test_fix_cmd_shell() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Test Template Injection - CMD
on: push
jobs:
  test:
    runs-on: windows-latest
    steps:
      - name: Vulnerable step with cmd shell
        shell: cmd
        run: echo User is ${{ github.actor }}
"#;

    let workspace = WorkspaceBuilder::default().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            Zizmor::cargo_bin()
                .output(zizmor_dev::OutputMode::Both)
                .args(["--fix=all", "--persona=pedantic"])
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -7,4 +7,4 @@
         steps:
           - name: Vulnerable step with cmd shell
             shell: cmd
    -        run: echo User is ${{ github.actor }}
    +        run: echo User is %GITHUB_ACTOR%
    "
    );

    Ok(())
}

#[test]
fn test_fix_pwsd_shell() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Test Template Injection - PowerShell
on: push
jobs:
  test:
    runs-on: windows-latest
    steps:
      - name: Vulnerable step with pwsh shell
        shell: pwsh
        run: Write-Host "User is ${{ github.actor }}"
"#;

    let workspace = WorkspaceBuilder::default().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            Zizmor::cargo_bin()
                .output(zizmor_dev::OutputMode::Both)
                .args(["--fix=all", "--persona=pedantic"])
                .input(workspace.path())
                .run()
        })?,
        @r#"
    @@ -7,4 +7,4 @@
         steps:
           - name: Vulnerable step with pwsh shell
             shell: pwsh
    -        run: Write-Host "User is ${{ github.actor }}"
    +        run: Write-Host "User is $env:GITHUB_ACTOR"
    "#
    );

    Ok(())
}

#[test]
fn test_fix_default_shell_ubuntu() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Test Template Injection - Default Shell Ubuntu
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Vulnerable step with default shell
        run: echo "User is ${{ github.actor }}"
"#;

    let workspace = WorkspaceBuilder::default().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            Zizmor::cargo_bin()
                .output(zizmor_dev::OutputMode::Both)
                .args(["--fix=all", "--persona=pedantic"])
                .input(workspace.path())
                .run()
        })?,
        @r#"
    @@ -6,4 +6,4 @@
         runs-on: ubuntu-latest
         steps:
           - name: Vulnerable step with default shell
    -        run: echo "User is ${{ github.actor }}"
    +        run: echo "User is ${GITHUB_ACTOR}"
    "#
    );

    Ok(())
}

#[test]
fn test_fix_default_shell_windows() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Test Template Injection - Default Shell Windows
on: push
jobs:
  test:
    runs-on: windows-latest
    steps:
      - name: Vulnerable step with default shell
        run: Write-Host "User is ${{ github.actor }}"
"#;

    let workspace = WorkspaceBuilder::default().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            Zizmor::cargo_bin()
                .output(zizmor_dev::OutputMode::Both)
                .args(["--fix=all", "--persona=pedantic"])
                .input(workspace.path())
                .run()
        })?,
        @r#"
    @@ -6,4 +6,4 @@
         runs-on: windows-latest
         steps:
           - name: Vulnerable step with default shell
    -        run: Write-Host "User is ${{ github.actor }}"
    +        run: Write-Host "User is $env:GITHUB_ACTOR"
    "#
    );

    Ok(())
}

#[test]
fn test_fix_cmd_shell_with_custom_env() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Test Template Injection - CMD with Custom Env
on: pull_request
jobs:
  test:
    runs-on: windows-latest
    steps:
      - name: Vulnerable step with custom context
        shell: cmd
        run: echo PR title is ${{ github.event.pull_request.title }}
"#;

    let workspace = WorkspaceBuilder::default().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            Zizmor::cargo_bin()
                .output(zizmor_dev::OutputMode::Both)
                .args(["--fix=all", "--persona=pedantic"])
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -7,4 +7,6 @@
         steps:
           - name: Vulnerable step with custom context
             shell: cmd
    -        run: echo PR title is ${{ github.event.pull_request.title }}
    +        run: echo PR title is %GITHUB_EVENT_PULL_REQUEST_TITLE%
    +        env:
    +          GITHUB_EVENT_PULL_REQUEST_TITLE: ${{ github.event.pull_request.title }}
    "
    );

    Ok(())
}

/// Reproducer for #1580.
///
/// See: <https://github.com/zizmorcore/zizmor/issues/1580>
#[test]
fn test_fix_unicode_in_script() -> anyhow::Result<()> {
    let workflow_content = r#"
name: Repro issue #1580
on:
  issue_comment:
    types: [created]
jobs:
  repro:
    runs-on: ubuntu-latest
    steps:
      - shell: bash
        run: |
          echo "✓ ${{ github.event.comment.body }}"

      - shell: bash
        run: echo ok
"#;

    let workspace = WorkspaceBuilder::default().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/test.yml", workflow_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/workflows/test.yml", |workspace| {
            Zizmor::cargo_bin()
                .output(zizmor_dev::OutputMode::Both)
                .args(["--fix=all", "--persona=pedantic"])
                .input(workspace.path())
                .run()
        })?,
        @r#"
    @@ -9,7 +9,9 @@
         steps:
           - shell: bash
             run: |
    -          echo "✓ ${{ github.event.comment.body }}"
    +          echo "✓ ${GITHUB_EVENT_COMMENT_BODY}"
    +        env:
    +          GITHUB_EVENT_COMMENT_BODY: ${{ github.event.comment.body }}
     ⏎
           - shell: bash
             run: echo ok
    "#
    );

    Ok(())
}

#[test]
fn test_workflow_input_types() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("template-injection/input-caps.yml"))
            .run()?,
        @r#"
    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:25:24
       |
     5 |       test:
       |       ---- input test declared here
    ...
    25 |         run: echo "${{ inputs.test == 'true' && github.ref_name || '' }}"
       |         ---            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |         |
       |         this run block
       |
       = note: audit confidence → High

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:28:24
       |
    28 |         run: echo "${{ format('{0}{1}', inputs.called, inputs.manual) == '' && github.ref_name || '' }}"
       |         ---            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |         |
       |         this run block
       |
       = note: audit confidence → High

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:42:24
       |
     5 |       test:
       |       ---- input test declared here
    ...
    11 |       test:
       |       ---- input test declared here
    ...
    41 |           VALUE: ${{ inputs[vars.INPUT_NAME] }}
       |           ------------------------------------- VALUE is defined here
    42 |         run: echo "${{ env[vars.ENV_NAME] }}"
       |         ---            ^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |         |
       |         this run block
       |
       = note: audit confidence → High

    10 findings (7 suppressed): 0 informational, 0 low, 0 medium, 3 high
    "#
    );
    Ok(())
}

#[test]
fn test_interpreted_indirections() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("template-injection/interpreted-indirections.yml"))
            .run()?,
        @r#"
    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:18:21
       |
     8 |       TITLE: ${{ github.event.issue.title }}
       |       -------------------------------------- TITLE is defined here
    ...
    17 |       - run: |
       |         --- this run block
    18 |           echo "${{ env.TITLE }}"
       |                     ^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:19:21
       |
    12 |         command: [fixed, '${{ github.event.issue.title }}']
       |                          --------------------------------- matrix value defined here
    ...
    17 |       - run: |
       |         --- this run block
    18 |           echo "${{ env.TITLE }}"
    19 |           echo "${{ format('{0}', matrix.command) }}"
       |                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:20:21
       |
    14 |           - indirect: "literal '{' ${{ github.event.action == 'opened' && 'fixed' || github.event.issue.title }} '}'"
       |             --------------------------------------------------------------------------------------------------------- matrix value defined here
    ...
    17 |       - run: |
       |         --- this run block
    ...
    20 |           echo "${{ matrix.indirect }}"
       |                     ^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:23:21
       |
    17 |       - run: |
       |         --- this run block
    ...
    23 |           echo "${{ github.event.action == 'opened' && fromJSON('invalid') || github.event.issue.title }}"
       |                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:25:21
       |
    12 |         command: [fixed, '${{ github.event.issue.title }}']
       |                   -----  --------------------------------- matrix value defined here
       |                   |
       |                   matrix value defined here
    13 |         include:
    14 |           - indirect: "literal '{' ${{ github.event.action == 'opened' && 'fixed' || github.event.issue.title }} '}'"
       |             --------------------------------------------------------------------------------------------------------- matrix value defined here
    15 |             pieces: ["${{ case(github.event.action == 'opened', 'a', 'b') }}", c]
       |                      --------------------------------------------------------  - matrix value defined here
       |                      |
       |                      matrix value defined here
    16 |     steps:
    17 |       - run: |
       |         --- this run block
    ...
    25 |           echo "${{ matrix[github.event.action] || github.event.issue.title }}"
       |                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:26:21
       |
    17 |       - run: |
       |         --- this run block
    ...
    26 |           echo "${{ matrix['*'] || github.event.issue.title }}"
       |                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:27:21
       |
    15 |             pieces: ["${{ case(github.event.action == 'opened', 'a', 'b') }}", c]
       |                      --------------------------------------------------------  - matrix value defined here
       |                      |
       |                      matrix value defined here
    16 |     steps:
    17 |       - run: |
       |         --- this run block
    ...
    27 |           echo "${{ join(matrix.pieces, ',') == 'a,c' && github.event.issue.title || 'fixed' }}"
       |                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:43:21
       |
    34 |         os: [ubuntu, windows]
       |                      ------- matrix value defined here
    ...
    38 |           - {os: windows, label: included}
       |             ------------------------------
       |             |
       |             matrix value defined here
       |             matrix value defined here
    ...
    41 |       - run: |
       |         --- this run block
    42 |           echo "${{ matrix.os == 'ubuntu' && matrix.node == 18 && github.event.issue.title || 'fixed' }}"
    43 |           echo "${{ matrix.label && github.event.issue.title || 'fixed' }}"
       |                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:44:21
       |
    39 |           - {os: extra, node: 99}
       |             ---------------------
       |             |
       |             matrix value defined here
       |             matrix value defined here
    40 |     steps:
    41 |       - run: |
       |         --- this run block
    ...
    44 |           echo "${{ matrix.os == 'extra' && matrix.node == 99 && github.event.issue.title || 'fixed' }}"
       |                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:64:24
       |
    59 |         os: ["${{ vars.BUILD_OS }}"]
       |              ---------------------- matrix value defined here
    60 |         version: [stable]
       |                   ------ matrix value defined here
    61 |         include:
    62 |           - {os: linux, label: included}
       |             ----------------------------
       |             |
       |             matrix value defined here
       |             matrix value defined here
    63 |     steps:
    64 |       - run: echo "${{ matrix.version && matrix.label && github.event.issue.title }}"
       |         ---            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |         |
       |         this run block
       |
       = note: audit confidence → High

    22 findings (12 suppressed, 2 unsafe fixes): 0 informational, 0 low, 0 medium, 10 high
    "#
    );

    Ok(())
}

#[test]
fn test_output_aliases() -> Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("template-injection/output-aliases.yml"))
            .run()?,
        @r#"
    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:26:24
       |
     8 |       title: ${{ github.event.issue.title }}
       |       -------------------------------------- this job declares output title
    ...
    16 |       title: ${{ needs.producer.outputs.title }}
       |       ------------------------------------------ this job declares output title
    ...
    24 |       TITLE: ${{ needs.middle.outputs.title }}
       |       ---------------------------------------- TITLE is defined here
    25 |     steps:
    26 |       - run: echo "${{ env.TITLE }}"
       |         ---            ^^^^^^^^^ may expand into attacker-controllable code
       |         |
       |         this run block
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:48:21
       |
    31 |         os: [linux, mac]
       |              -----  --- matrix value defined here
       |              |
       |              matrix value defined here
    ...
    36 |       linux: ${{ matrix.os == 'linux' && 'built' || '' }}
       |       --------------------------------------------------- this job declares output linux
    37 |       mac: ${{ matrix.os == 'mac' && 'built' || '' }}
       |       ----------------------------------------------- this job declares output mac
    ...
    47 |       - run: |
       |         --- this run block
    48 |           echo "${{ needs.builds.outputs.linux && needs.builds.outputs.mac && github.event.issue.title }}"
       |                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:50:21
       |
    31 |         os: [linux, mac]
       |              -----  --- matrix value defined here
       |              |
       |              matrix value defined here
    ...
    34 |       enabled: ${{ matrix.os == 'other' }}
       |       ------------------------------------ this job declares output enabled
    ...
    44 |       ENABLED: ${{ needs.builds.outputs.enabled == 'true' }}
       |       ------------------------------------------------------ ENABLED is defined here
    ...
    47 |       - run: |
       |         --- this run block
    ...
    50 |           echo "${{ env.ENABLED && needs.builds.outputs.enabled && github.event.issue.title }}"
       |                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    11 findings (8 suppressed, 1 unsafe fixes): 0 informational, 0 low, 0 medium, 3 high
    "#
    );

    Ok(())
}
