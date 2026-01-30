use crate::common::{input_under_test, zizmor};
use anyhow::Result;

#[test]
fn test_template_injection_static_matrix() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
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
       |                                    ^^^^^^^^^^^ may expand into attacker-controllable code
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
        zizmor()
            .input(input_under_test(
                "template-injection/template-injection-dynamic-matrix.yml"
            ))
            .args(["--persona=auditor"])
            .run()?,
        @r#"
    help[template-injection]: code injection via template expansion
      --> @@INPUT@@:26:36
       |
    25 |         run: |
       |         --- this run block
    26 |           echo "doing a thing: ${{ matrix.dynamic }}"
       |                                    ^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    warning[template-injection]: code injection via template expansion
      --> @@INPUT@@:26:36
       |
    25 |         run: |
       |         --- this run block
    26 |           echo "doing a thing: ${{ matrix.dynamic }}"
       |                                    ^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → Medium
       = note: this finding has an auto-fix

    2 findings (1 fixable): 0 informational, 1 low, 1 medium, 0 high
    "#
    );

    Ok(())
}

#[test]
fn test_issue_22_repro() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection/issue-22-repro.yml"))
            .run()?,
        @"No findings to report. Good job! (6 suppressed)"
    );

    Ok(())
}

#[test]
fn test_pr_317_repro() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection/pr-317-repro.yml"))
            .run()?,
        @r"
    warning[template-injection]: code injection via template expansion
      --> @@INPUT@@:28:20
       |
    27 |       - run: |
       |         --- this run block
    28 |           echo ${{ matrix.bar }}
       |                    ^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → Medium
       = note: this finding has an auto-fix

    3 findings (2 suppressed, 1 fixable): 0 informational, 0 low, 1 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_static_env() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection/static-env.yml"))
            .run()?,
        @r"
    help[template-injection]: code injection via template expansion
      --> @@INPUT@@:43:20
       |
    42 |         run: |
       |         --- this run block
    43 |           echo ${{ env.bar }}
       |                    ^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[template-injection]: code injection via template expansion
      --> @@INPUT@@:50:20
       |
    49 |         run: |
       |         --- this run block
    50 |           echo ${{ env.foo }}
       |                    ^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[template-injection]: code injection via template expansion
      --> @@INPUT@@:55:20
       |
    54 |         run: |
       |         --- this run block
    55 |           echo ${{ env.quux }}
       |                    ^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    13 findings (10 suppressed, 3 fixable): 0 informational, 3 low, 0 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_issue_339_repro() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
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

    3 findings (2 suppressed): 1 informational, 0 low, 0 medium, 0 high
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
        zizmor()
            .input(input_under_test("template-injection/issue-418-repro.yml"))
            .run()?,
        @"No findings to report. Good job! (3 suppressed)"
    );

    Ok(())
}

#[test]
fn test_pr_425_backstop_action() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "template-injection/pr-425-backstop/action.yml"
            ))
            .run()?,
        @r#"
    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:14:19
       |
    13 |       run: |
       |       --- this run block
    14 |         hello ${{ inputs.expandme }}
       |                   ^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:20:29
       |
    18 |       uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea
       |       -------------------------------------------------------------------- action accepts arbitrary code
    19 |       with:
    20 |         script: return "${{ inputs.expandme }}"
       |         ------              ^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |         |
       |         via this input
       |
       = note: audit confidence → High

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:26:27
       |
    23 |       uses: azure/cli@089eac9d8cc39f5d003e94f8b65efc51076c9cbd
       |       -------------------------------------------------------- action accepts arbitrary code
    24 |       with:
    25 |         inlineScript: |
       |         ------------ via this input
    26 |           echo "hello ${{ inputs.expandme }}"
       |                           ^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:31:56
       |
    29 |       uses: azure/powershell@whatever
       |       ------------------------------- action accepts arbitrary code
    30 |       with:
    31 |         inlineScript: Get-AzVM -ResourceGroupName "${{ inputs.expandme }}"
       |         ------------ via this input                    ^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:29:13
       |
    29 |       uses: azure/powershell@whatever
       |             ^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    9 findings (4 suppressed, 1 fixable): 0 informational, 0 low, 0 medium, 5 high
    "#
    );

    Ok(())
}

#[test]
fn test_false_positive_menagerie() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "template-injection/false-positive-menagerie.yml"
            ))
            .run()?,
        @"No findings to report. Good job! (7 suppressed)"
    );

    Ok(())
}

#[test]
fn test_issue_749_repro() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection/issue-749-repro.yml"))
            .run()?,
        @"No findings to report. Good job! (2 suppressed)"
    );

    Ok(())
}

#[test]
fn test_codeql_sinks() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection/codeql-sinks.yml"))
            .run()?,
        @r"
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

    3 findings (2 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

#[test]
fn test_pwsh_script() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
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

    3 findings (2 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_issue_883_repro_action() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "template-injection/issue-883-repro/action.yml"
            ))
            .run()?,
        @r#"
    help[template-injection]: code injection via template expansion
      --> @@INPUT@@:48:53
       |
    34 |       uses: jannekem/run-python-script-action@bbfca66c612a28f3eeca0ae40e1f810265e2ea68 # v1.7
       |       -------------------------------------------------------------------------------- action accepts arbitrary code
    ...
    39 |         script: |
       |         ------ via this input
    ...
    48 |           chango_instance = get_chango_instance(${{ inputs.pyproject-toml }})
       |                                                     ^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → Low

    help[template-injection]: code injection via template expansion
      --> @@INPUT@@:56:26
       |
    34 |       uses: jannekem/run-python-script-action@bbfca66c612a28f3eeca0ae40e1f810265e2ea68 # v1.7
       |       -------------------------------------------------------------------------------- action accepts arbitrary code
    ...
    39 |         script: |
       |         ------ via this input
    ...
    56 |               ${{ toJson(env.CUSTOM_OUTPUT) }}
       |                          ^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    help[template-injection]: code injection via template expansion
      --> @@INPUT@@:57:29
       |
    34 |       uses: jannekem/run-python-script-action@bbfca66c612a28f3eeca0ae40e1f810265e2ea68 # v1.7
       |       -------------------------------------------------------------------------------- action accepts arbitrary code
    ...
    39 |         script: |
       |         ------ via this input
    ...
    57 |               or ${{ toJson(env.DEFAULT_OUTPUT) }}
       |                             ^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    help[template-injection]: code injection via template expansion
      --> @@INPUT@@:60:19
       |
    34 |       uses: jannekem/run-python-script-action@bbfca66c612a28f3eeca0ae40e1f810265e2ea68 # v1.7
       |       -------------------------------------------------------------------------------- action accepts arbitrary code
    ...
    39 |         script: |
       |         ------ via this input
    ...
    60 |               ${{ inputs.data }}
       |                   ^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → Low

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:65:32
       |
    34 |       uses: jannekem/run-python-script-action@bbfca66c612a28f3eeca0ae40e1f810265e2ea68 # v1.7
       |       -------------------------------------------------------------------------------- action accepts arbitrary code
    ...
    39 |         script: |
       |         ------ via this input
    ...
    65 |               event=${{ toJson(github.event) }},
       |                                ^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    help[template-injection]: code injection via template expansion
       --> @@INPUT@@:110:33
        |
    104 |       uses: jannekem/run-python-script-action@bbfca66c612a28f3eeca0ae40e1f810265e2ea68 # v1.7
        |       -------------------------------------------------------------------------------- action accepts arbitrary code
    105 |       with:
    106 |         script: |
        |         ------ via this input
    ...
    110 |           file_path = Path("${{ env.CHANGE_NOTE_PATH }}")
        |                                 ^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
        |
        = note: audit confidence → High

    help[template-injection]: code injection via template expansion
       --> @@INPUT@@:111:34
        |
    104 |       uses: jannekem/run-python-script-action@bbfca66c612a28f3eeca0ae40e1f810265e2ea68 # v1.7
        |       -------------------------------------------------------------------------------- action accepts arbitrary code
    105 |       with:
    106 |         script: |
        |         ------ via this input
    ...
    111 |           encoded_content = "${{ env.CHANGE_NOTE_CONTENT }}"
        |                                  ^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
        |
        = note: audit confidence → High

    14 findings (7 suppressed): 0 informational, 6 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_multiline_expression_pedantic() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "template-injection/multiline-expression.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?,
        @r#"
    help[template-injection]: code injection via template expansion
      --> @@INPUT@@:18:13
       |
    16 |         - run: |
       |           --- this run block
    17 |             echo ${{
    18 | /             some.ctx
    19 | |             && foo.bar
    20 | |             || baz.qux
       | |______________________^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    info[template-injection]: code injection via template expansion
      --> @@INPUT@@:19:16
       |
    16 |       - run: |
       |         --- this run block
    ...
    19 |             && foo.bar
       |                ^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → Low

    info[template-injection]: code injection via template expansion
      --> @@INPUT@@:20:16
       |
    16 |       - run: |
       |         --- this run block
    ...
    20 |             || baz.qux
       |                ^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → Low

    help[template-injection]: code injection via template expansion
      --> @@INPUT@@:26:15
       |
    24 |           run: |
       |           --- this run block
    25 |             echo "TSAN_OPTIONS=log_path=${GITHUB_WORKSPACE}/tsan_log suppressions=${GITHUB_WORKSPACE}/Tools/tsan/suppressions${{
    26 | /               fromJSON(inputs.free-threading)
    27 | |               && '_free_threading'
    28 | |               || ''
       | |___________________^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    4 findings: 2 informational, 2 low, 0 medium, 0 high
    "#
    );

    Ok(())
}

#[test]
fn test_issue_988_repro_pedantic() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
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
       |                             ^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    help[template-injection]: code injection via template expansion
      --> @@INPUT@@:30:57
       |
    28 |         run: |
       |         --- this run block
    29 |           curl -X POST https://api.example.com -H "Content-type: application/json" \
    30 |             -d "{\"text\":\"ドドド: https://github.com/${{ github.repository }}\"}"
       |                                                            ^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    2 findings: 0 informational, 2 low, 0 medium, 0 high
    "#
    );

    Ok(())
}
