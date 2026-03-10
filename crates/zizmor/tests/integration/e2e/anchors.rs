//! End-to-end tests for YAML anchor handling in zizmor.

use anyhow::Result;

use crate::common::{input_under_test, zizmor};

/// Basic sanity test for anchor handling.
///
/// This test reveals duplicate findings, since zizmor doesn't
/// (yet) de-duplicate findings that arise from YAML anchors.
#[test]
fn test_basic() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "anchors/basic.yml"
            ))
            .run()?,
        @r#"
    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:13:31
       |
    12 |       - run: &run |
       |         --- this run block
    13 |           "doing a thing: ${{ github.event.issue.title }}"
       |                               ^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:13:31
       |
    13 |           "doing a thing: ${{ github.event.issue.title }}"
       |                               ^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
    14 |
    15 |       - run: *run
       |         --- this run block
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:18:49
       |
    18 |         run: &print-info echo "Building ref ${{ github.ref }}"
       |         --- this run block                      ^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:18:49
       |
    18 |         run: &print-info echo "Building ref ${{ github.ref }}"
       |                                                 ^^^^^^^^^^ may expand into attacker-controllable code
    ...
    21 |         run: *print-info
       |         --- this run block
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    5 findings (1 suppressed, 4 fixable): 0 informational, 0 low, 0 medium, 4 high
    "#
    );

    Ok(())
}

#[test]
fn test_scalar_cross_context() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("anchors/scalar-cross-context.yml"))
            .run()?,
        @r#"
    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:5:23
       |
     5 |   CMD: &cmd "echo ${{ github.event.issue.title }}"
       |                       ^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
    ...
    10 |       - run: *cmd
       |         --- this run block
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    3 findings (2 suppressed, 1 fixable): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_with_mapping_alias() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("anchors/with-mapping-alias.yml"))
            .run()?,
        @"
    warning[artipacked]: credential persistence through GitHub Actions artifacts
      --> @@INPUT@@:8:9
       |
     8 |         - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
       |  _________^
     9 | |         with: &checkout-opts
    10 | |           fetch-depth: 0
       | |________________________^ does not set persist-credentials: false
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    warning[artipacked]: credential persistence through GitHub Actions artifacts
      --> @@INPUT@@:11:9
       |
    11 |         - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
       |  _________^
    12 | |         with: *checkout-opts
       | |_____________________________^ does not set persist-credentials: false
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    4 findings (2 suppressed, 2 fixable): 0 informational, 0 low, 2 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_trigger_paths_anchor() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("anchors/trigger-paths-anchor.yml"))
            .run()?,
        @r#"
    error[dangerous-triggers]: use of fundamentally insecure workflow trigger
     --> @@INPUT@@:2:1
      |
    2 | / on:
    3 | |   pull_request_target:
    4 | |     paths-ignore: &ignore
    5 | |       - "docs/**"
    6 | |       - "**.md"
    7 | |   push:
    8 | |     paths-ignore: *ignore
      | |_________________________^ pull_request_target is almost always used insecurely
      |
      = note: audit confidence → Medium

    3 findings (2 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_trigger_block_alias() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("anchors/trigger-block-alias.yml"))
            .run()?,
        @r#"
    error[dangerous-triggers]: use of fundamentally insecure workflow trigger
     --> @@INPUT@@:2:1
      |
    2 | / on:
    3 | |   push: &trigger
    4 | |     branches: [main]
    5 | |     paths-ignore:
    6 | |       - "**.md"
    7 | |   pull_request_target: *trigger
      | |_______________________________^ pull_request_target is almost always used insecurely
      |
      = note: audit confidence → Medium

    3 findings (2 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_steps_list_alias() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("anchors/steps-list-alias.yml"))
            .run()?,
        @r#"
    error[template-injection]: code injection via template expansion
     --> @@INPUT@@:8:24
      |
    8 |       - run: echo "${{ github.event.issue.title }}"
      |         ---            ^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
      |         |
      |         this run block
      |
      = note: audit confidence → High
      = note: this finding has an auto-fix

    error[template-injection]: code injection via template expansion
     --> @@INPUT@@:8:24
      |
    8 |       - run: echo "${{ github.event.issue.title }}"
      |         ---            ^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
      |         |
      |         this run block
      |
      = note: audit confidence → High
      = note: this finding has an auto-fix

    6 findings (4 suppressed, 2 fixable): 0 informational, 0 low, 0 medium, 2 high
    "#
    );

    Ok(())
}

#[test]
fn test_cross_key_scalar() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("anchors/cross-key-scalar.yml"))
            .run()?,
        @r#"
    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:10:42
       |
     8 |       - uses: actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b # v7
       |         -------------------------------------------------------------------- action accepts arbitrary code
     9 |         with:
    10 |           script: &cmd "console.log('${{ github.event.issue.title }}')"
       |           ------ via this input          ^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:10:42
       |
    10 |           script: &cmd "console.log('${{ github.event.issue.title }}')"
       |                                          ^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
    11 |       - uses: actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b # v7
       |         -------------------------------------------------------------------- action accepts arbitrary code
    12 |         with:
    13 |           script: *cmd
       |           ------ via this input
       |
       = note: audit confidence → High

    4 findings (2 suppressed): 0 informational, 0 low, 0 medium, 2 high
    "#
    );

    Ok(())
}

#[test]
fn test_multi_scalar_anchors() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("anchors/multi-scalar-anchors.yml"))
            .run()?,
        @r#"
    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:11:37
       |
     8 |       - uses: tibdex/backport@9565281eda0731b1d20c4025c43339fb0a23812e # v2
       |         -------------------------------------------------------------- action accepts arbitrary code
    ...
    11 |           body_template: &body "${{ github.event.issue.body }}"
       |           -------------             ^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |           |
       |           via this input
       |
       = note: audit confidence → High

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:10:39
       |
     8 |       - uses: tibdex/backport@9565281eda0731b1d20c4025c43339fb0a23812e # v2
       |         -------------------------------------------------------------- action accepts arbitrary code
     9 |         with:
    10 |           title_template: &title "${{ github.event.issue.title }}"
       |           --------------              ^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |           |
       |           via this input
       |
       = note: audit confidence → High

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:11:37
       |
    11 |           body_template: &body "${{ github.event.issue.body }}"
       |                                     ^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
    12 |       - uses: tibdex/backport@9565281eda0731b1d20c4025c43339fb0a23812e # v2
       |         -------------------------------------------------------------- action accepts arbitrary code
    ...
    15 |           body_template: *body
       |           ------------- via this input
       |
       = note: audit confidence → High

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:10:39
       |
    10 |           title_template: &title "${{ github.event.issue.title }}"
       |                                       ^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
    11 |           body_template: &body "${{ github.event.issue.body }}"
    12 |       - uses: tibdex/backport@9565281eda0731b1d20c4025c43339fb0a23812e # v2
       |         -------------------------------------------------------------- action accepts arbitrary code
    13 |         with:
    14 |           title_template: *title
       |           -------------- via this input
       |
       = note: audit confidence → High

    6 findings (2 suppressed): 0 informational, 0 low, 0 medium, 4 high
    "#
    );

    Ok(())
}

#[test]
fn test_dummy_job_anchors() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("anchors/dummy-job-anchors.yml"))
            .run()?,
        @"
    warning[artipacked]: credential persistence through GitHub Actions artifacts
      --> @@INPUT@@:9:9
       |
     9 |         - &checkout
       |  _________^
    10 | |         uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2 
       | |_________________________________________________________________________________^ does not set persist-credentials: false
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    warning[artipacked]: credential persistence through GitHub Actions artifacts
      --> @@INPUT@@:14:9
       |
    14 |       - *checkout
       |         ^^^^^^^^^ does not set persist-credentials: false
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
     --> @@INPUT@@:6:13
      |
    6 |     if: ${{ false }}
      |             ^^^^^ can be replaced by its static evaluation
      |
      = note: audit confidence → High
      = note: this finding has an auto-fix

    7 findings (4 suppressed, 3 fixable): 0 informational, 1 low, 2 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_inputs_block_alias() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("anchors/inputs-block-alias.yml"))
            .run()?,
        @"No findings to report. Good job! (2 suppressed)"
    );

    Ok(())
}

#[test]
fn test_flow_mapping_step() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("anchors/flow-mapping-step.yml"))
            .run()?,
        @r#"
    warning[artipacked]: credential persistence through GitHub Actions artifacts
     --> @@INPUT@@:8:9
      |
    8 |       - &checkout { uses: "actions/checkout@v4" }
      |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ does not set persist-credentials: false
      |
      = note: audit confidence → Low
      = note: this finding has an auto-fix

    warning[artipacked]: credential persistence through GitHub Actions artifacts
     --> @@INPUT@@:9:9
      |
    9 |       - *checkout
      |         ^^^^^^^^^ does not set persist-credentials: false
      |
      = note: audit confidence → Low
      = note: this finding has an auto-fix

    error[unpinned-uses]: unpinned action reference
     --> @@INPUT@@:8:28
      |
    8 |       - &checkout { uses: "actions/checkout@v4" }
      |                            ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
      |
      = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
     --> @@INPUT@@:8:28
      |
    8 |       - &checkout { uses: "actions/checkout@v4" }
      |                            ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
      |
      = note: audit confidence → High

    6 findings (2 suppressed, 2 fixable): 0 informational, 0 low, 2 medium, 2 high
    "#
    );

    Ok(())
}
