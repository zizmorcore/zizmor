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

/// Scalar value anchored in `env:` and aliased as `runs-on:`.
#[test]
fn test_scalar_cross_context() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("anchors/scalar-cross-context.yml"))
            .run()?,
        @"No findings to report. Good job! (2 suppressed)"
    );

    Ok(())
}

/// Anchor an entire `with:` mapping and alias it in another step.
#[test]
fn test_with_mapping_alias() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("anchors/with-mapping-alias.yml"))
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
     --> @@INPUT@@:8:15
      |
    8 |       - uses: actions/checkout@v6
      |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
      |
      = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:12:15
       |
    12 |       - uses: actions/checkout@v6
       |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    4 findings (2 suppressed): 0 informational, 0 low, 0 medium, 2 high
    "
    );

    Ok(())
}

/// Anchor `paths-ignore:` under `push:`, alias under `pull_request:`.
#[test]
fn test_trigger_paths_anchor() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("anchors/trigger-paths-anchor.yml"))
            .run()?,
        @"No findings to report. Good job! (2 suppressed)"
    );

    Ok(())
}

/// Anchor the entire `push:` trigger object and alias as `pull_request:`.
#[test]
fn test_trigger_block_alias() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("anchors/trigger-block-alias.yml"))
            .run()?,
        @"No findings to report. Good job! (2 suppressed)"
    );

    Ok(())
}

/// Anchor an entire `steps:` list and alias it in another job.
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

/// Anchor a scalar and alias it under a different key name.
#[test]
fn test_cross_key_scalar() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("anchors/cross-key-scalar.yml"))
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
     --> @@INPUT@@:8:15
      |
    8 |       - uses: peter-evans/create-pull-request@v8
      |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
      |
      = note: audit confidence → High

    4 findings (3 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

/// Multiple independent anchors in one step, each aliased later.
#[test]
fn test_multi_scalar_anchors() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("anchors/multi-scalar-anchors.yml"))
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
     --> @@INPUT@@:8:15
      |
    8 |       - uses: actions/cache@v4
      |               ^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
      |
      = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:13:15
       |
    13 |       - uses: actions/cache@v4
       |               ^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    4 findings (2 suppressed): 0 informational, 0 low, 0 medium, 2 high
    "
    );

    Ok(())
}

/// Dummy job with `if: false` defines anchors; real jobs use aliases.
/// Tests whether anchors in unreachable jobs resolve correctly.
#[test]
fn test_dummy_job_anchors() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("anchors/dummy-job-anchors.yml"))
            .run()?,
        @r#"
    warning[artipacked]: credential persistence through GitHub Actions artifacts
      --> @@INPUT@@:10:9
       |
    10 |         uses: actions/checkout@v4
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^ does not set persist-credentials: false
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    warning[artipacked]: credential persistence through GitHub Actions artifacts
      --> @@INPUT@@:10:9
       |
    10 |         uses: actions/checkout@v4
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^ does not set persist-credentials: false
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:12:24
       |
    12 |         run: echo "${{ github.event.issue.title }}"
       |         ---            ^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |         |
       |         this run block
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:12:24
       |
    12 |         run: echo "${{ github.event.issue.title }}"
       |         ---            ^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |         |
       |         this run block
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:10:15
       |
    10 |         uses: actions/checkout@v4
       |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:10:15
       |
    10 |         uses: actions/checkout@v4
       |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    help[obfuscation]: obfuscated usage of GitHub Actions features
     --> @@INPUT@@:6:13
      |
    6 |     if: ${{ false }}
      |             ^^^^^ can be replaced by its static evaluation
      |
      = note: audit confidence → High
      = note: this finding has an auto-fix

    11 findings (4 suppressed, 5 fixable): 0 informational, 1 low, 2 medium, 4 high
    "#
    );

    Ok(())
}

/// Anchor `inputs:` mapping under `workflow_call`, alias under `workflow_dispatch`.
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

/// Step defined in compact flow mapping syntax with an anchor.
#[test]
fn test_flow_mapping_step() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("anchors/flow-mapping-step.yml"))
            .run()?,
        @r#"
    warning[artipacked]: credential persistence through GitHub Actions artifacts
     --> @@INPUT@@:8:19
      |
    8 |       - &checkout { uses: "actions/checkout@v4" }
      |                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ does not set persist-credentials: false
      |
      = note: audit confidence → Low
      = note: this finding has an auto-fix

    warning[artipacked]: credential persistence through GitHub Actions artifacts
     --> @@INPUT@@:8:19
      |
    8 |       - &checkout { uses: "actions/checkout@v4" }
      |                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ does not set persist-credentials: false
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

/// Anchor a value containing a `${{ }}` expression, alias elsewhere.
#[test]
fn test_expression_anchor() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("anchors/expression-anchor.yml"))
            .expects_failure(1)
            .run()?,
        @"
    🌈 zizmor v@@VERSION@@
     WARN audit: zizmor: one or more inputs contains YAML anchors; you may encounter crashes or unpredictable behavior
     WARN audit: zizmor: for more information, see: https://docs.zizmor.sh/usage/#yaml-anchors
    fatal: no audit was performed
    'template-injection' audit failed on file://@@INPUT@@

    Caused by:
        0: error in 'template-injection' audit
        1: syntax node `flow_node` is missing child field `key`
    "
    );

    Ok(())
}
