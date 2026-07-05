use crate::common::{input_under_test, zizmor};

/// A workflow that only contains one step (of `actions/labeler`)
/// should not produce a `dangerous-triggers` finding, even if
/// `pull_request_target` is used.
#[test]
fn test_actions_labeler_exception() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "dangerous-triggers/actions-labeler.yml"
            ))
            .run()?,
        @"No findings to report. Good job! (3 suppressed)"
    );

    Ok(())
}

#[test]
fn test_scalar_trigger_location() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("dangerous-triggers/scalar-trigger.yml"))
            .run()?,
        @r#"
    error[dangerous-triggers]: use of fundamentally insecure workflow trigger
     --> @@INPUT@@:2:1
      |
    2 | on: pull_request_target
      | ^^^^^^^^^^^^^^^^^^^^^^^ pull_request_target is almost always used insecurely
      |
      = note: audit confidence → Medium

    3 findings (2 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_flow_sequence_trigger_location() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "dangerous-triggers/flow-sequence-trigger.yml"
            ))
            .run()?,
        @r#"
    error[dangerous-triggers]: use of fundamentally insecure workflow trigger
     --> @@INPUT@@:2:12
      |
    2 | on: [push, pull_request_target]
      |            ^^^^^^^^^^^^^^^^^^^ pull_request_target is almost always used insecurely
      |
      = note: audit confidence → Medium

    3 findings (2 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_block_sequence_trigger_location() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "dangerous-triggers/block-sequence-trigger.yml"
            ))
            .run()?,
        @r#"
    error[dangerous-triggers]: use of fundamentally insecure workflow trigger
     --> @@INPUT@@:4:5
      |
    4 |   - pull_request_target
      |     ^^^^^^^^^^^^^^^^^^^ pull_request_target is almost always used insecurely
      |
      = note: audit confidence → Medium

    3 findings (2 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_mapping_trigger_location() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("dangerous-triggers/mapping-trigger.yml"))
            .run()?,
        @r#"
    error[dangerous-triggers]: use of fundamentally insecure workflow trigger
     --> @@INPUT@@:4:3
      |
    4 |   pull_request_target:
      |   ^^^^^^^^^^^^^^^^^^^^ pull_request_target is almost always used insecurely
      |
      = note: audit confidence → Medium

    3 findings (2 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_workflow_run_trigger_location() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "dangerous-triggers/workflow-run-trigger.yml"
            ))
            .run()?,
        @r#"
    error[dangerous-triggers]: use of fundamentally insecure workflow trigger
     --> @@INPUT@@:3:3
      |
    3 | /   workflow_run:
    4 | |     workflows: ["Build"]
    5 | |     types: [completed]
      | |______________________^ workflow_run is almost always used insecurely
      |
      = note: audit confidence → Medium

    3 findings (2 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}
