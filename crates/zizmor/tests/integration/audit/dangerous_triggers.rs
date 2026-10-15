use zizmor_dev::{Zizmor, input_under_test};

/// A workflow that only contains one step (of `actions/labeler`)
/// should not produce a `dangerous-triggers` finding, even if
/// `pull_request_target` is used.
#[test]
fn test_actions_labeler_exception() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test(
                "dangerous-triggers/actions-labeler.yml"
            ))
            .run()?,
        @"No findings to report. Good job! (3 suppressed)"
    );

    Ok(())
}

#[test]
fn test_dangerous_trigger_bare_style() -> anyhow::Result<()> {
    insta::assert_snapshot!(
    Zizmor::cargo_bin()
        .input(input_under_test(
            "dangerous-triggers/dangerous-bare.yml"
        ))
        .run()?,
    @"
    error[dangerous-triggers]: use of fundamentally insecure workflow trigger
     --> @@INPUT@@:1:1
      |
    1 | on: pull_request_target
      | ^^^^^^^^^^^^^^^^^^^^^^^ pull_request_target is almost always used insecurely
      |
      = note: audit confidence → Medium

    4 findings (3 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

/// Ensures that we produce a reasonable diagnostic span when a dangerous
/// trigger is used in various YAML list styles.
#[test]
fn test_dangerous_trigger_list_styles() -> anyhow::Result<()> {
    insta::assert_snapshot!(
    Zizmor::cargo_bin()
        .input(input_under_test(
            "dangerous-triggers/dangerous-block-list.yml"
        ))
        .run()?,
    @"
    error[dangerous-triggers]: use of fundamentally insecure workflow trigger
     --> @@INPUT@@:3:5
      |
    3 |   - pull_request_target
      |     ^^^^^^^^^^^^^^^^^^^ pull_request_target is almost always used insecurely
      |
      = note: audit confidence → Medium

    4 findings (3 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "
    );

    insta::assert_snapshot!(
    Zizmor::cargo_bin()
        .input(input_under_test(
            "dangerous-triggers/dangerous-flow-list.yml"
        ))
        .run()?,
    @"
    error[dangerous-triggers]: use of fundamentally insecure workflow trigger
     --> @@INPUT@@:1:12
      |
    1 | on: [push, pull_request_target, workflow_call]
      |            ^^^^^^^^^^^^^^^^^^^ pull_request_target is almost always used insecurely
      |
      = note: audit confidence → Medium

    4 findings (3 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

#[test]
fn test_issue_comment() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test(
                "dangerous-triggers/issue-comment.yml"
            ))
            .run()?,
        @"
    error[dangerous-triggers]: use of fundamentally insecure workflow trigger
     --> @@INPUT@@:2:3
      |
    2 |   issue_comment:
      |   ^^^^^^^^^^^^^ issue_comment is almost always used insecurely
      |
      = note: audit confidence → Medium

    4 findings (3 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

/// Repro for #2448: a `# zizmor: ignore` comment at the top of the `on:` block
/// should be honored for `dangerous-triggers`.
///
/// See: <https://github.com/zizmorcore/zizmor/issues/2448>
#[test]
fn test_issue_2448() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test(
                "dangerous-triggers/issue-2448-repro.yml"
            ))
            .run()?,
        @"No findings to report. Good job! (1 ignored, 3 suppressed)"
    );

    Ok(())
}
