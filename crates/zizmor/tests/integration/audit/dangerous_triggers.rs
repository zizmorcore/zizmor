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
fn test_precise_trigger_location() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "dangerous-triggers/precise-trigger-location.yml"
            ))
            .run()?,
        @r#"
    error[dangerous-triggers]: use of fundamentally insecure workflow trigger
     --> @@INPUT@@:6:3
      |
    6 | /   pull_request_target:
    7 | |     paths-ignore:
    8 | |       - "docs/**"
      | |_________________^ pull_request_target is almost always used insecurely
      |
      = note: audit confidence → Medium

    2 findings (1 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}
