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
