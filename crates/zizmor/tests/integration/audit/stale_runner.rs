use crate::common::{input_under_test, zizmor};
use anyhow::Result;

#[test]
fn test_stale_runner_removed() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("stale-runner/stale-runner-removed.yml"))
            .run()?,
    );

    Ok(())
}

#[test]
fn test_stale_runner_stale() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("stale-runner/stale-runner-stale.yml"))
            .run()?,
    );

    Ok(())
}

#[test]
fn test_stale_runner_current() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "stale-runner/stale-runner-current.yml"
            ))
            .run()?,
        @"No findings to report. Good job! (8 suppressed)"
    );

    Ok(())
}

#[test]
fn test_stale_runner_matrix() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("stale-runner/stale-runner-matrix.yml"))
            .run()?,
    );

    Ok(())
}
