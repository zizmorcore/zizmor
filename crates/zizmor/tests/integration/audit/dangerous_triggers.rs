use crate::common::{input_under_test, zizmor};
use anyhow::Result;

#[test]
fn test_issue_comment_bare() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "dangerous-triggers/issue-comment-bare.yml",
            ))
            .run()?,
    );

    Ok(())
}

#[test]
fn test_issue_comment_events() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "dangerous-triggers/issue-comment-events.yml",
            ))
            .run()?,
    );

    Ok(())
}

#[test]
fn test_pull_request_target() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "dangerous-triggers/pull-request-target.yml",
            ))
            .run()?,
    );

    Ok(())
}

#[test]
fn test_workflow_run() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("dangerous-triggers/workflow-run.yml",))
            .run()?,
    );

    Ok(())
}

#[test]
fn test_multiple_dangerous() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "dangerous-triggers/multiple-dangerous.yml",
            ))
            .run()?,
    );

    Ok(())
}

#[test]
fn test_issue_comment_bare_list() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "dangerous-triggers/issue-comment-bare-list.yml",
            ))
            .run()?,
    );

    Ok(())
}

#[test]
fn test_safe() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("dangerous-triggers/safe.yml"))
            .run()?,
        @"No findings to report. Good job! (2 suppressed)"
    );

    Ok(())
}
