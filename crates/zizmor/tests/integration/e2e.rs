//! End-to-end integration tests.

use anyhow::Result;

use crate::common::{OutputMode, input_under_test, zizmor};

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn gha_hazmat() -> Result<()> {
    // Stability test against with online retrieval but no online audits.
    // Ensures that we consistently collect the same files in the default
    // configuration.
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .output(OutputMode::Both)
            .args(["--no-online-audits"])
            .input("woodruffw/gha-hazmat@33cd22cdd7823a5795768388aff977fe992b5aad")
            .run()?
    );
    Ok(())
}

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn issue_569() -> Result<()> {
    // Regression test for #569.
    // Ensures that we don't produce spurious warnings for unreachable
    // expressions (i.e. inside comments).
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .output(OutputMode::Both)
            .args(["--no-online-audits", "--collect=workflows-only"])
            .input("python/cpython@f963239ff1f986742d4c6bab2ab7b73f5a4047f6")
            .run()?
    );
    Ok(())
}

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn issue_726() -> Result<()> {
    // Regression test for #726.
    // See: https://github.com/zizmorcore/zizmor/issues/726
    // See: https://github.com/woodruffw-experiments/zizmor-bug-726
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .output(OutputMode::Both)
            .args(["--no-online-audits"])
            .input("woodruffw-experiments/zizmor-bug-726@a038d1a35")
            .run()?
    );
    Ok(())
}

#[test]
fn menagerie() -> Result<()> {
    // Respects .gitignore by default.
    insta::assert_snapshot!(
        zizmor()
            .output(OutputMode::Both)
            .input(input_under_test("e2e-menagerie"))
            .run()?
    );

    // Ignores .gitignore when --collect=all is specified.
    insta::assert_snapshot!(
        zizmor()
            .output(OutputMode::Both)
            .args(["--collect=all"])
            .input(input_under_test("e2e-menagerie"))
            .run()?
    );

    Ok(())
}

#[test]
fn color_control_basic() -> Result<()> {
    // No terminal, so no color by default.
    let no_color_default_output = zizmor()
        .output(OutputMode::Both)
        .input(input_under_test("e2e-menagerie"))
        .run()?;
    assert!(!no_color_default_output.contains("\x1b["));

    // Force color via --color=always.
    let forced_color_via_arg_output = zizmor()
        .output(OutputMode::Both)
        .args(["--color=always"])
        .input(input_under_test("e2e-menagerie"))
        .run()?;
    assert!(forced_color_via_arg_output.contains("\x1b["));

    // Force color via FORCE_COLOR.
    let forced_color_via_force_color_env_output = zizmor()
        .output(OutputMode::Both)
        .setenv("FORCE_COLOR", "1")
        .input(input_under_test("e2e-menagerie"))
        .run()?;
    assert!(forced_color_via_force_color_env_output.contains("\x1b["));

    // Force color via CLICOLOR_FORCE.
    let forced_color_via_cli_color_env_output = zizmor()
        .output(OutputMode::Both)
        .setenv("CLICOLOR_FORCE", "1")
        .input(input_under_test("e2e-menagerie"))
        .run()?;
    assert!(forced_color_via_cli_color_env_output.contains("\x1b["));

    // Forced color outputs should be equivalent.
    assert_eq!(
        forced_color_via_arg_output,
        forced_color_via_force_color_env_output
    );
    assert_eq!(
        forced_color_via_arg_output,
        forced_color_via_cli_color_env_output
    );

    Ok(())
}

#[cfg_attr(not(feature = "tty-tests"), ignore)]
#[test]
fn color_control_tty() -> Result<()> {
    // TTY enabled, so color by default.
    let color_default_output = zizmor()
        .output(OutputMode::Both)
        .unbuffer(true)
        .input(input_under_test("e2e-menagerie"))
        .run()?;
    assert!(color_default_output.contains("\x1b["));

    // Progress bar is also rendered, since zizmor thinks it's on a TTY.
    assert!(color_default_output.contains("collect_inputs{}"));

    // TTY, but color explicitly disabled via NO_COLOR.
    let no_color_via_no_color_env_output = zizmor()
        .output(OutputMode::Both)
        .unbuffer(true)
        .setenv("NO_COLOR", "1")
        .input(input_under_test("e2e-menagerie"))
        .run()?;
    assert!(!no_color_via_no_color_env_output.contains("\x1b["));

    // Progress bar is not rendered, since NO_COLOR is set.
    assert!(!no_color_via_no_color_env_output.contains("collect_inputs{}"));

    // TTY, but color explicitly disabled via `--color=never`.
    let no_color_via_arg_output = zizmor()
        .output(OutputMode::Both)
        .unbuffer(true)
        .args(["--color=never"])
        .input(input_under_test("e2e-menagerie"))
        .run()?;
    assert!(!no_color_via_arg_output.contains("\x1b["));

    // Progress bar is not rendered, since --color=never is set.
    assert!(!no_color_via_arg_output.contains("collect_inputs{}"));

    Ok(())
}

#[cfg_attr(not(feature = "tty-tests"), ignore)]
#[test]
fn progress_bar_tty() -> Result<()> {
    // TTY enabled, so progress bar is rendered by default.
    let progress_bar_default_output = zizmor()
        .output(OutputMode::Both)
        .unbuffer(true)
        .input(input_under_test("e2e-menagerie"))
        .run()?;
    assert!(progress_bar_default_output.contains("collect_inputs{}"));

    // TTY, but progress bar explicitly disabled via `--no-progress`.
    let no_progress_via_arg_output = zizmor()
        .output(OutputMode::Both)
        .unbuffer(true)
        .args(["--no-progress"])
        .input(input_under_test("e2e-menagerie"))
        .run()?;
    assert!(!no_progress_via_arg_output.contains("collect_inputs{}"));

    Ok(())
}

#[test]
fn issue_612_repro() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("issue-612-repro/action.yml"))
            .run()?
    );

    Ok(())
}

#[test]
fn invalid_config_file() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .config(if cfg!(windows) { "NUL" } else { "/dev/null" })
            .input(input_under_test("e2e-menagerie"))
            .run()?
    );

    Ok(())
}

#[test]
fn invalid_inputs() -> Result<()> {
    for workflow_tc in [
        "invalid-workflow",
        "invalid-workflow-2",
        "empty",
        "bad-yaml-1",
        "bad-yaml-2",
        "blank",
        "comment-only",
        "invalid-action-1/action",
        "invalid-action-2/action",
        "empty-action/action",
    ] {
        insta::assert_snapshot!(
            zizmor()
                .expects_failure(true)
                .input(input_under_test(&format!("invalid/{workflow_tc}.yml")))
                .args(["--strict-collection"])
                .run()?
        );
    }

    Ok(())
}
