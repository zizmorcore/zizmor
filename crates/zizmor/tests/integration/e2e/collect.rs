//! End-to-end integration tests for `--collect=<mode>`.

use anyhow::Result;
use insta::assert_snapshot;

use crate::common::{input_under_test, zizmor};

#[test]
fn test_fails_incompatible_modes() -> Result<()> {
    assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .args(["--collect=workflows,actions-only"])
            .input(input_under_test("neutral.yml"))
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    error: `workflows-only` and `actions-only` cannot be combined with other collection modes

    Usage: zizmor [OPTIONS] <INPUTS>...

    For more information, try '--help'.
    "
    );

    assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .args(["--collect=actions,workflows-only"])
            .input(input_under_test("neutral.yml"))
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    error: `workflows-only` and `actions-only` cannot be combined with other collection modes

    Usage: zizmor [OPTIONS] <INPUTS>...

    For more information, try '--help'.
    "
    );

    assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .args(["--collect=actions-only,workflows-only"])
            .input(input_under_test("neutral.yml"))
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    error: `workflows-only` and `actions-only` cannot be combined with other collection modes

    Usage: zizmor [OPTIONS] <INPUTS>...

    For more information, try '--help'.
    "
    );

    Ok(())
}

#[test]
fn test_warn_deprecated_modes() -> Result<()> {
    assert_snapshot!(
        zizmor()
            .args(["--collect=workflows-only"])
            .output(crate::common::OutputMode::Both)
            .input(input_under_test("neutral.yml"))
            .setenv("RUST_LOG", "warn")
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
     WARN zizmor: --collect=workflows-only is deprecated; use --collect=workflows instead
     WARN zizmor: future versions of zizmor will reject this mode
    No findings to report. Good job!
    ");

    assert_snapshot!(
        zizmor()
            .args(["--collect=actions-only"])
            .output(crate::common::OutputMode::Both)
            .input(input_under_test("neutral.yml"))
            .setenv("RUST_LOG", "warn")
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
     WARN zizmor: --collect=actions-only is deprecated; use --collect=actions instead
     WARN zizmor: future versions of zizmor will reject this mode
    No findings to report. Good job!
    ");

    Ok(())
}
