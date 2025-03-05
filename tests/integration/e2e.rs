//! End-to-end snapshot integration tests.

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
            .input("woodruffw/gha-hazmat@42064a9533f401a493c3599e56f144918f8eacfd")
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
