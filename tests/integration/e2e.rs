//! End-to-end snapshot integration tests.

use anyhow::Result;

use crate::common::{zizmor, OutputMode};

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn gha_hazmat() -> Result<()> {
    // Stability test against with online retrieval but no online audits.
    // Ensures that we consistently collect the same files in the default
    // configuration.
    insta::assert_snapshot!(zizmor()
        .offline(false)
        .output(OutputMode::Both)
        .args(["--no-online-audits"])
        .input("woodruffw/gha-hazmat@42064a9533f401a493c3599e56f144918f8eacfd")
        .run()?);
    Ok(())
}
