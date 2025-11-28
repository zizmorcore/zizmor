//! Snapshot integration tests.
//!
//! TODO: This file is too big; break it into multiple
//! modules, one per audit/conceptual group.

use crate::common::{input_under_test, zizmor};
use anyhow::Result;

#[test]
fn test_cant_retrieve_offline() -> Result<()> {
    // Fails because --offline prevents network access.
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .offline(true)
            .unsetenv("GH_TOKEN")
            .args(["pypa/sampleproject"])
            .run()?
    );

    Ok(())
}

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_cant_retrieve_no_gh_token() -> Result<()> {
    // Fails because GH_TOKEN is not set.
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .offline(false)
            .unsetenv("GH_TOKEN")
            .args(["pypa/sampleproject"])
            .run()?
    );

    Ok(())
}

#[test]
fn test_github_output() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(true)
            .input(input_under_test("several-vulnerabilities.yml"))
            .args(["--persona=auditor", "--format=github"])
            .run()?
    );

    Ok(())
}
