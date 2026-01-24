use crate::common::zizmor;

/// Test that `--gh-token` and `--github-token` conflict with each other.
#[test]
fn test_gh_token_github_token_conflict() -> anyhow::Result<()> {
    // As CLI flags.
    insta::assert_snapshot!(
        zizmor()
            .offline(true)
            .expects_failure(2)
            .args(["--gh-token=x", "--github-token=x"])
            .run()?,
        @r"
    error: the argument '--gh-token <GH_TOKEN>' cannot be used with '--github-token <GITHUB_TOKEN>'

    Usage: zizmor --gh-token <GH_TOKEN> --offline --no-progress --show-audit-urls <SHOW_AUDIT_URLS> <INPUTS>...

    For more information, try '--help'.
    "
    );

    // As environment variables.
    insta::assert_snapshot!(
        zizmor()
            .offline(true)
            .expects_failure(2)
            .setenv("GH_TOKEN", "x")
            .setenv("GITHUB_TOKEN", "x")
            .run()?,
        @r"
    error: the argument '--gh-token <GH_TOKEN>' cannot be used with '--github-token <GITHUB_TOKEN>'

    Usage: zizmor --offline --no-progress --show-audit-urls <SHOW_AUDIT_URLS> --gh-token <GH_TOKEN> <INPUTS>...

    For more information, try '--help'.
    "
    );

    Ok(())
}
