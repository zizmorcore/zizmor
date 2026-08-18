#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use crate::models::repository_uses_pattern::RepositoryUsesPattern;
    use anyhow::anyhow;
    use github_actions_models::common::Uses;
    use url::Url;

    use crate::models::repo_ref::RepoRef;

    #[test]
    fn test_repositoryusespattern_matches_repo_ref() -> anyhow::Result<()> {
        for (url, git_ref, pattern, matches) in [
            // OK: case insensitive
            (
                Url::parse("https://github.com/actions/checkout")?,
                "v3",
                "Actions/Checkout@v3",
                true,
            ),
            // NOT OK: domain is not slug-able
            (
                Url::parse("https://notgithub.com/actions/checkout")?,
                "v3",
                "Actions/Checkout@v3",
                false,
            ),
            // NOT OK: subpath patterns never match
            (
                Url::parse("https://github.com/actions/checkout")?,
                "v3",
                "Actions/Checkout/foo@v3",
                false,
            ),
        ] {
            let repo_ref = RepoRef::from_url(&url, git_ref);
            let pattern = RepositoryUsesPattern::from_str(pattern)?;

            assert_eq!(pattern.matches(&repo_ref), matches);
        }

        Ok(())
    }

    #[test]
    fn test_repositoryusespattern_matches_uses() -> anyhow::Result<()> {
        for (uses, pattern, matches) in [
            // OK: case-insensitive, except subpath and tag
            ("actions/checkout@v3", "Actions/Checkout@v3", true),
            ("actions/checkout/foo@v3", "Actions/Checkout/foo", true),
            ("actions/checkout@v3", "actions/checkout@V3", false),
            // NOT OK: owner/repo do not match
            ("actions/checkout@v3", "foo/checkout", false),
            ("actions/checkout@v3", "actions/bar", false),
            // NOT OK: subpath does not match
            ("actions/checkout/foo@v3", "actions/checkout@v3", false),
            // NOT OK: template is more specific than `uses:`
            ("actions/checkout@v3", "actions/checkout/foo@v3", false),
            // owner/repo/subpath matches regardless of ref and casing
            // but only when the subpath matches.
            // the subpath must share the same case but might not be
            // normalized
            ("actions/checkout/foo@v3", "actions/checkout/foo", true),
            ("ACTIONS/CHECKOUT/foo@v3", "actions/checkout/foo", true),
            // TODO: See comment in `RepositoryUsesPattern::matches`
            // ("ACTIONS/CHECKOUT/foo@v3", "actions/checkout/foo/", true),
            // ("ACTIONS/CHECKOUT/foo@v3", "actions/checkout/foo//", true),
            // ("ACTIONS/CHECKOUT//foo////@v3", "actions/checkout/foo", true),
            // owner/repo matches regardless of ref and casing
            // but does not match subpaths
            ("ACTIONS/CHECKOUT@v3", "actions/checkout", true),
            ("actions/checkout@v3", "actions/checkout", true),
            ("actions/checkout/foo@v3", "actions/checkout", false),
            ("actions/somethingelse@v3", "actions/checkout", false),
            ("whatever/checkout@v3", "actions/checkout", false),
            // owner/repo/* matches regardless of ref and casing
            // including subpaths
            // but does not match when owner diverges
            ("ACTIONS/CHECKOUT@v3", "actions/checkout/*", true),
            ("actions/checkout@v3", "actions/checkout/*", true),
            ("actions/checkout/foo@v3", "actions/checkout/*", true),
            ("actions/checkout/foo/bar@v3", "actions/checkout/*", true),
            ("someoneelse/checkout@v3", "actions/checkout/*", false),
            // owner/* matches regardless of ref, casing, and subpath
            // but rejects when owner diverges
            ("ACTIONS/CHECKOUT@v3", "actions/*", true),
            ("actions/checkout@v3", "actions/*", true),
            ("actions/checkout/foo@v3", "actions/*", true),
            ("someoneelse/checkout@v3", "actions/*", false),
            // * matches everything
            ("actions/checkout@v3", "*", true),
            ("actions/checkout/foo@v3", "*", true),
            ("whatever/checkout@v3", "*", true),
            // exact matches
            ("actions/checkout@v3", "actions/checkout@v3", true),
            ("actions/checkout/foo@v3", "actions/checkout/foo@v3", true),
            ("actions/checkout/foo@v1", "actions/checkout/foo@v3", false),
        ] {
            let Ok(Uses::Repository(uses)) = Uses::parse(uses) else {
                return Err(anyhow!("invalid uses: {uses}"));
            };

            let pattern = RepositoryUsesPattern::from_str(pattern)?;

            assert_eq!(
                pattern.matches(&RepoRef::from(&uses)),
                matches,
                "pattern: {pattern:?}, uses: {uses:?}, matches: {matches}"
            );
        }

        Ok(())
    }
}
