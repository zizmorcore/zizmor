//! Extension traits for the `Uses` APIs.

use std::{str::FromStr, sync::LazyLock};

use github_actions_models::common::{RepositoryUses, Uses};
use regex::Regex;
use serde::Deserialize;

/// Matches all variants of [`RepositoryUsesPattern`] except `*`.
///
/// TODO: Replace this with a real parser; this is ridiculous.
static REPOSITORY_USES_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?xmi)                   # verbose, multi-line mode, case-insensitive
        ^                           # start of line
        ([\w-]+)                    # (1) owner
        /                           # /
        ([\w\.-]+|\*)               # (2) repo or *
        (?:                         # non-capturing group for optional subpath
          /                         # /
          (                         # (3) subpath
            [[[:graph:]]&&[^@\*]]+  # any non-space, non-@, non-* characters
            |                       # OR
            \*                      # *
          )                         # end of (3) subpath
        )?                          # end of non-capturing group for optional subpath
        (?:                         # non-capturing group for optional git ref
          @                         # @
          ([[[:graph:]]&&[^\*]]+)   # (4) git ref (any non-space, non-* characters)
        )?                          # end of non-capturing group for optional git ref
        $                           # end of line
        "#,
    )
    .unwrap()
});

/// Represents a pattern for matching repository `uses` references.
/// These patterns are ordered by specificity; more specific patterns
/// should be listed first.
#[derive(Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub(crate) enum RepositoryUsesPattern {
    /// Matches exactly `owner/repo/subpath@ref`.
    ExactWithRef {
        owner: String,
        repo: String,
        subpath: Option<String>,
        git_ref: String,
    },
    /// Matches exactly `owner/repo/subpath`.
    ExactPath {
        owner: String,
        repo: String,
        subpath: String,
    },
    /// Matches exactly `owner/repo`.
    ExactRepo { owner: String, repo: String },
    /// Matches `owner/repo/*` (i.e. any subpath under the given repo, including
    /// the empty subpath).
    InRepo { owner: String, repo: String },
    /// Matches `owner/*` (i.e. any repo under the given owner).
    InOwner(String),
    /// Matches any `owner/repo`.
    Any,
}

impl RepositoryUsesPattern {
    pub(crate) fn matches(&self, uses: &RepositoryUses) -> bool {
        match self {
            RepositoryUsesPattern::ExactWithRef {
                owner,
                repo,
                subpath,
                git_ref,
            } => {
                uses.owner.eq_ignore_ascii_case(owner)
                    && uses.repo.eq_ignore_ascii_case(repo)
                    && uses.subpath == *subpath
                    && uses.git_ref.as_deref().is_some_and(|s| s == git_ref)
            }
            RepositoryUsesPattern::ExactPath {
                owner,
                repo,
                subpath,
            } => {
                // TODO: Normalize the subpath here.
                // This is nontrivial, since we need to normalize
                // both leading slashes *and* arbitrary ./.. components.
                // Utf8Path gets us part of the way there, but is
                // platform dependent (i.e. will do the wrong thing
                // if the platform separator is not /).
                uses.owner.eq_ignore_ascii_case(owner)
                    && uses.repo.eq_ignore_ascii_case(repo)
                    && uses.subpath.as_deref().is_some_and(|s| s == subpath)
            }
            RepositoryUsesPattern::ExactRepo { owner, repo } => {
                uses.owner.eq_ignore_ascii_case(owner)
                    && uses.repo.eq_ignore_ascii_case(repo)
                    && uses.subpath.is_none()
            }
            RepositoryUsesPattern::InRepo { owner, repo } => {
                uses.owner.eq_ignore_ascii_case(owner) && uses.repo.eq_ignore_ascii_case(repo)
            }
            RepositoryUsesPattern::InOwner(owner) => uses.owner.eq_ignore_ascii_case(owner),
            RepositoryUsesPattern::Any => true,
        }
    }
}

impl FromStr for RepositoryUsesPattern {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "*" {
            return Ok(RepositoryUsesPattern::Any);
        }

        let caps = REPOSITORY_USES_PATTERN
            .captures(s)
            .ok_or_else(|| anyhow::anyhow!("invalid pattern: {s}"))?;

        let owner = &caps[1];
        let repo = &caps[2];
        let subpath = caps.get(3).map(|m| m.as_str());
        let git_ref = caps.get(4).map(|m| m.as_str());

        match (owner, repo, subpath, git_ref) {
            (owner, "*", None, None) => Ok(RepositoryUsesPattern::InOwner(owner.into())),
            (owner, repo, None, None) => Ok(RepositoryUsesPattern::ExactRepo {
                owner: owner.into(),
                repo: repo.into(),
            }),
            (_, "*", Some(_), _) => Err(anyhow::anyhow!("invalid pattern: {s}")),
            (owner, repo, Some("*"), None) => Ok(RepositoryUsesPattern::InRepo {
                owner: owner.into(),
                repo: repo.into(),
            }),
            (owner, repo, Some(subpath), None) => Ok(RepositoryUsesPattern::ExactPath {
                owner: owner.into(),
                repo: repo.into(),
                subpath: subpath.into(),
            }),
            (_, _, Some("*"), Some(_)) => Err(anyhow::anyhow!("invalid pattern: {s}")),
            (owner, repo, subpath, Some(git_ref)) => Ok(RepositoryUsesPattern::ExactWithRef {
                owner: owner.into(),
                repo: repo.into(),
                subpath: subpath.map(|s| s.into()),
                git_ref: git_ref.into(),
            }),
        }
    }
}

impl<'de> Deserialize<'de> for RepositoryUsesPattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        RepositoryUsesPattern::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// Useful APIs for interacting with `uses: owner/repo` clauses.
pub(crate) trait RepositoryUsesExt {
    /// Returns whether this `uses:` clause matches the given pattern.
    ///
    /// This uses [`RepositoryUsesPattern`] under the hood, and follows the
    /// same matching rules.
    fn matches(&self, pattern: &str) -> bool;

    /// Returns whether this `uses:` clause has a `git` ref and, if so,
    /// whether that ref is a commit ref.
    ///
    /// For example, `foo/bar@baz` returns false while `foo/bar@1234...`
    /// returns true.
    fn ref_is_commit(&self) -> bool;

    /// Returns the `git` ref for this `uses:`, if present.
    fn commit_ref(&self) -> Option<&str>;

    /// Returns the *symbolic* `git` ref for this `uses`, if present.
    ///
    /// Commit refs (i.e. SHA refs) are not returned.
    fn symbolic_ref(&self) -> Option<&str>;
}

impl RepositoryUsesExt for RepositoryUses {
    fn matches(&self, template: &str) -> bool {
        let Ok(pat) = template.parse::<RepositoryUsesPattern>() else {
            return false;
        };

        pat.matches(self)
    }

    fn ref_is_commit(&self) -> bool {
        match &self.git_ref {
            Some(git_ref) => git_ref.len() == 40 && git_ref.chars().all(|c| c.is_ascii_hexdigit()),
            None => false,
        }
    }

    fn commit_ref(&self) -> Option<&str> {
        match &self.git_ref {
            Some(git_ref) if self.ref_is_commit() => Some(git_ref),
            _ => None,
        }
    }

    fn symbolic_ref(&self) -> Option<&str> {
        match &self.git_ref {
            Some(git_ref) if !self.ref_is_commit() => Some(git_ref),
            _ => None,
        }
    }
}

/// Useful APIs for interacting with all kinds of `uses:` clauses.
pub(crate) trait UsesExt {
    fn unpinned(&self) -> bool;
    fn unhashed(&self) -> bool;
}

impl UsesExt for Uses {
    /// Whether the `uses:` is unpinned.
    fn unpinned(&self) -> bool {
        match self {
            Uses::Docker(docker) => docker.hash.is_none() && docker.tag.is_none(),
            Uses::Repository(repo) => repo.git_ref.is_none(),
            // Local `uses:` are always unpinned; any `@ref` component
            // is actually part of the path.
            Uses::Local(_) => true,
        }
    }

    /// Whether the `uses:` is unhashed (but potentially pinned with a non-hash),
    fn unhashed(&self) -> bool {
        match self {
            // TODO: Handle this case. Right now it's not very important,
            // since we don't really analyze local action uses at all,
            // and the "hashedness" of a local action is mostly moot anyways
            // (since it's fully contained within the calling repo),
            Uses::Local(_) => false,
            Uses::Repository(repo) => !repo.ref_is_commit(),
            Uses::Docker(docker) => docker.hash.is_none(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use anyhow::anyhow;
    use github_actions_models::common::Uses;

    use super::RepositoryUsesPattern;

    #[test]
    fn test_repositoryusespattern_parse() {
        for (pattern, expected) in [
            ("", None),      // Invalid, empty
            ("/", None),     // Invalid, not well formed
            ("//", None),    // Invalid, not well formed
            ("///", None),   // Invalid, not well formed
            ("owner", None), // Invalid, sho,uld be owner/*
            ("**", None),    // Invalid, should be *
            ("*", Some(RepositoryUsesPattern::Any)),
            (
                "owner/*",
                Some(RepositoryUsesPattern::InOwner("owner".into())),
            ),
            ("owner/*/", None),      // Invalid, should be owner/*
            ("owner/*/foo", None),   // Invalid, not well formed
            ("owner/*/*", None),     // Invalid, not well formed
            ("*/foo", None),         // Invalid, not well formed
            ("owner/repo/**", None), // Invalid, not well formed.
            (
                "owner/repo/*",
                Some(RepositoryUsesPattern::InRepo {
                    owner: "owner".into(),
                    repo: "repo".into(),
                }),
            ),
            (
                "owner/repo",
                Some(RepositoryUsesPattern::ExactRepo {
                    owner: "owner".into(),
                    repo: "repo".into(),
                }),
            ),
            (
                "owner/repo/subpath",
                Some(RepositoryUsesPattern::ExactPath {
                    owner: "owner".into(),
                    repo: "repo".into(),
                    subpath: "subpath".into(),
                }),
            ),
            // We don't do any subpath normalization at construction time.
            (
                "owner/repo//",
                Some(RepositoryUsesPattern::ExactPath {
                    owner: "owner".into(),
                    repo: "repo".into(),
                    subpath: "/".into(),
                }),
            ),
            (
                "owner/repo/subpath/",
                Some(RepositoryUsesPattern::ExactPath {
                    owner: "owner".into(),
                    repo: "repo".into(),
                    subpath: "subpath/".into(),
                }),
            ),
            (
                "owner/repo/subpath/very/nested////and/literal",
                Some(RepositoryUsesPattern::ExactPath {
                    owner: "owner".into(),
                    repo: "repo".into(),
                    subpath: "subpath/very/nested////and/literal".into(),
                }),
            ),
            (
                "owner/repo@v1",
                Some(RepositoryUsesPattern::ExactWithRef {
                    owner: "owner".into(),
                    repo: "repo".into(),
                    subpath: None,
                    git_ref: "v1".into(),
                }),
            ),
            (
                "owner/repo/subpath@v1",
                Some(RepositoryUsesPattern::ExactWithRef {
                    owner: "owner".into(),
                    repo: "repo".into(),
                    subpath: Some("subpath".into()),
                    git_ref: "v1".into(),
                }),
            ),
            (
                "owner/repo@172239021f7ba04fe7327647b213799853a9eb89",
                Some(RepositoryUsesPattern::ExactWithRef {
                    owner: "owner".into(),
                    repo: "repo".into(),
                    subpath: None,
                    git_ref: "172239021f7ba04fe7327647b213799853a9eb89".into(),
                }),
            ),
            (
                "pypa/gh-action-pypi-publish@release/v1",
                Some(RepositoryUsesPattern::ExactWithRef {
                    owner: "pypa".into(),
                    repo: "gh-action-pypi-publish".into(),
                    subpath: None,
                    git_ref: "release/v1".into(),
                }),
            ),
            // Invalid: no wildcards allowed when refs are present.
            ("owner/repo/*@v1", None),
            ("owner/repo/*/subpath@v1", None),
            ("owner/*/subpath@v1", None),
            ("*/*/subpath@v1", None),
            // Ref also cannot be a wildcard.
            ("owner/repo@*", None),
            ("owner/repo@**", None),
            ("owner/repo@***", None),
            ("owner/repo/subpath@*", None),
            ("owner/*@*", None),
            ("*@*", None),
        ] {
            let pattern = RepositoryUsesPattern::from_str(pattern).ok();
            assert_eq!(pattern, expected);
        }
    }

    #[test]
    fn test_repositoryusespattern_ord() {
        let mut patterns = vec![
            RepositoryUsesPattern::Any,
            RepositoryUsesPattern::ExactRepo {
                owner: "owner".into(),
                repo: "repo".into(),
            },
            RepositoryUsesPattern::InOwner("owner".into()),
        ];

        patterns.sort();

        assert_eq!(
            patterns,
            vec![
                RepositoryUsesPattern::ExactRepo {
                    owner: "owner".into(),
                    repo: "repo".into()
                },
                RepositoryUsesPattern::InOwner("owner".into()),
                RepositoryUsesPattern::Any,
            ]
        );
    }

    #[test]
    fn test_repositoryusespattern_matches() -> anyhow::Result<()> {
        for (uses, pattern, matches) in [
            // OK: case-insensitive, except subpath and tag
            ("actions/checkout@v3", "Actions/Checkout@v3", true),
            ("actions/checkout/foo", "actions/checkout/Foo", false),
            ("actions/checkout/foo@v3", "Actions/Checkout/foo", true),
            ("actions/checkout@v3", "actions/checkout@V3", false),
            // NOT OK: owner/repo do not match
            ("actions/checkout@v3", "foo/checkout", false),
            ("actions/checkout@v3", "actions/bar", false),
            // NOT OK: subpath does not match
            ("actions/checkout/foo", "actions/checkout", false),
            ("actions/checkout/foo@v3", "actions/checkout@v3", false),
            // NOT OK: template is more specific than `uses:`
            ("actions/checkout", "actions/checkout@v3", false),
            ("actions/checkout/foo", "actions/checkout/foo@v3", false),
            // owner/repo/subpath matches regardless of ref and casing
            // but only when the subpath matches.
            // the subpath must share the same case but might not be
            // normalized
            ("actions/checkout/foo", "actions/checkout/foo", true),
            ("ACTIONS/CHECKOUT/foo", "actions/checkout/foo", true),
            ("actions/checkout/foo@v3", "actions/checkout/foo", true),
            ("ACTIONS/CHECKOUT/foo@v3", "actions/checkout/foo", true),
            // TODO: See comment in `RepositoryUsesPattern::matches`
            // ("ACTIONS/CHECKOUT/foo@v3", "actions/checkout/foo/", true),
            // ("ACTIONS/CHECKOUT/foo@v3", "actions/checkout/foo//", true),
            // ("ACTIONS/CHECKOUT//foo////@v3", "actions/checkout/foo", true),
            ("actions/checkout/FOO", "actions/checkout/foo", false),
            ("actions/checkout/foo/bar", "actions/checkout/foo", false),
            // owner/repo matches regardless of ref and casing
            // but does not match subpaths
            ("actions/checkout", "actions/checkout", true),
            ("ACTIONS/CHECKOUT", "actions/checkout", true),
            ("actions/checkout@v3", "actions/checkout", true),
            ("actions/checkout/foo@v3", "actions/checkout", false),
            ("actions/somethingelse", "actions/checkout", false),
            ("whatever/checkout", "actions/checkout", false),
            // owner/repo/* matches regardless of ref and casing
            // including subpaths
            // but does not match when owner diverges
            ("actions/checkout", "actions/checkout/*", true),
            ("ACTIONS/CHECKOUT", "actions/checkout/*", true),
            ("actions/checkout@v3", "actions/checkout/*", true),
            ("actions/checkout/foo@v3", "actions/checkout/*", true),
            ("actions/checkout/foo/bar@v3", "actions/checkout/*", true),
            ("someoneelse/checkout", "actions/checkout/*", false),
            // owner/* matches regardless of ref, casing, and subpath
            // but rejects when owner diverges
            ("actions/checkout", "actions/*", true),
            ("ACTIONS/CHECKOUT", "actions/*", true),
            ("actions/checkout@v3", "actions/*", true),
            ("actions/checkout/foo@v3", "actions/*", true),
            ("someoneelse/checkout", "actions/*", false),
            // * matches everything
            ("actions/checkout", "*", true),
            ("actions/checkout@v3", "*", true),
            ("actions/checkout/foo@v3", "*", true),
            ("whatever/checkout", "*", true),
            // exact matches
            ("actions/checkout@v3", "actions/checkout@v3", true),
            ("actions/checkout/foo@v3", "actions/checkout/foo@v3", true),
            ("actions/checkout/foo", "actions/checkout/foo@v3", false),
        ] {
            let Ok(Uses::Repository(uses)) = Uses::from_str(uses) else {
                return Err(anyhow!("invalid uses: {uses}"));
            };

            let pattern = RepositoryUsesPattern::from_str(pattern)?;

            assert_eq!(
                pattern.matches(&uses),
                matches,
                "pattern: {pattern:?}, uses: {uses:?}, matches: {matches}"
            );
        }

        Ok(())
    }
}
