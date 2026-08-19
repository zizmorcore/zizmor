//! Extension traits for the `Uses` APIs.
//!
//! This is for GitHub Actions style `uses:` clauses;
//! more general "reference to repository" handling
//! lives in [`super::repo_ref`].

use std::{str::FromStr, sync::LazyLock};

use github_actions_models::common::{RepositoryUses, Uses};
use regex::Regex;
use serde::Deserialize;

use crate::models::repo_ref::{RepoRef, Slug};

/// Matches all variants of [`RepositoryUsesPattern`] except `*`.
///
/// TODO: Replace this with a real parser; this is ridiculous.
static REPOSITORY_USES_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)]
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

/// # Represents a pattern for matching repository `uses` references.
///
/// These patterns are ordered by specificity; more specific patterns
/// should be listed first.
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema),
    schemars(with = "String")
)]
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
    pub(crate) fn matches<'doc>(&self, repo: &RepoRef<'doc>) -> bool {
        match repo {
            RepoRef::Uses(uses) => self.matches_uses(uses),
            RepoRef::Url {
                _url,
                slug: Some(slug),
                git_ref,
            } => self.matches_slug(slug, git_ref),
            // Our URL doesn't have a slug, so we can't meaningfully match it (yet).
            _ => false,
        }
    }

    fn matches_slug(&self, slug: &Slug<'_>, slug_git_ref: &str) -> bool {
        match self {
            Self::ExactWithRef {
                owner,
                repo,
                subpath,
                git_ref,
            } => {
                if subpath.is_some() {
                    // Slugs never contain subpaths, so this will never match.
                    false
                } else {
                    slug.owner().eq_ignore_ascii_case(owner)
                        && slug.repo().eq_ignore_ascii_case(repo)
                        && slug_git_ref == git_ref
                }
            }
            Self::ExactPath { .. } => false,
            // `owner/repo` and `owner/repo/*` behave the same for slugs.
            Self::ExactRepo { owner, repo } | Self::InRepo { owner, repo } => {
                slug.owner().eq_ignore_ascii_case(owner) && slug.repo().eq_ignore_ascii_case(repo)
            }
            Self::InOwner(owner) => slug.owner().eq_ignore_ascii_case(owner),
            Self::Any => true,
        }
    }

    fn matches_uses(&self, uses: &RepositoryUses) -> bool {
        match self {
            Self::ExactWithRef {
                owner,
                repo,
                subpath,
                git_ref,
            } => {
                uses.owner().eq_ignore_ascii_case(owner)
                    && uses.repo().eq_ignore_ascii_case(repo)
                    && uses.subpath() == subpath.as_deref()
                    && uses.git_ref() == git_ref
            }
            Self::ExactPath {
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
                uses.owner().eq_ignore_ascii_case(owner)
                    && uses.repo().eq_ignore_ascii_case(repo)
                    && uses.subpath().is_some_and(|s| s == subpath)
            }
            Self::ExactRepo { owner, repo } => {
                uses.owner().eq_ignore_ascii_case(owner)
                    && uses.repo().eq_ignore_ascii_case(repo)
                    && uses.subpath().is_none()
            }
            Self::InRepo { owner, repo } => {
                uses.owner().eq_ignore_ascii_case(owner) && uses.repo().eq_ignore_ascii_case(repo)
            }
            Self::InOwner(owner) => uses.owner().eq_ignore_ascii_case(owner),
            Self::Any => true,
        }
    }
}

impl FromStr for RepositoryUsesPattern {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "*" {
            return Ok(Self::Any);
        }

        let caps = REPOSITORY_USES_PATTERN
            .captures(s)
            .ok_or_else(|| anyhow::anyhow!("invalid pattern: {s}"))?;

        let owner = &caps[1];
        let repo = &caps[2];
        let subpath = caps.get(3).map(|m| m.as_str());
        let git_ref = caps.get(4).map(|m| m.as_str());

        match (owner, repo, subpath, git_ref) {
            (owner, "*", None, None) => Ok(Self::InOwner(owner.into())),
            (owner, repo, None, None) => Ok(Self::ExactRepo {
                owner: owner.into(),
                repo: repo.into(),
            }),
            (_, "*", Some(_), _) => Err(anyhow::anyhow!("invalid pattern: {s}")),
            (owner, repo, Some("*"), None) => Ok(Self::InRepo {
                owner: owner.into(),
                repo: repo.into(),
            }),
            (owner, repo, Some(subpath), None) => Ok(Self::ExactPath {
                owner: owner.into(),
                repo: repo.into(),
                subpath: subpath.into(),
            }),
            (_, _, Some("*"), Some(_)) => Err(anyhow::anyhow!("invalid pattern: {s}")),
            (owner, repo, subpath, Some(git_ref)) => Ok(Self::ExactWithRef {
                owner: owner.into(),
                repo: repo.into(),
                subpath: subpath.map(|s| s.into()),
                git_ref: git_ref.into(),
            }),
        }
    }
}

impl std::fmt::Display for RepositoryUsesPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any => write!(f, "*"),
            Self::InOwner(owner) => write!(f, "{owner}/*"),
            Self::InRepo { owner, repo } => write!(f, "{owner}/{repo}/*"),
            Self::ExactRepo { owner, repo } => write!(f, "{owner}/{repo}"),
            Self::ExactPath {
                owner,
                repo,
                subpath,
            } => write!(f, "{owner}/{repo}/{subpath}"),
            Self::ExactWithRef {
                owner,
                repo,
                subpath,
                git_ref,
            } => match subpath {
                Some(subpath) => write!(f, "{owner}/{repo}/{subpath}@{git_ref}"),
                None => write!(f, "{owner}/{repo}@{git_ref}"),
            },
        }
    }
}

impl<'de> Deserialize<'de> for RepositoryUsesPattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// Useful APIs for interacting with `uses: owner/repo` clauses.
///
/// Some of these APIs are projections of [`RepoRef`]'s APIs.
pub(crate) trait RepositoryUsesExt {
    /// See [`RepoRef::matches`].
    fn matches(&self, pattern: &str) -> bool;

    /// See [`RepoRef::ref_is_commit`].
    fn ref_is_commit(&self) -> bool;

    /// See [`RepoRef::commit_ref`].
    fn commit_ref(&self) -> Option<&str>;

    /// See [`RepoRef::symbolic_ref`].
    fn symbolic_ref(&self) -> Option<&str>;
}

impl RepositoryUsesExt for RepositoryUses {
    fn matches(&self, template: &str) -> bool {
        RepoRef::from(self).matches(template)
    }

    fn ref_is_commit(&self) -> bool {
        RepoRef::from(self).ref_is_commit()
    }

    fn commit_ref(&self) -> Option<&str> {
        RepoRef::from(self).commit_ref()
    }

    fn symbolic_ref(&self) -> Option<&str> {
        RepoRef::from(self).symbolic_ref()
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
            Self::Docker(docker) => docker.hash().is_none() && docker.tag().is_none(),
            Self::Repository(_) => false,
            // Local `uses:` are always unpinned; any `@ref` component
            // is actually part of the path.
            Self::Local(_) => true,
        }
    }

    /// Whether the `uses:` is unhashed (but potentially pinned with a non-hash),
    fn unhashed(&self) -> bool {
        match self {
            // TODO: Handle this case. Right now it's not very important,
            // since we don't really analyze local action uses at all,
            // and the "hashedness" of a local action is mostly moot anyways
            // (since it's fully contained within the calling repo),
            Self::Local(_) => false,
            Self::Repository(repo) => !RepoRef::from(repo).ref_is_commit(),
            Self::Docker(docker) => docker.hash().is_none(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use anyhow::anyhow;
    use github_actions_models::common::Uses;
    use url::Url;

    use crate::models::repo_ref::RepoRef;

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
                pattern.matches_uses(&uses),
                matches,
                "pattern: {pattern:?}, uses: {uses:?}, matches: {matches}"
            );
        }

        Ok(())
    }
}
