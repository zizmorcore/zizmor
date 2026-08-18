use std::{str::FromStr, sync::LazyLock};

use github_actions_models::common::RepositoryUses;
use regex::Regex;
use serde::Deserialize;

use crate::models::repo_ref::{RepoRef, Slug};

/// Matches all variants of [`RepositoryUsesPattern`] except `*`.
///
/// TODO: Replace this with a real parser; this is ridiculous.
static REPOSITORY_USES_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)]
    Regex::new(
        r#"(?xmi)
        ^
        ([\w-]+)
        /
        ([\w\.-]+|\*)
        (?:/([[[:graph:]]&&[^@\*]]+|\*))?
        (?:@([[[:graph:]]&&[^\*]]+))?
        $
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
pub enum RepositoryUsesPattern {
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
    /// Matches `owner/repo/*`, including the empty subpath.
    InRepo { owner: String, repo: String },
    /// Matches any repository under `owner`.
    InOwner(String),
    /// Matches any repository reference.
    Any,
}

impl RepositoryUsesPattern {
    pub fn matches<'doc>(&self, repo: &RepoRef<'doc>) -> bool {
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

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == "*" {
            return Ok(Self::Any);
        }

        let captures = REPOSITORY_USES_PATTERN
            .captures(value)
            .ok_or_else(|| anyhow::anyhow!("invalid pattern: {value}"))?;
        let owner = &captures[1];
        let repo = &captures[2];
        let subpath = captures.get(3).map(|value| value.as_str());
        let git_ref = captures.get(4).map(|value| value.as_str());

        match (owner, repo, subpath, git_ref) {
            (owner, "*", None, None) => Ok(Self::InOwner(owner.into())),
            (owner, repo, None, None) => Ok(Self::ExactRepo {
                owner: owner.into(),
                repo: repo.into(),
            }),
            (_, "*", Some(_), _) | (_, _, Some("*"), Some(_)) => {
                Err(anyhow::anyhow!("invalid pattern: {value}"))
            }
            (owner, repo, Some("*"), None) => Ok(Self::InRepo {
                owner: owner.into(),
                repo: repo.into(),
            }),
            (owner, repo, Some(subpath), None) => Ok(Self::ExactPath {
                owner: owner.into(),
                repo: repo.into(),
                subpath: subpath.into(),
            }),
            (owner, repo, subpath, Some(git_ref)) => Ok(Self::ExactWithRef {
                owner: owner.into(),
                repo: repo.into(),
                subpath: subpath.map(Into::into),
                git_ref: git_ref.into(),
            }),
        }
    }
}

impl std::fmt::Display for RepositoryUsesPattern {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any => write!(formatter, "*"),
            Self::InOwner(owner) => write!(formatter, "{owner}/*"),
            Self::InRepo { owner, repo } => write!(formatter, "{owner}/{repo}/*"),
            Self::ExactRepo { owner, repo } => write!(formatter, "{owner}/{repo}"),
            Self::ExactPath {
                owner,
                repo,
                subpath,
            } => write!(formatter, "{owner}/{repo}/{subpath}"),
            Self::ExactWithRef {
                owner,
                repo,
                subpath,
                git_ref,
            } => match subpath {
                Some(subpath) => write!(formatter, "{owner}/{repo}/{subpath}@{git_ref}"),
                None => write!(formatter, "{owner}/{repo}@{git_ref}"),
            },
        }
    }
}

impl<'de> Deserialize<'de> for RepositoryUsesPattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::RepositoryUsesPattern;

    #[test]
    fn test_repositoryusespattern_parse() {
        for (pattern, expected) in [
            ("", None),      // Invalid, empty
            ("/", None),     // Invalid, not well formed
            ("//", None),    // Invalid, not well formed
            ("///", None),   // Invalid, not well formed
            ("owner", None), // Invalid, should be owner/*
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
}
