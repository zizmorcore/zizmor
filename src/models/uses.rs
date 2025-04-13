//! Extension traits for the `Uses` APIs.

use std::{str::FromStr, sync::LazyLock};

use github_actions_models::common::{RepositoryUses, Uses};
use regex::Regex;
use serde::Deserialize;

// Matches patterns like `owner/repo` and `owner/*`.
static REPOSITORY_USES_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?mi)^[\w-]+/([\w\.-]+|\*)$"#).unwrap());

/// Represents a pattern for matching repository `uses` references.
/// These patterns are ordered by specificity; more specific patterns
/// should be listed first.
#[derive(Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub(crate) enum RepositoryUsesPattern {
    InRepo { owner: String, repo: String },
    InOwner(String),
    Any,
}

impl RepositoryUsesPattern {
    pub(crate) fn matches(&self, uses: &RepositoryUses) -> bool {
        match self {
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

        if !REPOSITORY_USES_PATTERN.is_match(s) {
            return Err(anyhow::anyhow!("invalid repository pattern: {s}"));
        }

        let (owner, repo) = s
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("invalid repository pattern: {s}"))?;

        Ok(if repo == "*" {
            RepositoryUsesPattern::InOwner(owner.into())
        } else {
            RepositoryUsesPattern::InRepo {
                owner: owner.into(),
                repo: repo.into(),
            }
        })
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
    /// Returns whether this `uses:` clause "matches" the given template.
    /// The template is itself formatted like a normal `uses:` clause.
    ///
    /// This is an asymmetrical match: `actions/checkout@v3` "matches"
    /// the `actions/checkout` template but not vice versa.
    ///
    /// Comparisons are case-insensitive, since GitHub's own APIs are insensitive.
    ///
    /// TODO: Remove this API and replace it with [`RepositoryUsesPattern`].
    fn matches(&self, template: &str) -> bool;

    /// Like [`RepositoryUsesExt::matches`].
    fn matches_uses(&self, template: &RepositoryUses) -> bool;

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
        let Ok(other) = template.parse::<RepositoryUses>() else {
            return false;
        };

        self.matches_uses(&other)
    }

    fn matches_uses(&self, template: &RepositoryUses) -> bool {
        self.owner.eq_ignore_ascii_case(&template.owner)
            && (template.repo == "*" || self.repo.eq_ignore_ascii_case(&template.repo))
            && self.subpath.as_ref().map(|s| s.to_lowercase())
                == template.subpath.as_ref().map(|s| s.to_lowercase())
            && template.git_ref.as_ref().is_none_or(|git_ref| {
                Some(git_ref.to_lowercase()) == self.git_ref.as_ref().map(|r| r.to_lowercase())
            })
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
            Uses::Local(local) => local.git_ref.is_none(),
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

    use crate::models::uses::RepositoryUsesExt;

    use super::RepositoryUsesPattern;

    #[test]
    fn test_repositoryuses_matches() {
        for (uses, template, matches) in [
            // OK: `uses:` is more specific than template
            ("actions/checkout@v3", "actions/checkout", true),
            ("actions/checkout/foo@v3", "actions/checkout/foo", true),
            // OK: equally specific
            ("actions/checkout@v3", "actions/checkout@v3", true),
            ("actions/checkout", "actions/checkout", true),
            ("actions/checkout/foo", "actions/checkout/foo", true),
            ("actions/checkout/foo@v3", "actions/checkout/foo@v3", true),
            // OK: case-insensitive
            ("actions/checkout@v3", "Actions/Checkout@v3", true),
            ("actions/checkout/foo", "actions/checkout/Foo", true),
            ("actions/checkout/foo@v3", "Actions/Checkout/Foo", true),
            ("actions/checkout@v3", "actions/checkout@V3", true),
            // NOT OK: owner/repo do not match
            ("actions/checkout@v3", "foo/checkout", false),
            ("actions/checkout@v3", "actions/bar", false),
            // NOT OK: subpath does not match
            ("actions/checkout/foo", "actions/checkout", false),
            ("actions/checkout/foo@v3", "actions/checkout@v3", false),
            // NOT OK: template is more specific than `uses:`
            ("actions/checkout", "actions/checkout@v3", false),
            ("actions/checkout/foo", "actions/checkout/foo@v3", false),
        ] {
            let Ok(Uses::Repository(uses)) = Uses::from_str(uses) else {
                panic!();
            };

            assert_eq!(uses.matches(template), matches)
        }
    }

    #[test]
    fn test_repositoryusespattern_matches() -> anyhow::Result<()> {
        for (uses, pattern, matches) in [
            // owner/repo matches regardless of ref, casing, and subpath
            // but rejects when owner/repo diverges
            ("actions/checkout", "actions/checkout", true),
            ("ACTIONS/CHECKOUT", "actions/checkout", true),
            ("actions/checkout@v3", "actions/checkout", true),
            ("actions/checkout/foo@v3", "actions/checkout", true),
            ("actions/somethingelse", "actions/checkout", false),
            ("whatever/checkout", "actions/checkout", false),
            // owner/* matches of ref, casing, and subpath
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
        ] {
            let Ok(Uses::Repository(uses)) = Uses::from_str(uses) else {
                return Err(anyhow!("invalid uses: {uses}"));
            };

            let pattern = RepositoryUsesPattern::from_str(pattern)?;

            assert_eq!(pattern.matches(&uses), matches);
        }

        Ok(())
    }
}
