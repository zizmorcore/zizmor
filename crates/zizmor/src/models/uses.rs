//! Extension traits for the `Uses` APIs.

use std::{cmp::Ordering, str::FromStr, sync::LazyLock};

use github_actions_models::common::{RepositoryUses, Uses};
use regex::Regex;
use serde::Deserialize;

/// Matches all variants of [`RepositoryUsesPattern`] except `*`.
///
/// TODO: Replace this with a real parser; this is ridiculous.
static REPOSITORY_USES_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)]
    Regex::new(
        r#"(?xmi)                   # verbose, multi-line mode, case-insensitive
        ^                           # start of line
        ([\w-]+)                    # (1) owner (no wildcards allowed)
        /                           # /
        (                           # (2) repo: exact, glob, or *
          [\w\.-]+                  # exact repo name (no wildcards)
          |                         # OR
          [\w\.-]*\*[\w\.-]*        # glob pattern with single * (e.g., foo-*, *-bar)
          |                         # OR
          \*                        # just * (matches any repo)
        )
        (?:                         # non-capturing group for optional subpath
          /                         # /
          (                         # (3) subpath: exact, glob, or *
            [[[:graph:]]&&[^@\*]]+  # exact subpath (no wildcards)
            |                       # OR
            [[[:graph:]]&&[^@\*]]*\*[[[:graph:]]&&[^@\*]]*  # glob pattern with single *
            |                       # OR
            \*                      # just * (matches any subpath)
          )                         # end of (3) subpath
        )?                          # end of non-capturing group for optional subpath
        (?:                         # non-capturing group for optional git ref
          @                         # @
          ([[[:graph:]]&&[^\*]]+)   # (4) git ref (no wildcards allowed)
        )?                          # end of non-capturing group for optional git ref
        $                           # end of line
        "#,
    )
    .unwrap()
});

/// A segment that can be either an exact match or a glob pattern.
///
/// This is used for repo and subpath matching in [`RepositoryUsesPattern`].
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) enum Segment {
    /// An exact literal match (e.g., "checkout", "foo/bar")
    Exact(String),
    /// A glob pattern with a single `*` (e.g., "foo-*", "*-bar")
    Glob {
        /// The literal text before the `*`
        prefix: String,
        /// The literal text after the `*`
        suffix: String,
    },
}

/// Result of parsing a segment string, including the special `*` case.
///
/// This is used during pattern parsing to distinguish between:
/// - `Star`: the full wildcard `*` (used for `owner/*` or `owner/repo/*`)
/// - `Segment`: an exact match or glob pattern
/// - Parse failure (multiple wildcards)
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ParsedSegment {
    /// Just `*` - matches anything in this position
    Star,
    /// A concrete segment (exact or glob)
    Segment(Segment),
}

impl ParsedSegment {
    /// Parse a string into a ParsedSegment.
    ///
    /// - `*` alone becomes `Star`
    /// - A string with exactly one `*` becomes a `Glob` segment
    /// - A string with no `*` becomes an `Exact` segment
    /// - Multiple `*` characters returns `None` (invalid)
    pub(crate) fn parse(s: &str) -> Option<Self> {
        let star_count = s.matches('*').count();

        match star_count {
            0 => Some(ParsedSegment::Segment(Segment::Exact(s.to_string()))),
            1 if s == "*" => Some(ParsedSegment::Star),
            1 => {
                let (prefix, suffix) = s.split_once('*')?;
                Some(ParsedSegment::Segment(Segment::Glob {
                    prefix: prefix.to_string(),
                    suffix: suffix.to_string(),
                }))
            }
            _ => None, // Multiple wildcards not supported
        }
    }
}

impl Segment {
    /// Check if a value matches this segment (case-sensitive).
    pub(crate) fn matches(&self, value: &str) -> bool {
        match self {
            Segment::Exact(s) => s == value,
            Segment::Glob { prefix, suffix } => {
                if value.len() < prefix.len() + suffix.len() {
                    return false;
                }
                value.starts_with(prefix) && value.ends_with(suffix)
            }
        }
    }

    /// Check if a value matches this segment (case-insensitive for ASCII).
    pub(crate) fn matches_ignore_ascii_case(&self, value: &str) -> bool {
        match self {
            Segment::Exact(s) => s.eq_ignore_ascii_case(value),
            Segment::Glob { prefix, suffix } => {
                if value.len() < prefix.len() + suffix.len() {
                    return false;
                }
                // Compare prefix (case-insensitive) without allocating
                let prefix_matches = value
                    .as_bytes()
                    .iter()
                    .zip(prefix.as_bytes())
                    .all(|(v, p)| v.eq_ignore_ascii_case(p));
                if !prefix_matches {
                    return false;
                }
                // Compare suffix (case-insensitive) without allocating
                value
                    .as_bytes()
                    .iter()
                    .rev()
                    .zip(suffix.as_bytes().iter().rev())
                    .all(|(v, s)| v.eq_ignore_ascii_case(s))
            }
        }
    }

    /// Returns the "specificity" of this segment for ordering purposes.
    /// Lower values are more specific.
    /// Exact matches are more specific than globs.
    /// For globs, longer prefix+suffix means more specific.
    fn specificity(&self) -> (u8, usize) {
        match self {
            // Exact is most specific (0), with no length consideration
            Segment::Exact(_) => (0, 0),
            // Glob is less specific (1), but longer literals are more specific (inverted)
            Segment::Glob { prefix, suffix } => (1, usize::MAX - (prefix.len() + suffix.len())),
        }
    }
}

impl PartialOrd for Segment {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Segment {
    fn cmp(&self, other: &Self) -> Ordering {
        self.specificity().cmp(&other.specificity())
    }
}

impl std::fmt::Display for Segment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Segment::Exact(s) => write!(f, "{s}"),
            Segment::Glob { prefix, suffix } => write!(f, "{prefix}*{suffix}"),
        }
    }
}

/// # Represents a pattern for matching repository `uses` references.
///
/// These patterns are ordered by specificity; more specific patterns
/// should be listed first. The ordering is:
///
/// 1. `ExactWithRef` - most specific (matches owner/repo/subpath@ref exactly)
/// 2. `ExactPath` - matches owner/repo/subpath (any ref)
/// 3. `ExactRepo` - matches owner/repo with no subpath (any ref)
/// 4. `InRepo` - matches owner/repo/* (any subpath, any ref)
/// 5. `InOwner` - matches owner/* (any repo, any subpath, any ref)
/// 6. `Any` - matches * (everything)
///
/// Within variants that have `Segment` fields, patterns with exact segments
/// are more specific than patterns with glob segments.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(
    feature = "schema",
    derive(schemars::JsonSchema),
    schemars(with = "String")
)]
pub(crate) enum RepositoryUsesPattern {
    /// Matches `owner/repo/subpath@ref` where repo and subpath can be exact or globs.
    ExactWithRef {
        owner: String,
        repo: Segment,
        subpath: Option<Segment>,
        git_ref: String,
    },
    /// Matches `owner/repo/subpath` where repo and subpath can be exact or globs.
    /// Any ref is matched.
    ExactPath {
        owner: String,
        repo: Segment,
        subpath: Segment,
    },
    /// Matches `owner/repo` (no subpath allowed) where repo can be exact or a glob.
    /// Any ref is matched.
    ExactRepo { owner: String, repo: Segment },
    /// Matches `owner/repo/*` where repo can be exact or a glob.
    /// Any subpath (including none) is matched. Any ref is matched.
    InRepo { owner: String, repo: Segment },
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
                uses.owner().eq_ignore_ascii_case(owner)
                    && repo.matches_ignore_ascii_case(uses.repo())
                    && match subpath {
                        Some(sp) => uses.subpath().is_some_and(|s| sp.matches(s)),
                        None => uses.subpath().is_none(),
                    }
                    && uses.git_ref() == git_ref
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
                uses.owner().eq_ignore_ascii_case(owner)
                    && repo.matches_ignore_ascii_case(uses.repo())
                    // Subpath matching is case-sensitive
                    && uses.subpath().is_some_and(|s| subpath.matches(s))
            }
            RepositoryUsesPattern::ExactRepo { owner, repo } => {
                uses.owner().eq_ignore_ascii_case(owner)
                    && repo.matches_ignore_ascii_case(uses.repo())
                    && uses.subpath().is_none()
            }
            RepositoryUsesPattern::InRepo { owner, repo } => {
                uses.owner().eq_ignore_ascii_case(owner)
                    && repo.matches_ignore_ascii_case(uses.repo())
            }
            RepositoryUsesPattern::InOwner(owner) => uses.owner().eq_ignore_ascii_case(owner),
            RepositoryUsesPattern::Any => true,
        }
    }

    /// Returns a tuple used for ordering patterns by specificity.
    /// Lower values are more specific and should come first when sorted.
    fn specificity(&self) -> (u8, Segment, Option<Segment>) {
        // Create a dummy segment for comparison purposes
        let no_segment = Segment::Exact(String::new());

        match self {
            RepositoryUsesPattern::ExactWithRef { repo, subpath, .. } => {
                (0, repo.clone(), subpath.clone())
            }
            RepositoryUsesPattern::ExactPath { repo, subpath, .. } => {
                (1, repo.clone(), Some(subpath.clone()))
            }
            RepositoryUsesPattern::ExactRepo { repo, .. } => (2, repo.clone(), None),
            RepositoryUsesPattern::InRepo { repo, .. } => (3, repo.clone(), None),
            RepositoryUsesPattern::InOwner(_) => (4, no_segment.clone(), None),
            RepositoryUsesPattern::Any => (5, no_segment, None),
        }
    }
}

impl PartialOrd for RepositoryUsesPattern {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RepositoryUsesPattern {
    fn cmp(&self, other: &Self) -> Ordering {
        self.specificity().cmp(&other.specificity())
    }
}

impl FromStr for RepositoryUsesPattern {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Special case: bare `*` matches everything
        if s == "*" {
            return Ok(RepositoryUsesPattern::Any);
        }

        let caps = REPOSITORY_USES_PATTERN
            .captures(s)
            .ok_or_else(|| anyhow::anyhow!("invalid pattern: {s}"))?;

        let owner = &caps[1];
        let repo_str = &caps[2];
        let subpath_str = caps.get(3).map(|m| m.as_str());
        let git_ref = caps.get(4).map(|m| m.as_str());

        // Parse repo segment (handles validation of multiple wildcards)
        let repo_parsed = ParsedSegment::parse(repo_str)
            .ok_or_else(|| anyhow::anyhow!("invalid pattern: {s}"))?;

        // Parse subpath segment if present
        let subpath_parsed = subpath_str
            .map(|sp| {
                ParsedSegment::parse(sp).ok_or_else(|| anyhow::anyhow!("invalid pattern: {s}"))
            })
            .transpose()?;

        // Build the appropriate pattern variant
        match (&repo_parsed, &subpath_parsed, git_ref) {
            // ================================================================
            // owner/* - matches any repo under owner
            // ================================================================
            (ParsedSegment::Star, None, None) => Ok(RepositoryUsesPattern::InOwner(owner.into())),

            // owner/*@ref is invalid (can't have ref with repo star)
            (ParsedSegment::Star, None, Some(_)) => Err(anyhow::anyhow!("invalid pattern: {s}")),

            // owner/*/... is invalid (can't have subpath after repo star)
            (ParsedSegment::Star, Some(_), _) => Err(anyhow::anyhow!("invalid pattern: {s}")),

            // ================================================================
            // Patterns without subpath
            // ================================================================
            // owner/repo or owner/repo-* (no subpath, no ref)
            (ParsedSegment::Segment(repo), None, None) => Ok(RepositoryUsesPattern::ExactRepo {
                owner: owner.into(),
                repo: repo.clone(),
            }),

            // owner/repo@ref or owner/repo-*@ref (no subpath, with ref)
            (ParsedSegment::Segment(repo), None, Some(r)) => {
                Ok(RepositoryUsesPattern::ExactWithRef {
                    owner: owner.into(),
                    repo: repo.clone(),
                    subpath: None,
                    git_ref: r.into(),
                })
            }

            // ================================================================
            // Patterns with subpath = *
            // ================================================================
            // owner/repo/* or owner/repo-*/* (any subpath)
            (ParsedSegment::Segment(repo), Some(ParsedSegment::Star), None) => {
                Ok(RepositoryUsesPattern::InRepo {
                    owner: owner.into(),
                    repo: repo.clone(),
                })
            }

            // owner/repo/*@ref is invalid (can't combine subpath star with ref)
            (_, Some(ParsedSegment::Star), Some(_)) => Err(anyhow::anyhow!("invalid pattern: {s}")),

            // ================================================================
            // Patterns with exact or glob subpath
            // ================================================================
            // owner/repo/subpath or owner/repo-*/subpath or owner/repo/subpath-*
            (ParsedSegment::Segment(repo), Some(ParsedSegment::Segment(subpath)), None) => {
                Ok(RepositoryUsesPattern::ExactPath {
                    owner: owner.into(),
                    repo: repo.clone(),
                    subpath: subpath.clone(),
                })
            }

            // owner/repo/subpath@ref or owner/repo-*/subpath@ref or owner/repo/subpath-*@ref
            (ParsedSegment::Segment(repo), Some(ParsedSegment::Segment(subpath)), Some(r)) => {
                Ok(RepositoryUsesPattern::ExactWithRef {
                    owner: owner.into(),
                    repo: repo.clone(),
                    subpath: Some(subpath.clone()),
                    git_ref: r.into(),
                })
            }
        }
    }
}

impl std::fmt::Display for RepositoryUsesPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RepositoryUsesPattern::ExactWithRef {
                owner,
                repo,
                subpath,
                git_ref,
            } => match subpath {
                Some(subpath) => write!(f, "{owner}/{repo}/{subpath}@{git_ref}"),
                None => write!(f, "{owner}/{repo}@{git_ref}"),
            },
            RepositoryUsesPattern::ExactPath {
                owner,
                repo,
                subpath,
            } => write!(f, "{owner}/{repo}/{subpath}"),
            RepositoryUsesPattern::ExactRepo { owner, repo } => write!(f, "{owner}/{repo}"),
            RepositoryUsesPattern::InRepo { owner, repo } => write!(f, "{owner}/{repo}/*"),
            RepositoryUsesPattern::InOwner(owner) => write!(f, "{owner}/*"),
            RepositoryUsesPattern::Any => write!(f, "*"),
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
        self.git_ref().len() == 40 && self.git_ref().chars().all(|c| c.is_ascii_hexdigit())
    }

    fn commit_ref(&self) -> Option<&str> {
        match &self.git_ref() {
            git_ref if self.ref_is_commit() => Some(git_ref),
            _ => None,
        }
    }

    fn symbolic_ref(&self) -> Option<&str> {
        match &self.git_ref() {
            git_ref if !self.ref_is_commit() => Some(git_ref),
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
            Uses::Docker(docker) => docker.hash().is_none() && docker.tag().is_none(),
            Uses::Repository(_) => false,
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
            Uses::Docker(docker) => docker.hash().is_none(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use anyhow::anyhow;
    use github_actions_models::common::Uses;

    use super::{ParsedSegment, RepositoryUsesPattern, Segment};

    #[test]
    fn test_parsed_segment_parse() {
        // Exact segments
        assert_eq!(
            ParsedSegment::parse("checkout"),
            Some(ParsedSegment::Segment(Segment::Exact("checkout".into())))
        );
        assert_eq!(
            ParsedSegment::parse("foo-bar"),
            Some(ParsedSegment::Segment(Segment::Exact("foo-bar".into())))
        );

        // Star (full wildcard)
        assert_eq!(ParsedSegment::parse("*"), Some(ParsedSegment::Star));

        // Glob segments
        assert_eq!(
            ParsedSegment::parse("foo-*"),
            Some(ParsedSegment::Segment(Segment::Glob {
                prefix: "foo-".into(),
                suffix: "".into()
            }))
        );
        assert_eq!(
            ParsedSegment::parse("*-bar"),
            Some(ParsedSegment::Segment(Segment::Glob {
                prefix: "".into(),
                suffix: "-bar".into()
            }))
        );
        assert_eq!(
            ParsedSegment::parse("foo-*-bar"),
            Some(ParsedSegment::Segment(Segment::Glob {
                prefix: "foo-".into(),
                suffix: "-bar".into()
            }))
        );

        // Multiple wildcards - not supported
        assert_eq!(ParsedSegment::parse("foo-*-*"), None);
        assert_eq!(ParsedSegment::parse("**"), None);
    }

    #[test]
    fn test_segment_matches() {
        // Exact matching
        let exact = Segment::Exact("checkout".into());
        assert!(exact.matches("checkout"));
        assert!(!exact.matches("Checkout")); // case-sensitive
        assert!(!exact.matches("checkout-v2"));

        // Case-insensitive exact matching
        assert!(exact.matches_ignore_ascii_case("checkout"));
        assert!(exact.matches_ignore_ascii_case("CHECKOUT"));
        assert!(exact.matches_ignore_ascii_case("Checkout"));

        // Glob matching - prefix
        let prefix_glob = Segment::Glob {
            prefix: "foo-".into(),
            suffix: "".into(),
        };
        assert!(prefix_glob.matches("foo-bar"));
        assert!(prefix_glob.matches("foo-"));
        assert!(prefix_glob.matches("foo-baz-qux"));
        assert!(!prefix_glob.matches("bar-foo"));
        assert!(!prefix_glob.matches("foo"));

        // Glob matching - suffix
        let suffix_glob = Segment::Glob {
            prefix: "".into(),
            suffix: "-bar".into(),
        };
        assert!(suffix_glob.matches("foo-bar"));
        assert!(suffix_glob.matches("-bar"));
        assert!(suffix_glob.matches("baz-qux-bar"));
        assert!(!suffix_glob.matches("bar-foo"));
        assert!(!suffix_glob.matches("bar"));

        // Glob matching - case insensitive
        assert!(prefix_glob.matches_ignore_ascii_case("FOO-bar"));
        assert!(prefix_glob.matches_ignore_ascii_case("Foo-BAZ"));
    }

    #[test]
    fn test_segment_ordering() {
        let exact = Segment::Exact("checkout".into());
        let short_glob = Segment::Glob {
            prefix: "foo-".into(),
            suffix: "".into(),
        };
        let long_glob = Segment::Glob {
            prefix: "foo-bar-".into(),
            suffix: "-baz".into(),
        };

        // Exact is more specific than any glob
        assert!(exact < short_glob);
        assert!(exact < long_glob);

        // Longer globs are more specific than shorter globs
        assert!(long_glob < short_glob);
    }

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
                    repo: Segment::Exact("repo".into()),
                }),
            ),
            (
                "owner/repo",
                Some(RepositoryUsesPattern::ExactRepo {
                    owner: "owner".into(),
                    repo: Segment::Exact("repo".into()),
                }),
            ),
            (
                "owner/repo/subpath",
                Some(RepositoryUsesPattern::ExactPath {
                    owner: "owner".into(),
                    repo: Segment::Exact("repo".into()),
                    subpath: Segment::Exact("subpath".into()),
                }),
            ),
            // We don't do any subpath normalization at construction time.
            (
                "owner/repo//",
                Some(RepositoryUsesPattern::ExactPath {
                    owner: "owner".into(),
                    repo: Segment::Exact("repo".into()),
                    subpath: Segment::Exact("/".into()),
                }),
            ),
            (
                "owner/repo/subpath/",
                Some(RepositoryUsesPattern::ExactPath {
                    owner: "owner".into(),
                    repo: Segment::Exact("repo".into()),
                    subpath: Segment::Exact("subpath/".into()),
                }),
            ),
            (
                "owner/repo/subpath/very/nested////and/literal",
                Some(RepositoryUsesPattern::ExactPath {
                    owner: "owner".into(),
                    repo: Segment::Exact("repo".into()),
                    subpath: Segment::Exact("subpath/very/nested////and/literal".into()),
                }),
            ),
            (
                "owner/repo@v1",
                Some(RepositoryUsesPattern::ExactWithRef {
                    owner: "owner".into(),
                    repo: Segment::Exact("repo".into()),
                    subpath: None,
                    git_ref: "v1".into(),
                }),
            ),
            (
                "owner/repo/subpath@v1",
                Some(RepositoryUsesPattern::ExactWithRef {
                    owner: "owner".into(),
                    repo: Segment::Exact("repo".into()),
                    subpath: Some(Segment::Exact("subpath".into())),
                    git_ref: "v1".into(),
                }),
            ),
            (
                "owner/repo@172239021f7ba04fe7327647b213799853a9eb89",
                Some(RepositoryUsesPattern::ExactWithRef {
                    owner: "owner".into(),
                    repo: Segment::Exact("repo".into()),
                    subpath: None,
                    git_ref: "172239021f7ba04fe7327647b213799853a9eb89".into(),
                }),
            ),
            (
                "pypa/gh-action-pypi-publish@release/v1",
                Some(RepositoryUsesPattern::ExactWithRef {
                    owner: "pypa".into(),
                    repo: Segment::Exact("gh-action-pypi-publish".into()),
                    subpath: None,
                    git_ref: "release/v1".into(),
                }),
            ),
            // Invalid: no wildcards allowed when refs are present (subpath star only).
            ("owner/repo/*@v1", None),
            // Note: owner/repo/*/subpath@v1 is now VALID - it's a subpath glob matching "*" + "/subpath"
            // See the glob patterns section below for the expected parse result.
            ("owner/*/subpath@v1", None), // Invalid: can't have subpath after repo star
            ("*/*/subpath@v1", None),     // Invalid: owner can't be wildcard
            // Ref also cannot be a wildcard.
            ("owner/repo@*", None),
            ("owner/repo@**", None),
            ("owner/repo@***", None),
            ("owner/repo/subpath@*", None),
            ("owner/*@*", None),
            ("*@*", None),
            // ================================================================
            // NEW: Glob patterns
            // ================================================================
            // Repo globs
            (
                "owner/foo-*",
                Some(RepositoryUsesPattern::ExactRepo {
                    owner: "owner".into(),
                    repo: Segment::Glob {
                        prefix: "foo-".into(),
                        suffix: "".into(),
                    },
                }),
            ),
            (
                "owner/*-bar",
                Some(RepositoryUsesPattern::ExactRepo {
                    owner: "owner".into(),
                    repo: Segment::Glob {
                        prefix: "".into(),
                        suffix: "-bar".into(),
                    },
                }),
            ),
            // Glob with both prefix and suffix (single * with text on both sides)
            (
                "owner/foo-*-bar",
                Some(RepositoryUsesPattern::ExactRepo {
                    owner: "owner".into(),
                    repo: Segment::Glob {
                        prefix: "foo-".into(),
                        suffix: "-bar".into(),
                    },
                }),
            ),
            (
                "owner/foo-*/*",
                Some(RepositoryUsesPattern::InRepo {
                    owner: "owner".into(),
                    repo: Segment::Glob {
                        prefix: "foo-".into(),
                        suffix: "".into(),
                    },
                }),
            ),
            (
                "owner/foo-*/subpath",
                Some(RepositoryUsesPattern::ExactPath {
                    owner: "owner".into(),
                    repo: Segment::Glob {
                        prefix: "foo-".into(),
                        suffix: "".into(),
                    },
                    subpath: Segment::Exact("subpath".into()),
                }),
            ),
            (
                "owner/foo-*/subpath@v1",
                Some(RepositoryUsesPattern::ExactWithRef {
                    owner: "owner".into(),
                    repo: Segment::Glob {
                        prefix: "foo-".into(),
                        suffix: "".into(),
                    },
                    subpath: Some(Segment::Exact("subpath".into())),
                    git_ref: "v1".into(),
                }),
            ),
            (
                "owner/foo-*@v1",
                Some(RepositoryUsesPattern::ExactWithRef {
                    owner: "owner".into(),
                    repo: Segment::Glob {
                        prefix: "foo-".into(),
                        suffix: "".into(),
                    },
                    subpath: None,
                    git_ref: "v1".into(),
                }),
            ),
            // Subpath globs
            (
                "owner/repo/sub-*",
                Some(RepositoryUsesPattern::ExactPath {
                    owner: "owner".into(),
                    repo: Segment::Exact("repo".into()),
                    subpath: Segment::Glob {
                        prefix: "sub-".into(),
                        suffix: "".into(),
                    },
                }),
            ),
            (
                "owner/repo/sub-*@v1",
                Some(RepositoryUsesPattern::ExactWithRef {
                    owner: "owner".into(),
                    repo: Segment::Exact("repo".into()),
                    subpath: Some(Segment::Glob {
                        prefix: "sub-".into(),
                        suffix: "".into(),
                    }),
                    git_ref: "v1".into(),
                }),
            ),
            // Subpath glob with suffix (matches */subpath pattern)
            (
                "owner/repo/*/subpath@v1",
                Some(RepositoryUsesPattern::ExactWithRef {
                    owner: "owner".into(),
                    repo: Segment::Exact("repo".into()),
                    subpath: Some(Segment::Glob {
                        prefix: "".into(),
                        suffix: "/subpath".into(),
                    }),
                    git_ref: "v1".into(),
                }),
            ),
            // Combined repo and subpath globs
            (
                "owner/foo-*/sub-*",
                Some(RepositoryUsesPattern::ExactPath {
                    owner: "owner".into(),
                    repo: Segment::Glob {
                        prefix: "foo-".into(),
                        suffix: "".into(),
                    },
                    subpath: Segment::Glob {
                        prefix: "sub-".into(),
                        suffix: "".into(),
                    },
                }),
            ),
            // Invalid: multiple wildcards in segment
            ("owner/foo-*-*", None),
            ("owner/repo/sub-*-*", None),
        ] {
            let pattern = RepositoryUsesPattern::from_str(pattern).ok();
            assert_eq!(pattern, expected, "pattern: {pattern:?}");
        }
    }

    #[test]
    fn test_repositoryusespattern_ord() {
        let mut patterns = vec![
            RepositoryUsesPattern::Any,
            RepositoryUsesPattern::ExactRepo {
                owner: "owner".into(),
                repo: Segment::Exact("repo".into()),
            },
            RepositoryUsesPattern::InOwner("owner".into()),
        ];

        patterns.sort();

        assert_eq!(
            patterns,
            vec![
                RepositoryUsesPattern::ExactRepo {
                    owner: "owner".into(),
                    repo: Segment::Exact("repo".into()),
                },
                RepositoryUsesPattern::InOwner("owner".into()),
                RepositoryUsesPattern::Any,
            ]
        );
    }

    #[test]
    fn test_repositoryusespattern_ord_with_globs() {
        let mut patterns = vec![
            RepositoryUsesPattern::ExactRepo {
                owner: "owner".into(),
                repo: Segment::Glob {
                    prefix: "foo-".into(),
                    suffix: "".into(),
                },
            },
            RepositoryUsesPattern::ExactRepo {
                owner: "owner".into(),
                repo: Segment::Exact("foo-bar".into()),
            },
            RepositoryUsesPattern::InRepo {
                owner: "owner".into(),
                repo: Segment::Exact("foo-bar".into()),
            },
        ];

        patterns.sort();

        // Exact repo should come before glob repo
        // InRepo should come after both ExactRepo variants
        assert_eq!(
            patterns,
            vec![
                RepositoryUsesPattern::ExactRepo {
                    owner: "owner".into(),
                    repo: Segment::Exact("foo-bar".into()),
                },
                RepositoryUsesPattern::ExactRepo {
                    owner: "owner".into(),
                    repo: Segment::Glob {
                        prefix: "foo-".into(),
                        suffix: "".into(),
                    },
                },
                RepositoryUsesPattern::InRepo {
                    owner: "owner".into(),
                    repo: Segment::Exact("foo-bar".into()),
                },
            ]
        );
    }

    #[test]
    fn test_repositoryusespattern_matches() -> anyhow::Result<()> {
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
            // ================================================================
            // NEW: Glob pattern matching
            // ================================================================
            // Repo globs - basic matching
            ("org/foo-bar@v1", "org/foo-*", true),
            ("org/foo-baz@v1", "org/foo-*", true),
            ("org/foo-@v1", "org/foo-*", true), // edge case: just prefix
            ("org/bar-foo@v1", "org/foo-*", false), // doesn't start with prefix
            ("org/foo@v1", "org/foo-*", false), // missing hyphen
            // Repo globs - suffix matching
            ("org/bar-action@v1", "org/*-action", true),
            ("org/foo-action@v1", "org/*-action", true),
            ("org/action-bar@v1", "org/*-action", false),
            // Repo globs - prefix AND suffix matching (single * with text on both sides)
            ("org/foo-something-bar@v1", "org/foo-*-bar", true),
            ("org/foo--bar@v1", "org/foo-*-bar", true), // empty middle is valid (matches "")
            ("org/foo-x-bar@v1", "org/foo-*-bar", true),
            ("org/foo-bar@v1", "org/foo-*-bar", false), // too short: prefix+suffix overlap
            ("org/foo-something-baz@v1", "org/foo-*-bar", false), // wrong suffix
            ("org/baz-something-bar@v1", "org/foo-*-bar", false), // wrong prefix
            // Repo globs - case insensitivity (repo matching)
            ("org/FOO-BAR@v1", "org/foo-*", true),
            ("ORG/foo-bar@v1", "org/foo-*", true),
            // Repo globs - no subpath allowed for ExactRepo variant
            ("org/foo-bar@v1", "org/foo-*", true),
            ("org/foo-bar/subpath@v1", "org/foo-*", false), // Has subpath, pattern doesn't allow
            // Repo globs with InRepo (/*) - allows subpaths
            ("org/foo-bar@v1", "org/foo-*/*", true),
            ("org/foo-bar/subpath@v1", "org/foo-*/*", true),
            ("org/foo-bar/deep/path@v1", "org/foo-*/*", true),
            // Repo globs with specific subpath
            ("org/foo-bar/init@v1", "org/foo-*/init", true),
            ("org/foo-baz/init@v1", "org/foo-*/init", true),
            ("org/foo-bar/other@v1", "org/foo-*/init", false),
            // Repo globs with ref
            ("org/foo-bar@v1", "org/foo-*@v1", true),
            ("org/foo-bar@v2", "org/foo-*@v1", false),
            ("org/foo-bar/sub@v1", "org/foo-*/sub@v1", true),
            // Subpath globs
            ("org/repo/sub-foo@v1", "org/repo/sub-*", true),
            ("org/repo/sub-bar@v1", "org/repo/sub-*", true),
            ("org/repo/other@v1", "org/repo/sub-*", false),
            // Subpath globs - case sensitivity (subpath is case-sensitive)
            ("org/repo/sub-foo@v1", "org/repo/sub-*", true),
            ("org/repo/SUB-foo@v1", "org/repo/sub-*", false), // case mismatch
            // Combined repo and subpath globs
            ("org/foo-bar/sub-baz@v1", "org/foo-*/sub-*", true),
            ("org/foo-qux/sub-quux@v1", "org/foo-*/sub-*", true),
            ("org/bar-foo/sub-baz@v1", "org/foo-*/sub-*", false), // repo doesn't match
            ("org/foo-bar/other@v1", "org/foo-*/sub-*", false),   // subpath doesn't match
        ] {
            let Ok(Uses::Repository(uses)) = Uses::parse(uses) else {
                return Err(anyhow!("invalid uses: {uses}"));
            };

            let pattern = RepositoryUsesPattern::from_str(pattern)?;

            assert_eq!(
                pattern.matches(&uses),
                matches,
                "pattern: {pattern:?}, uses: {uses:?}, expected matches: {matches}"
            );
        }

        Ok(())
    }

    #[test]
    fn test_repositoryusespattern_display() {
        // Test that Display roundtrips correctly for glob patterns
        let patterns = [
            "owner/foo-*",
            "owner/*-bar",
            "owner/foo-*/*",
            "owner/foo-*/subpath",
            "owner/foo-*@v1",
            "owner/foo-*/subpath@v1",
            "owner/repo/sub-*",
            "owner/repo/sub-*@v1",
        ];

        for pattern_str in patterns {
            let pattern = RepositoryUsesPattern::from_str(pattern_str).unwrap();
            assert_eq!(
                pattern.to_string(),
                pattern_str,
                "Display roundtrip failed for {pattern_str}"
            );
        }
    }
}
