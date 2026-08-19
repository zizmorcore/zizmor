//! Parsing and comparison of versions, as they appear in
//! tags on GitHub Actions `uses:` directives.
//!
//! This implements something similar but not identical to
//! [semantic versioning](https://semver.org/), as GitHub Actions
//! has no structured versioning scheme.

use crate::{finding::location::Comment, utils::once::static_regex};

static_regex!(
    VERSION_COMMENT_PATTERN,
    r#"(?x)                             # verbose mode
    ^                                   # start of string
    \#                                  # start of comment
    \s*                                 # optional whitespace
    (?:                                 # start non-capturing group for version prefix
      (?:tag|version|ver)\s*[:=]\s*     # version prefix + `:` or `=`
    )?                                  # end optional non-capturing group
    (                                   # start capturing group for version
      \S+                               # one or more non-whitespace characters
    )                                   # end capturing group for version
    $                                   # end of string
    "#
);

// Ratchet pins actions with comments like `# ratchet:actions/checkout@v4.2.2`.
// See https://github.com/sethvargo/ratchet for details.
static_regex!(
    RATCHET_COMMENT_PATTERN,
    r#"(?x)                             # verbose mode
    ^                                   # start of string
    \#                                  # start of comment
    \s*                                 # optional whitespace
    ratchet:                            # ratchet prefix
    [^@]+                               # action name, anything up to @
    @                                   # separator
    (                                   # start capturing group for version
      \S+                               # one or more non-whitespace characters
    )                                   # end capturing group for version
    $                                   # end of string
    "#
);

/// A "raw" version.
///
/// This represents an arbitrary string that we *think* is a version
/// (for context-sensitive reasons, e.g. being in a comment that looks
/// like a version), but that we haven't validated at all as actually being
/// semver-shaped.
pub(crate) struct RawVersion<'a> {
    raw: &'a str,
}

impl<'a> From<&'a str> for RawVersion<'a> {
    fn from(raw: &'a str) -> Self {
        RawVersion { raw }
    }
}

impl<'a> RawVersion<'a> {
    pub(crate) fn from_comment(comment: &Comment<'a>) -> Option<Self> {
        let comment = comment.as_raw();
        if let Some(captures) = RATCHET_COMMENT_PATTERN.captures(comment)
            && let Some(version_match) = captures.get(1)
        {
            Some(version_match.as_str().into())
        } else if let Some(captures) = VERSION_COMMENT_PATTERN.captures(comment)
            && let Some(version_match) = captures.get(1)
        {
            Some(version_match.as_str().into())
        } else {
            None
        }
    }

    pub(crate) fn as_raw(&self) -> &'a str {
        self.raw
    }

    pub(crate) fn as_version(&self) -> Option<Version<'a>> {
        // TODO: Handle "versions" like `name/v1.2.3`.
        // These are somewhat common in GitHub Actions.
        Version::parse(self.raw).ok()
    }
}

static_regex!(
    VERSION_PATTERN,
    r#"(?x)            # verbose mode
        ^                  # start of string
        v?                 # optional 'v' prefix
        (?<major>\d+)      # major version number
        (?:                # non-capturing group for grouping the separator
          \.               # literal dot separator
          (?<minor>\d+)    # minor version number
        )?                 # end of non-capturing group, optional
        (?:                # non-capturing group for grouping the separator
          \.               # literal dot separator
          (?<patch>\d+)    # patch version number
        )?                 # end of non-capturing group, optional
        $                  # end of string
    "#
);

#[derive(Eq)]
pub(crate) struct Version<'a> {
    /// The raw version, exactly as it appears in its source.
    #[allow(dead_code)]
    raw: &'a str,
    major: u64,
    minor: u64,
    patch: u64,
}

impl<'a> Version<'a> {
    /// Parse a version from a string.
    ///
    /// This accepts versions in the form `v1`, `v1.2`, `v1.2.3`, `1`, `1.2`,
    /// or `1.2.3`, where the `v` prefix is optional and the minor and patch
    /// numbers are also optional (defaulting to zero if not present).
    ///
    /// Returns an error on a parse failure, or if any component
    /// is too large to fit in a `u64`.
    pub(crate) fn parse(s: &'a str) -> anyhow::Result<Self> {
        let captures = VERSION_PATTERN
            .captures(s)
            .ok_or_else(|| anyhow::anyhow!("invalid version format: {s}"))?;

        // NOTE: Safe unwrap because the 'major' group is required.
        // Additionally, the only way the parse() can fail is if we're
        // given a valid major number that's too big to fit in a u64.
        let major = captures
            .name("major")
            .expect("impossible: missing required 'major' capture")
            .as_str()
            .parse()
            .or_else(|e| anyhow::bail!("invalid major version in {s}: {e}"))?;

        let minor = captures.name("minor").map_or(Ok(0), |m| {
            m.as_str()
                .parse()
                .or_else(|e| anyhow::bail!("invalid minor version in {s}: {e}"))
        })?;

        let patch = captures.name("patch").map_or(Ok(0), |m| {
            m.as_str()
                .parse()
                .or_else(|e| anyhow::bail!("invalid patch version in {s}: {e}"))
        })?;

        // TODO(ww): Bother rejecting `0.0.0`, leading zeros, etc?

        Ok(Self {
            raw: s,
            major,
            minor,
            patch,
        })
    }

    pub(crate) fn from_comment(comment: &Comment<'a>) -> Option<Self> {
        RawVersion::from_comment(comment).and_then(|rc| rc.as_version())
    }
}

impl Ord for Version<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch))
    }
}

impl PartialOrd for Version<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Version<'_> {
    fn eq(&self, other: &Self) -> bool {
        (self.major, self.minor, self.patch) == (other.major, other.minor, other.patch)
    }
}

#[cfg(test)]
mod tests {
    use crate::models::version::{RATCHET_COMMENT_PATTERN, VERSION_COMMENT_PATTERN};

    use super::Version;

    #[test]
    fn test_version_comment_pattern() {
        let test_cases = vec![
            ("# tag=v2.8.0", Some("v2.8.0")),
            ("# tag=v6-beta", Some("v6-beta")),
            ("# tag=v1.2.3-rc.1", Some("v1.2.3-rc.1")),
            ("# tag=v1.2.3rc.1", Some("v1.2.3rc.1")),
            ("# tag=v6-beta-2", Some("v6-beta-2")),
            ("# tag=release-2024-01", Some("release-2024-01")),
            ("# v2.8.0", Some("v2.8.0")),
            ("# v6-beta", Some("v6-beta")),
            ("# v1.2.3-rc.1", Some("v1.2.3-rc.1")),
            ("# v1.2.3rc1", Some("v1.2.3rc1")),
            ("# v6-beta-2", Some("v6-beta-2")),
            ("# v1.0.0-rc-1", Some("v1.0.0-rc-1")),
            ("# v2.0-preview-3", Some("v2.0-preview-3")),
            ("# tag=2.8.0", Some("2.8.0")),
            ("# version: 2.8.0", Some("2.8.0")),
            ("# version: v1.2.3-rc.1", Some("v1.2.3-rc.1")),
            ("# version: v1.2.3rc.1", Some("v1.2.3rc.1")),
            ("# version: v6-beta-2", Some("v6-beta-2")),
            ("# version: v1.0.0-rc-1", Some("v1.0.0-rc-1")),
            ("# ver=1.0.0", Some("1.0.0")),
            ("# visit the docs", None),
            ("# some other comment", None),
            ("# zizmor: ignore[ref-version-mismatch]", None),
        ];

        for (comment, expected) in test_cases {
            // Test the pattern matching directly
            match (VERSION_COMMENT_PATTERN.captures(comment), expected) {
                (None, None) => (),
                (None, Some(expected)) => {
                    assert!(
                        false,
                        "Got no match in '{comment}', but expected {expected}"
                    )
                }
                (Some(caps), None) => {
                    assert!(false, "Got unexpected match: {caps:?}")
                }
                (Some(_), Some(_)) => (),
            }
        }
    }

    #[test]
    fn test_ratchet_comment_pattern() {
        let test_cases = vec![
            ("# ratchet:actions/checkout@v4", Some("v4")),
            ("# ratchet:actions/checkout@v4.2.2", Some("v4.2.2")),
            ("# ratchet:actions/setup-node@v3.8.2", Some("v3.8.2")),
            ("# ratchet:owner/repo/path@v1.0.0", Some("v1.0.0")),
            ("# ratchet:actions/checkout@4.2.2", Some("4.2.2")),
            // These should NOT match the ratchet pattern
            ("# v4.2.2", None),
            ("# actions/checkout@v4.2.2", None),
            ("# some other comment", None),
        ];

        for (comment, expected) in test_cases {
            match (RATCHET_COMMENT_PATTERN.captures(comment), expected) {
                (None, None) => (),
                (None, Some(expected)) => {
                    panic!("Got no match in '{comment}', but expected {expected}")
                }
                (Some(caps), None) => {
                    panic!("Got unexpected match: {caps:?}")
                }
                (Some(_), Some(_)) => (),
            }
        }
    }

    #[test]
    fn parse_valid_versions() {
        let cases = [
            ("v1", 1, 0, 0),
            ("v1.2", 1, 2, 0),
            ("v1.2.3", 1, 2, 3),
            ("1", 1, 0, 0),
            ("1.2", 1, 2, 0),
            ("1.2.3", 1, 2, 3),
            ("v0.0.1", 0, 0, 1),
            ("0.0.1", 0, 0, 1),
            ("v10.20.30", 10, 20, 30),
            ("10.20.30", 10, 20, 30),
            // Cases that we consider valid for now.
            ("0.0.0", 0, 0, 0),
            ("v0", 0, 0, 0),
            ("v0.0", 0, 0, 0),
            ("0", 0, 0, 0),
            ("0.0", 0, 0, 0),
            ("v000.0.1", 0, 0, 1),
            ("000.0.1", 0, 0, 1),
        ];

        for (input, exp_major, exp_minor, exp_patch) in cases {
            let version = Version::parse(input).unwrap();
            assert_eq!(version.major, exp_major);
            assert_eq!(version.minor, exp_minor);
            assert_eq!(version.patch, exp_patch);
            assert_eq!(version.raw, input);
        }
    }

    #[test]
    fn parse_invalid_versions() {
        let cases = [
            "", "v", "v1.2.3.4", "nonsense", "v1.beta", ".1", ".v1", "v.1", "v1.", "v1.2.",
        ];

        for input in cases {
            assert!(Version::parse(input).is_err(),);
        }
    }

    #[test]
    fn compare_versions() {
        let cases = [
            ("v1", "v1", std::cmp::Ordering::Equal),
            ("v1", "v1.0", std::cmp::Ordering::Equal),
            ("v1", "v1.0.0", std::cmp::Ordering::Equal),
            ("v1.0", "v1.0.0", std::cmp::Ordering::Equal),
            ("v1.2", "v1.2.0", std::cmp::Ordering::Equal),
            ("v1.2.3", "v1.2.3", std::cmp::Ordering::Equal),
            ("v1", "v2", std::cmp::Ordering::Less),
            ("v1.0", "v2.0", std::cmp::Ordering::Less),
            ("v1.0.0", "v2.0.0", std::cmp::Ordering::Less),
            ("v1.2", "v2.0", std::cmp::Ordering::Less),
            ("v1.2.3", "v2.0.0", std::cmp::Ordering::Less),
            ("v1.2", "v1.3", std::cmp::Ordering::Less),
            ("v1.2.3", "v1.3.0", std::cmp::Ordering::Less),
            ("v1.2.3", "v1.2.4", std::cmp::Ordering::Less),
            ("v2", "v1", std::cmp::Ordering::Greater),
            ("v2.0", "v1.0", std::cmp::Ordering::Greater),
            ("v2.0.0", "v1.0.0", std::cmp::Ordering::Greater),
            ("v2.0", "v1.2", std::cmp::Ordering::Greater),
            ("v2.0.0", "v1.2.3", std::cmp::Ordering::Greater),
            ("v1.3", "v1.2", std::cmp::Ordering::Greater),
            ("v1.3.0", "v1.2.3", std::cmp::Ordering::Greater),
            ("v1.2.4", "v1.2.3", std::cmp::Ordering::Greater),
        ];
        for (v1_str, v2_str, expected_ordering) in cases {
            let v1 = Version::parse(v1_str).unwrap();
            let v2 = Version::parse(v2_str).unwrap();
            assert_eq!(v1.cmp(&v2), expected_ordering,);
        }
    }
}
