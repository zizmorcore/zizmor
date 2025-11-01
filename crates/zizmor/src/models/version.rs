//! Parsing and comparison of versions, as they appear in
//! tags on GitHub Actions `uses:` directives.
//!
//! This implements something similar but not identical to
//! [semantic versioning](https://semver.org/), as GitHub Actions
//! has no structured versioning scheme.

use crate::utils::once::static_regex;

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

    /// Return the raw version string, exactly as it was parsed.
    pub(crate) fn raw(&self) -> &'a str {
        self.raw
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
    use super::Version;

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
            assert_eq!(version.raw(), input);
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
