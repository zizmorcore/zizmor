//! Shared models and utilities.

use serde::{Deserialize, Deserializer, de::Error as _};

/// Represents a version inside of a `language_version` or `default_language_version` request.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case", rename_all_fields = "snake_case", untagged)]
pub enum VersionRequest {
    #[default]
    Default,
    Request(String),
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case", rename_all_fields = "snake_case", untagged)]
pub enum LanguageVersion {
    /// A raw `language_version` request, e.g. `python: "3.14"`
    Version(VersionRequest),
    /// A language version request along with its toolchain selection preference.
    ///
    /// This is a prek extension; see: <https://prek.j178.dev/reference/configuration/#language_version>
    VersionWithPreference {
        #[serde(default)]
        request: VersionRequest,
        // TODO: This could be strictly modeled as `only-managed`, `managed`,
        // `system`, or `only-system`.
        preference: String,
    },
}

impl Default for LanguageVersion {
    fn default() -> Self {
        Self::Version(VersionRequest::Default)
    }
}

/// A file-selection pattern accepted by pre-commit or prek.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, untagged)]
pub enum FilePattern {
    /// A regular expression, supported by both pre-commit and prek.
    Regex(String),
    /// A prek-specific glob mapping.
    ///
    /// See: <https://prek.j178.dev/reference/configuration/#files>
    Glob {
        /// One or more glob patterns.
        glob: GlobPatterns,
    },
}

/// The accepted forms for a prek `glob` value.
// TODO: `github-actions-models` has the same scalar-or-vector shape in `SoV`.
// Consider moving both types into a shared models crate.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum GlobPatterns {
    /// A single glob pattern.
    Single(String),
    /// Multiple glob patterns.
    Multiple(Vec<String>),
}

pub(crate) fn default_minimum_pre_commit_version() -> String {
    "0".into()
}

pub(crate) fn non_empty_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let vec = Vec::<T>::deserialize(deserializer)?;
    if vec.is_empty() {
        Err(D::Error::custom("expected at least one item in list"))
    } else {
        Ok(vec)
    }
}
