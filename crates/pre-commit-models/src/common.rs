//! Shared models and utilities.

use serde::{Deserialize, Deserializer, de::Error as _};

/// A file-selection pattern accepted by pre-commit or prek.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, untagged)]
pub enum FilePattern {
    /// A regular expression, supported by both pre-commit and prek.
    Regex(String),
    /// A prek-specific glob mapping.
    Glob {
        /// One or more glob patterns.
        glob: GlobPatterns,
    },
}

impl Default for FilePattern {
    fn default() -> Self {
        Self::Regex(String::new())
    }
}

/// The accepted forms for a prek `glob` value.
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
