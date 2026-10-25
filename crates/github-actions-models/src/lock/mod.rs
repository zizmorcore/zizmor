//! Data models for GitHub Actions workflow lockfiles.
//!
//! Resources:
//! * <https://github.com/github/actions-lockfile>
//! * <https://docs.github.com/en/actions/concepts/security/workflow-dependency-lockfiles>

use indexmap::IndexMap;
use serde::Deserialize;

/// Represents a GitHub Actions workflow lockfile.
#[derive(Deserialize, Debug)]
pub struct Lock {
    /// The lockfile's version.
    pub version: String,

    /// A mapping of workflow path -> pin keys.
    ///
    /// The workflow path is qualified, e.g. `.github/workflows/foo.yml`.
    pub workflows: IndexMap<String, Vec<PinKey>>,

    /// Each pin key's lock state.
    pub dependencies: IndexMap<PinKey, Pin>,
}

#[derive(Deserialize, Debug, Eq, Hash, PartialEq)]
pub struct PinKey(String);

#[derive(Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct Pin {
    /// The GitHub instance that owns and resolves this dependency.
    ///
    /// If absent, this is the "home" host for a GHE tenant, or `github.com` for GitHub.
    pub hostname: Option<String>,

    /// The Git ref the commit was resolved from.
    pub r#ref: String,

    /// The commit that the action/ref resolves to.
    ///
    /// This is in a prefixed form, e.g. `sha1-abcd...`.
    pub commit: String,

    /// The action's owner's numeric ID.
    pub owner_id: usize,

    /// The action's repo's numeric ID.
    pub repo_id: usize,

    /// The action's own direct dependencies.
    ///
    /// These index back into [`Lock::dependencies`].
    #[serde(default)]
    pub uses: Vec<PinKey>,
}
