//! Pre-commit hook definition models, i.e. for `.pre-commit-hooks.yml`.
//!
//! See: <https://pre-commit.com/#new-hooks>

use crate::common;

/// One or more hook definitions.
#[derive(Debug, serde::Deserialize)]
pub struct Hooks(pub Vec<HookDefinition>);

/// A single hook definition within a `.pre-commit-hooks.yml` file.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HookDefinition {
    /// The ID of the hook, as use in `.pre-commit-config.yml`.
    pub id: String,

    /// The name of the hook, shown during execution.
    pub name: String,

    /// The entrypoint for the hook, i.e. the executable to run.
    ///
    /// This can also contain arguments that aren't overridable, e.g.
    /// `entry: autopep8 -i`.
    pub entry: String,

    /// The hook's language.
    pub language: String,

    /// The pattern of files to run the hook on.
    pub files: Option<String>,

    /// Excludes files matches by `files` from the hook.
    pub exclude: Option<String>,

    /// Default list of file times to run the hook on (AND).
    pub types: Option<Vec<String>>,

    /// Default list of file times to run the hook on (OR).
    pub types_or: Option<Vec<String>>,

    /// Default list of file times to exclude.
    pub exclude_types: Option<Vec<String>>,

    /// If `true`, run the hook even when there are no matching files.
    #[serde(default)]
    pub always_run: bool,

    /// If `true`, pre-commit will stop running hooks if this hook fails.
    #[serde(default)]
    pub fail_fast: bool,

    /// If `true`, force the hook's output to be printed even if it passes.
    #[serde(default)]
    pub verbose: bool,

    /// If `false`, no filenames will be passed to the hook.
    #[serde(default = "default_true")]
    pub pass_filenames: bool,

    /// If `true`, this hook will execute using a single process instead of in parallel.
    #[serde(default)]
    pub require_serial: bool,

    /// A description of the hook, or `''` if not given.
    #[serde(default)]
    pub description: String,

    /// The default version to use for [`Self::language`].
    #[serde(default = "default_language_version")]
    pub language_version: String,

    /// The minimum version of pre-commit required.
    #[serde(default = "common::default_minimum_pre_commit_version")]
    pub minimum_pre_commit_version: String,

    /// The default list of additional parameters to pass to the hook.
    #[serde(default)]
    pub args: Vec<String>,

    /// The default set of stages to run the hook for.
    pub stages: Option<Vec<String>>,
}

const fn default_true() -> bool {
    true
}

fn default_language_version() -> String {
    "default".into()
}
