//! Pre-commit configuration models, i.e. for `.pre-commit-config.yml`.
//!
//! See: <https://pre-commit.com/#plugins>

use crate::common;
use indexmap::IndexMap;

/// A single pre-commit configuration, containing one or more repositories,
/// each of which may reference one or more hooks.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Config {
    /// A list of repository mappings.
    pub repos: Vec<Repo>,
    /// An optional list of `--hook-types`.
    ///
    /// If not supplied, this defaults to `[pre-commit]`.
    ///
    // TODO: Model that?
    pub default_install_hook_types: Option<Vec<String>>,

    /// A mapping from language to the default language version that
    /// should be used for that language, if a hook does not supply its
    /// own `language_version`.
    #[serde(default)]
    pub default_language_version: IndexMap<String, String>,

    /// The `stages` property for a hook, if a hook does not supply its
    /// own `stages`.
    pub default_stages: Option<Vec<String>>,

    /// The global file include pattern.
    #[serde(default)]
    pub files: String,

    /// The global file exclude pattern.
    #[serde(default)]
    pub exclude: String,

    /// Whether to have pre-commit stop running hooks after the first
    /// failure.
    #[serde(default)]
    pub fail_fast: bool,

    /// The minimum version of pre-commit required.
    #[serde(default = "common::default_minimum_pre_commit_version")]
    pub minimum_pre_commit_version: String,
}

/// A repository, i.e. where to get one or more hooks from.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Repo {
    /// The repository URL to clone, or one of the special forms.
    pub repo: RepoReference,
    /// The Git revision to check out from.
    pub rev: String,
    /// One or more hooks to use.
    pub hooks: Vec<Hook>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoReference {
    /// The hooks' repository is the local one.
    ///
    /// See: <https://pre-commit.com/#repository-local-hooks>
    Local,
    /// The referenced hooks are "meta" hooks.
    ///
    /// See: <https://pre-commit.com/#meta-hooks>
    Meta,
    /// A URL to `git clone`.
    #[serde(untagged)]
    Remote(String),
}

/// A single hook.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Hook {
    /// The ID of the hook to use.
    pub id: String,

    /// An optional additional ID to use when referring to the hook.
    pub alias: Option<String>,

    /// Overrides the name of the hook, as shown during execution.
    pub name: Option<String>,

    /// Overrides the language version for the hook.
    pub language_version: Option<String>,

    /// Overrides the files pattern for the hook.
    pub files: Option<String>,

    /// Overrides the exclude pattern for the hook.
    pub exclude: Option<String>,

    /// Overrides the default file types to run on for the hook (AND).
    pub types: Option<Vec<String>>,

    /// Overrides the default file types to run on for the hook (OR).
    pub types_or: Option<Vec<String>>,

    /// Overrides the types to exclude for the hook.
    pub exclude_types: Option<Vec<String>>,

    /// Optional list of additional args to supply to the hook.
    #[serde(default)]
    pub args: Vec<String>,

    /// Overrides the set of stages to run the hook for.
    pub stages: Option<Vec<String>>,

    /// Additional dependencies to install into the hook's environment.
    #[serde(default)]
    pub additional_dependencies: Vec<String>,

    /// If true, run the hook even when there are no matching files.
    #[serde(default)]
    pub always_run: bool,

    /// If true, force the hook's output to be printed even if it passes.
    #[serde(default)]
    pub verbose: bool,

    /// If present, additionally append the hook's log output to this file.
    #[serde(default)]
    pub log_file: Option<String>,
}
