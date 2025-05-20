//! Data models for GitHub Actions action definitions.
//!
//! Resources:
//! * [Metadata syntax for GitHub Actions]
//! * [JSON Schema definition for GitHub Actions]
//!
//! [Metadata syntax for GitHub Actions]: https://docs.github.com/en/actions/creating-actions/metadata-syntax-for-github-actions
//! [JSON Schema definition for GitHub Actions]: https://json.schemastore.org/github-action.json

use indexmap::IndexMap;
use serde::Deserialize;

use crate::common::{
    Env, If, Uses,
    expr::{BoE, LoE},
};

/// A GitHub Actions action definition.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Action {
    /// The action's name.
    ///
    /// NOTE: GitHub documents the action's name as required, but experimentally it is not.
    pub name: Option<String>,
    pub author: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub inputs: IndexMap<String, Input>,
    #[serde(default)]
    pub outputs: IndexMap<String, Output>,
    pub runs: Runs,
}

/// An action input.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Input {
    // NOTE: documented as required, but experimentally it is not.
    pub description: Option<String>,
    pub required: Option<bool>,
    pub default: Option<String>,
}

/// An action output.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Output {
    // NOTE: documented as required, but experimentally it is not.
    pub description: Option<String>,
    // NOTE: not optional for composite actions, but this is not worth modeling.
    pub value: Option<String>,
}

/// An action `runs` definition.
///
/// A `runs` definition can be either a JavaScript action, a "composite" action
/// (made up of several constituent actions), or a Docker action.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case", untagged)]
pub enum Runs {
    JavaScript(JavaScript),
    Composite(Composite),
    Docker(Docker),
}

/// A `runs` definition for a JavaScript action.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct JavaScript {
    /// The Node runtime to use for this action. This is one of:
    ///
    /// `"node12" | "node16" | "node20"`
    pub using: String,

    /// The action's entrypoint, as a JavaScript file.
    pub main: String,

    /// An optional script to run, before [`JavaScript::main`].
    pub pre: Option<String>,

    /// An optional expression that triggers [`JavaScript::pre`] if it evaluates to `true`.
    ///
    /// If not present, defaults to `always()`
    pub pre_if: Option<If>,

    /// An optional script to run, after [`JavaScript::main`].
    pub post: Option<String>,

    /// An optional expression that triggers [`JavaScript::post`] if it evaluates to `true`.
    ///
    /// If not present, defaults to `always()`
    pub post_if: Option<If>,
}

/// A `runs` definition for a composite action.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Composite {
    /// Invariant: `"composite"`
    pub using: String,
    /// The individual steps that make up this composite action.
    pub steps: Vec<Step>,
}

/// An individual composite action step.
///
/// This is similar, but not identical to [`crate::workflow::job::Step`].
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Step {
    /// An optional ID for this composite step.
    pub id: Option<String>,

    /// An optional expression that prevents this composite step from running unless it evaluates to `true`.
    pub r#if: Option<If>,

    /// An optional name for this composite step.
    pub name: Option<String>,

    /// An optional boolean or expression that, if `true`, prevents the job from failing when
    /// this composite step fails.
    #[serde(default)]
    pub continue_on_error: BoE,

    /// The `run:` or `uses:` body for this composite step.
    #[serde(flatten)]
    pub body: StepBody,
}

/// The body of a composite action step.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case", untagged)]
pub enum StepBody {
    /// A step that uses another GitHub Action.
    Uses {
        /// The GitHub Action being used.
        #[serde(deserialize_with = "crate::common::step_uses")]
        uses: Uses,

        /// Any inputs to the action being used.
        #[serde(default)]
        with: Env,
    },
    /// A step that runs a command in a shell.
    Run {
        /// The command to run.
        run: String,

        /// The shell to run in.
        shell: String,

        /// An optional environment mapping for this step.
        #[serde(default)]
        env: LoE<Env>,

        /// An optional working directory to run [`RunShell::run`] from.
        working_directory: Option<String>,
    },
}

/// A `runs` definition for a Docker action.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Docker {
    /// Invariant: `"docker"`
    pub using: String,

    /// The Docker image to use.
    pub image: String,

    /// An optional environment mapping for this step.
    #[serde(default)]
    pub env: Env,

    /// An optional Docker entrypoint, potentially overriding the image's
    /// default entrypoint.
    pub entrypoint: Option<String>,

    /// An optional "pre" entrypoint to run, before [`Docker::entrypoint`].
    pub pre_entrypoint: Option<String>,

    /// An optional expression that triggers [`Docker::pre_entrypoint`] if it evaluates to `true`.
    ///
    /// If not present, defaults to `always()`
    pub pre_if: Option<If>,

    /// An optional "post" entrypoint to run, after [`Docker::entrypoint`] or the default
    /// entrypoint.
    pub post_entrypoint: Option<String>,

    /// An optional expression that triggers [`Docker::post_entrypoint`] if it evaluates to `true`.
    ///
    /// If not present, defaults to `always()`
    pub post_if: Option<If>,
}
