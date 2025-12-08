//! Enriching/context-bearing wrappers over GitHub Actions models
//! from [`github_actions_models`].

use github_actions_expressions::context;
use github_actions_models::common;
use github_actions_models::common::Env;
use github_actions_models::common::expr::LoE;
use github_actions_models::workflow::job::Strategy;

use crate::finding::location::{Locatable, SymbolicLocation};
use crate::models::inputs::HasInputs;

pub(crate) mod action;
pub(crate) mod coordinate;
pub(crate) mod dependabot;
pub(crate) mod inputs;
pub(crate) mod uses;
pub(crate) mod version;
pub(crate) mod workflow;

pub(crate) trait AsDocument<'a, 'doc> {
    fn as_document(&'a self) -> &'doc yamlpath::Document;
}

/// Common fields between workflow and action step bodies.
pub(crate) enum StepBodyCommon<'s> {
    Uses {
        uses: &'s common::Uses,
        with: &'s Env,
    },
    Run {
        run: &'s str,
        _working_directory: Option<&'s str>,
        _shell: Option<&'s LoE<String>>,
    },
}

/// Common interfaces between workflow and action steps.
pub(crate) trait StepCommon<'doc>: Locatable<'doc> + HasInputs {
    /// Returns the step's index within its parent job or action.
    fn index(&self) -> usize;

    /// Returns whether the given `env.name` environment access is "static,"
    /// i.e. is not influenced by another expression.
    fn env_is_static(&self, ctx: &context::Context) -> bool;

    /// Returns a [`common::Uses`] for this step, if it has one.
    fn uses(&self) -> Option<&'doc common::Uses>;

    /// Returns this step's job's strategy, if present.
    ///
    /// Composite action steps have no strategy.
    fn strategy(&self) -> Option<&Strategy>;

    /// Returns a [`StepBodyCommon`] for this step.
    fn body(&self) -> StepBodyCommon<'doc>;

    /// Returns the document which contains this step.
    fn document(&self) -> &'doc yamlpath::Document;

    /// Returns the effective shell for this step, if it can be determined.
    /// This includes the step's explicit shell, job defaults, workflow defaults,
    /// and runner defaults.
    ///
    /// Returns `None` if the shell cannot be statically determined, including
    /// if the shell is specified via an expression.
    fn shell(&self) -> Option<(&str, SymbolicLocation<'doc>)>;
}

impl<'a, 'doc, T: StepCommon<'doc>> AsDocument<'a, 'doc> for T {
    fn as_document(&'a self) -> &'doc yamlpath::Document {
        self.document()
    }
}
