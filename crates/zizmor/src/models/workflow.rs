//! GitHub Actions workflow models.
//!
//! These models enrich the models under [`github_actions_models::workflow`],
//! providing higher-level APIs for zizmor to use.

use std::collections::HashMap;

use anyhow::Context as _;
use github_actions_expressions::context::{self, Context};
use github_actions_models::{
    common::{self, expr::LoE},
    workflow::{
        self, Trigger,
        event::{BareEvent, OptionalBody},
        job::{self, RunsOn, StepBody, Strategy},
    },
};
use indexmap::IndexMap;
use terminal_link::Link;

use crate::{
    InputKey,
    finding::location::{Locatable, Route, SymbolicFeature, SymbolicLocation},
    models::{
        AsDocument, StepBodyCommon, StepCommon,
        inputs::{Capability, HasInputs},
    },
    registry::InputError,
    utils::{self, WORKFLOW_VALIDATOR, extract_expressions, from_str_with_validation},
};

/// Represents an entire GitHub Actions workflow.
///
/// This type implements [`std::ops::Deref`] for [`workflow::Workflow`],
/// providing access to the underlying data model.
pub(crate) struct Workflow {
    /// This workflow's unique key into zizmor's runtime registry.
    pub(crate) key: InputKey,
    /// A clickable (OSC 8) link to this workflow, if remote.
    pub(crate) link: Option<String>,
    document: yamlpath::Document,
    inner: workflow::Workflow,
}

impl<'a> AsDocument<'a, 'a> for Workflow {
    fn as_document(&'a self) -> &'a yamlpath::Document {
        &self.document
    }
}

impl std::fmt::Debug for Workflow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{key}", key = self.key)
    }
}

impl std::ops::Deref for Workflow {
    type Target = workflow::Workflow;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl HasInputs for workflow::event::WorkflowCall {
    fn get_input(&self, name: &str) -> Option<Capability> {
        let input = self.inputs.get(name)?;

        Some(match input.r#type {
            workflow::event::WorkflowCallInputType::Boolean => Capability::Fixed,
            workflow::event::WorkflowCallInputType::Number => Capability::Fixed,
            workflow::event::WorkflowCallInputType::String => Capability::Arbitrary,
        })
    }
}

impl HasInputs for workflow::event::WorkflowDispatch {
    fn get_input(&self, name: &str) -> Option<Capability> {
        let input = self.inputs.get(name)?;

        Some(match input.r#type {
            workflow::event::WorkflowDispatchInputType::Boolean => Capability::Fixed,
            workflow::event::WorkflowDispatchInputType::Choice => Capability::Fixed,
            workflow::event::WorkflowDispatchInputType::Environment => Capability::Fixed,
            workflow::event::WorkflowDispatchInputType::Number => Capability::Fixed,
            workflow::event::WorkflowDispatchInputType::String => Capability::Arbitrary,
        })
    }
}

impl HasInputs for Workflow {
    fn get_input(&self, name: &str) -> Option<Capability> {
        let workflow::Trigger::Events(events) = &self.on else {
            return None;
        };

        let wc_cap = {
            if let workflow::event::OptionalBody::Body(wc) = &events.workflow_call {
                wc.get_input(name)
            } else {
                None
            }
        };

        let wd_cap = {
            if let workflow::event::OptionalBody::Body(wd) = &events.workflow_dispatch {
                wd.get_input(name)
            } else {
                None
            }
        };

        match (wc_cap, wd_cap) {
            (Some(cap1), Some(cap2)) => Some(cap1.unify(cap2)),
            (Some(single), None) | (None, Some(single)) => Some(single),
            (None, None) => None,
        }
    }
}

impl Workflow {
    /// Load a workflow from a buffer, with an assigned name.
    pub(crate) fn from_string(contents: String, key: InputKey) -> Result<Self, InputError> {
        let inner = from_str_with_validation(&contents, &WORKFLOW_VALIDATOR)?;

        let document = yamlpath::Document::new(&contents)
            .context("failed to load internal pathing document")?;

        let link = match key {
            InputKey::Local(_) => None,
            InputKey::Remote(_) => {
                // NOTE: InputKey's Display produces a URL, hence `key.to_string()`.
                Some(Link::new(key.presentation_path(), &key.to_string()).to_string())
            }
        };

        Ok(Self {
            link,
            key,
            document,
            inner,
        })
    }

    /// A [`Jobs`] iterator over this workflow's constituent [`Job`]s.
    pub(crate) fn jobs(&self) -> Jobs<'_> {
        Jobs::new(self)
    }

    /// Whether this workflow is triggered by pull_request_target.
    pub(crate) fn has_pull_request_target(&self) -> bool {
        match &self.on {
            Trigger::BareEvent(event) => *event == BareEvent::PullRequestTarget,
            Trigger::BareEvents(events) => events.contains(&BareEvent::PullRequestTarget),
            Trigger::Events(events) => !matches!(events.pull_request_target, OptionalBody::Missing),
        }
    }

    /// Whether this workflow is triggered by workflow_run.
    pub(crate) fn has_workflow_run(&self) -> bool {
        match &self.on {
            Trigger::BareEvent(event) => *event == BareEvent::WorkflowRun,
            Trigger::BareEvents(events) => events.contains(&BareEvent::WorkflowRun),
            Trigger::Events(events) => !matches!(events.workflow_run, OptionalBody::Missing),
        }
    }

    /// Whether this workflow is triggered by workflow_call.
    pub(crate) fn has_workflow_call(&self) -> bool {
        match &self.on {
            Trigger::BareEvent(event) => *event == BareEvent::WorkflowCall,
            Trigger::BareEvents(events) => events.contains(&BareEvent::WorkflowCall),
            Trigger::Events(events) => !matches!(events.workflow_call, OptionalBody::Missing),
        }
    }

    /// Whether this workflow is triggered by exactly one event.
    pub(crate) fn has_single_trigger(&self) -> bool {
        match &self.on {
            Trigger::BareEvent(_) => true,
            Trigger::BareEvents(events) => events.len() == 1,
            Trigger::Events(events) => events.count() == 1,
        }
    }

    /// Returns this workflow's [`SymbolicLocation`].
    ///
    /// NOTE: This is intentionally implemented directly on the `Workflow` type
    /// rather than through the [`Locatable`] trait, since introducing
    /// this through [`Locatable`] would require a split lifetime between
    /// `'self` and `'doc` for just this and [`Action`], i.e. the owning
    /// container types rather than the borrowing subtypes.
    pub fn location(&self) -> SymbolicLocation<'_> {
        SymbolicLocation {
            key: &self.key,
            annotation: "this workflow".to_string(),
            link: None,
            route: Route::new(),
            feature_kind: SymbolicFeature::Normal,
            kind: Default::default(),
        }
    }
}

/// Represents a single "normal" GitHub Actions job.
#[derive(Clone)]
pub(crate) struct NormalJob<'doc> {
    /// The job's unique ID (i.e., its key in the workflow's `jobs:` block).
    id: &'doc str,
    /// The underlying job.
    inner: &'doc job::NormalJob,
    /// The job's parent [`Workflow`].
    parent: &'doc Workflow,
}

impl<'doc> NormalJob<'doc> {
    pub(crate) fn new(id: &'doc str, inner: &'doc job::NormalJob, parent: &'doc Workflow) -> Self {
        Self { id, inner, parent }
    }

    /// An iterator of this job's constituent [`Step`]s.
    pub(crate) fn steps(&self) -> Steps<'doc> {
        Steps::new(self)
    }

    /// Perform feats of heroism to figure of what this job's runner's
    /// default shell is.
    ///
    /// Returns `None` if the job is not a normal job, or if the runner
    /// environment is indeterminate (e.g. controlled by an expression).
    pub(crate) fn runner_default_shell(&self) -> Option<&'static str> {
        match &self.runs_on {
            // The entire runs-on is an expression, so there's nothing we can do.
            LoE::Expr(_) => None,
            LoE::Literal(RunsOn::Group { group: _, labels })
            | LoE::Literal(RunsOn::Target(labels)) => {
                for label in labels {
                    match label.as_str() {
                        // Default self-hosted routing labels.
                        "linux" | "macOS" => return Some("bash"),
                        "windows" => return Some("pwsh"),
                        // Standard GitHub-hosted runners, e.g. `ubuntu-latest`.
                        // We check only the prefix here so that we don't have to keep track
                        // of every possible variation of these runners.
                        l if l.contains("ubuntu-") || l.contains("macos") => return Some("bash"),
                        l if l.contains("windows-") => return Some("pwsh"),
                        _ => continue,
                    }
                }

                None
            }
        }
    }
}

impl<'doc> JobExt<'doc> for NormalJob<'doc> {
    fn id(&self) -> &'doc str {
        self.id
    }

    fn name(&self) -> Option<&'doc str> {
        self.inner.name.as_deref()
    }

    fn parent(&self) -> &'doc Workflow {
        self.parent
    }
}

impl<'doc> std::ops::Deref for NormalJob<'doc> {
    type Target = &'doc job::NormalJob;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Represents a reusable workflow call job.
#[derive(Clone)]
pub(crate) struct ReusableWorkflowCallJob<'doc> {
    /// The job's unique ID (i.e., its key in the workflow's `jobs:` block).
    id: &'doc str,
    /// The underlying job.
    inner: &'doc job::ReusableWorkflowCallJob,
    /// The job's parent [`Workflow`].
    parent: &'doc Workflow,
}

impl<'doc> ReusableWorkflowCallJob<'doc> {
    pub(crate) fn new(
        id: &'doc str,
        inner: &'doc job::ReusableWorkflowCallJob,
        parent: &'doc Workflow,
    ) -> Self {
        Self { id, inner, parent }
    }
}

impl<'doc> JobExt<'doc> for ReusableWorkflowCallJob<'doc> {
    fn id(&self) -> &'doc str {
        self.id
    }

    fn name(&self) -> Option<&'doc str> {
        self.inner.name.as_deref()
    }

    fn parent(&self) -> &'doc Workflow {
        self.parent
    }
}

impl<'doc> std::ops::Deref for ReusableWorkflowCallJob<'doc> {
    type Target = &'doc job::ReusableWorkflowCallJob;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Common behavior across both normal and reusable jobs.
pub(crate) trait JobExt<'doc> {
    /// The job's unique ID (i.e., its key in the workflow's `jobs:` block).
    fn id(&self) -> &'doc str;

    // The job's name, if it has one.
    fn name(&self) -> Option<&'doc str>;

    /// The job's parent [`Workflow`].
    fn parent(&self) -> &'doc Workflow;
}

impl<'doc, T: JobExt<'doc>> Locatable<'doc> for T {
    /// Returns this job's [`SymbolicLocation`].
    fn location(&self) -> SymbolicLocation<'doc> {
        self.parent()
            .location()
            .annotated("this job")
            .with_keys(&["jobs".into(), self.id().into()])
    }

    fn location_with_name(&self) -> SymbolicLocation<'doc> {
        match self.name() {
            Some(_) => self.location().with_keys(&["name".into()]),
            None => self.location(),
        }
    }
}

/// Represents a single GitHub Actions job.
#[derive(Clone)]
pub(crate) enum Job<'doc> {
    NormalJob(NormalJob<'doc>),
    ReusableWorkflowCallJob(ReusableWorkflowCallJob<'doc>),
}

impl<'doc> Job<'doc> {
    fn new(id: &'doc str, inner: &'doc workflow::Job, parent: &'doc Workflow) -> Self {
        match inner {
            workflow::Job::NormalJob(normal) => Job::NormalJob(NormalJob::new(id, normal, parent)),
            workflow::Job::ReusableWorkflowCallJob(reusable) => {
                Job::ReusableWorkflowCallJob(ReusableWorkflowCallJob::new(id, reusable, parent))
            }
        }
    }
}

/// An iterable container for jobs within a [`Workflow`].
pub(crate) struct Jobs<'doc> {
    parent: &'doc Workflow,
    inner: indexmap::map::Iter<'doc, String, workflow::Job>,
}

impl<'doc> Jobs<'doc> {
    fn new(workflow: &'doc Workflow) -> Self {
        Self {
            parent: workflow,
            inner: workflow.jobs.iter(),
        }
    }
}

impl<'doc> Iterator for Jobs<'doc> {
    type Item = Job<'doc>;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.inner.next();

        match item {
            Some((id, job)) => Some(Job::new(id, job, self.parent)),
            None => None,
        }
    }
}

/// Represents an execution Matrix within a Job.
///
/// This type implements [`std::ops::Deref`] for [`job::NormalJob::strategy`], providing
/// access to the underlying data model.
#[derive(Clone)]
pub(crate) struct Matrix<'doc> {
    inner: &'doc LoE<job::Matrix>,
    pub(crate) expanded_values: Vec<(String, String)>,
}

impl<'doc> std::ops::Deref for Matrix<'doc> {
    type Target = &'doc LoE<job::Matrix>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'doc> TryFrom<&'doc NormalJob<'doc>> for Matrix<'doc> {
    type Error = anyhow::Error;

    fn try_from(job: &'doc NormalJob<'doc>) -> Result<Self, Self::Error> {
        let Some(Strategy {
            matrix: Some(inner),
            ..
        }) = &job.strategy
        else {
            anyhow::bail!("job does not define a strategy or interior matrix")
        };

        Ok(Matrix::new(inner))
    }
}

impl<'doc> Matrix<'doc> {
    pub(crate) fn new(inner: &'doc LoE<job::Matrix>) -> Self {
        Self {
            inner,
            expanded_values: Matrix::expand_values(inner),
        }
    }

    /// Checks whether some expanded path leads to an expression
    pub(crate) fn expands_to_static_values(&self, context: &Context) -> bool {
        let expands_to_expression = self.expanded_values.iter().any(|(path, expansion)| {
            // Each expanded value in the matrix might be an expression, or contain
            // one or more expressions (e.g. `foo-${{ bar }}-${{ baz }}`). So we
            // need to check for *any* expression in the expanded value,
            // not just that it starts and ends with the expression delimiters.
            let expansion_contains_expression = !extract_expressions(expansion).is_empty();
            context.matches(path.as_str()) && expansion_contains_expression
        });

        !expands_to_expression
    }

    /// Expands the current Matrix into all possible values
    /// By default, the return is a pair (String, String), in which
    /// the first component is the expanded path (e.g. 'matrix.os') and
    /// the second component is the string representation for the expanded value
    /// (e.g. ubuntu-latest)
    ///
    fn expand_values(inner: &LoE<job::Matrix>) -> Vec<(String, String)> {
        match inner {
            LoE::Expr(_) => vec![],
            LoE::Literal(matrix) => {
                let LoE::Literal(dimensions) = &matrix.dimensions else {
                    return vec![];
                };

                let mut expansions = Matrix::expand_dimensions(dimensions);

                if let LoE::Literal(includes) = &matrix.include {
                    let additional_expansions = includes
                        .iter()
                        .flat_map(Matrix::expand_explicit_rows)
                        .collect::<Vec<_>>();

                    expansions.extend(additional_expansions);
                };

                let LoE::Literal(excludes) = &matrix.exclude else {
                    return expansions;
                };

                let to_exclude = excludes
                    .iter()
                    .flat_map(Matrix::expand_explicit_rows)
                    .collect::<Vec<_>>();

                expansions
                    .into_iter()
                    .filter(|expanded| !to_exclude.contains(expanded))
                    .collect()
            }
        }
    }

    fn expand_explicit_rows(
        include: &IndexMap<String, serde_yaml::Value>,
    ) -> Vec<(String, String)> {
        let normalized = include
            .iter()
            .map(|(k, v)| (k.to_owned(), serde_json::json!(v)))
            .collect::<HashMap<_, _>>();

        Matrix::expand(normalized)
    }

    fn expand_dimensions(
        dimensions: &IndexMap<String, LoE<Vec<serde_yaml::Value>>>,
    ) -> Vec<(String, String)> {
        let normalized = dimensions
            .iter()
            .map(|(k, v)| (k.to_owned(), serde_json::json!(v)))
            .collect::<HashMap<_, _>>();

        Matrix::expand(normalized)
    }

    fn expand(values: HashMap<String, serde_json::Value>) -> Vec<(String, String)> {
        values
            .iter()
            .flat_map(|(key, value)| Matrix::walk_path(value, format!("matrix.{}", key)))
            .collect()
    }

    // Walks recursively a serde_json::Value tree, expanding it into a Vec<(String, String)>
    // according to the inner value of each node
    fn walk_path(tree: &serde_json::Value, current_path: String) -> Vec<(String, String)> {
        match tree {
            serde_json::Value::Null => vec![],

            // In the case of scalars, we just convert the value to a string
            serde_json::Value::Bool(inner) => vec![(current_path, inner.to_string())],
            serde_json::Value::Number(inner) => vec![(current_path, inner.to_string())],
            serde_json::Value::String(inner) => vec![(current_path, inner.to_string())],

            // In the case of an array, we recursively create on expansion pair for each item
            serde_json::Value::Array(inner) => inner
                .iter()
                .flat_map(|value| Matrix::walk_path(value, current_path.clone()))
                .collect(),

            // In the case of an object, we recursively create on expansion pair for each
            // value in the key/value set, using the key to form the expanded path using
            // the dot notation
            serde_json::Value::Object(inner) => inner
                .iter()
                .flat_map(|(key, value)| {
                    let mut new_path = current_path.clone();
                    new_path.push('.');
                    new_path.push_str(key);
                    Matrix::walk_path(value, new_path)
                })
                .collect(),
        }
    }
}

/// Represents a single step in a normal workflow job.
///
/// This type implements [`std::ops::Deref`] for [`workflow::job::Step`], which
/// provides access to the step's actual fields.
#[derive(Clone)]
pub(crate) struct Step<'doc> {
    /// The step's index within its parent job.
    pub(crate) index: usize,
    /// The inner step model.
    inner: &'doc workflow::job::Step,
    /// The parent [`Job`].
    pub(crate) parent: NormalJob<'doc>,
}

impl<'doc> std::ops::Deref for Step<'doc> {
    type Target = &'doc workflow::job::Step;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'doc> Locatable<'doc> for Step<'doc> {
    /// This step's [`SymbolicLocation`].
    fn location(&self) -> SymbolicLocation<'doc> {
        self.parent
            .location()
            .with_keys(&["steps".into(), self.index.into()])
            .annotated("this step")
    }

    fn location_with_name(&self) -> SymbolicLocation<'doc> {
        match self.inner.name {
            Some(_) => self.location().with_keys(&["name".into()]),
            None => self.location(),
        }
    }
}

impl HasInputs for Step<'_> {
    fn get_input(&self, name: &str) -> Option<Capability> {
        self.workflow().get_input(name)
    }
}

impl<'doc> StepCommon<'doc> for Step<'doc> {
    fn index(&self) -> usize {
        self.index
    }

    fn env_is_static(&self, ctx: &context::Context) -> bool {
        utils::env_is_static(ctx, &[&self.env, &self.job().env, &self.workflow().env])
    }

    fn uses(&self) -> Option<&common::Uses> {
        let StepBody::Uses { uses, .. } = &self.inner.body else {
            return None;
        };

        Some(uses)
    }

    fn strategy(&self) -> Option<&Strategy> {
        self.job().strategy.as_ref()
    }

    fn body(&self) -> StepBodyCommon<'doc> {
        match &self.body {
            StepBody::Uses { uses, with } => StepBodyCommon::Uses { uses, with },
            StepBody::Run {
                run,
                working_directory,
                shell,
            } => StepBodyCommon::Run {
                run,
                _working_directory: working_directory.as_deref(),
                _shell: shell.as_deref(),
            },
        }
    }

    fn document(&self) -> &'doc yamlpath::Document {
        self.workflow().as_document()
    }
}

impl<'doc> Step<'doc> {
    fn new(index: usize, inner: &'doc workflow::job::Step, parent: NormalJob<'doc>) -> Self {
        Self {
            index,
            inner,
            parent,
        }
    }

    /// Returns this step's parent [`NormalJob`].
    pub(crate) fn job(&self) -> &NormalJob<'doc> {
        &self.parent
    }

    /// Returns this step's (grand)parent [`Workflow`].
    pub(crate) fn workflow(&self) -> &'doc Workflow {
        self.parent.parent()
    }

    /// Returns the the shell used by this step, or `None`
    /// if the shell can't be statically inferred.
    ///
    /// Invariant: panics if the step is not a `run:` step.
    pub(crate) fn shell(&self) -> Option<&str> {
        let StepBody::Run {
            run: _,
            working_directory: _,
            shell,
        } = &self.inner.body
        else {
            panic!("API misuse: can't call shell() on a uses: step")
        };

        // The steps's own `shell:` takes precedence, followed by the
        // job's default, followed by the entire workflow's default,
        // followed by the runner's default.
        shell
            .as_deref()
            .or_else(|| {
                self.job()
                    .defaults
                    .as_ref()
                    .and_then(|d| d.run.as_ref().and_then(|r| r.shell.as_deref()))
            })
            .or_else(|| {
                self.workflow()
                    .defaults
                    .as_ref()
                    .and_then(|d| d.run.as_ref().and_then(|r| r.shell.as_deref()))
            })
            .or_else(|| self.parent.runner_default_shell())
    }
}

/// An iterable container for steps within a [`Job`].
pub(crate) struct Steps<'doc> {
    inner: std::iter::Enumerate<std::slice::Iter<'doc, github_actions_models::workflow::job::Step>>,
    parent: NormalJob<'doc>,
}

impl<'doc> Steps<'doc> {
    /// Create a new [`Steps`].
    fn new(job: &NormalJob<'doc>) -> Self {
        Self {
            inner: job.steps.iter().enumerate(),
            parent: job.clone(),
        }
    }
}

impl<'doc> Iterator for Steps<'doc> {
    type Item = Step<'doc>;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.inner.next();

        match item {
            Some((idx, step)) => Some(Step::new(idx, step, self.parent.clone())),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::models::{
        inputs::{Capability, HasInputs as _},
        workflow::Workflow,
    };

    #[test]
    fn test_workflow_has_inputs() -> anyhow::Result<()> {
        let workflow = r#"
name: Test Workflow
on:
  workflow_dispatch:
    inputs:
      foo:
        type: string
        required: true
      bar:
        type: boolean
        required: false
  workflow_call:
    inputs:
      foo:
        type: number
        required: true
      bar:
        type: boolean
        required: false

jobs:
  test_job:
    runs-on: ubuntu-latest
    steps:
      - run: true
"#;

        let workflow =
            Workflow::from_string(workflow.into(), crate::InputKey::local("dummy", None)?)?;

        // `foo` unifies in favor of the more permissive capability,
        // which is `Capability::Arbitrary` from the `string` input type
        // under `workflow_dispatch`.
        let foo_cap = workflow.get_input("foo").unwrap();
        assert_eq!(foo_cap, Capability::Arbitrary);

        // `bar` unifies to `Capability::Fixed` since both
        // `workflow_dispatch` and `workflow_call` define it as a boolean.
        let bar_cap = workflow.get_input("bar").unwrap();
        assert_eq!(bar_cap, Capability::Fixed);

        Ok(())
    }
}
