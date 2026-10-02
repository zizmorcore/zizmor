//! Data models for GitHub Actions workflow definitions.
//!
//! Resources:
//! * [Workflow syntax for GitHub Actions]
//! * [JSON Schema definition for workflows]
//!
//! [Workflow Syntax for GitHub Actions]: https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions>
//! [JSON Schema definition for workflows]: https://json.schemastore.org/github-workflow.json

use indexmap::IndexMap;
use serde::Deserialize;

use crate::common::{
    CacheMode, Env, Permissions,
    expr::{BoE, LoE},
};

pub mod event;
pub mod job;

/// A single GitHub Actions workflow.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Workflow {
    pub name: Option<String>,
    pub run_name: Option<String>,
    pub on: Trigger,
    pub cache_mode: Option<CacheMode>,
    #[serde(default)]
    pub permissions: Permissions,
    #[serde(default)]
    pub env: LoE<Env>,
    pub defaults: Option<Defaults>,
    pub concurrency: Option<Concurrency>,
    pub jobs: IndexMap<String, Job>,
}

/// The triggering condition or conditions for a workflow.
///
/// Workflow triggers take three forms:
///
/// 1. A single webhook event name:
///
///     ```yaml
///     on: push
///     ```
/// 2. A list of webhook event names:
///
///     ```yaml
///     on: [push, fork]
///     ```
///
/// 3. A mapping of event names with (optional) configurations:
///
///     ```yaml
///     on:
///       push:
///         branches: [main]
///       pull_request:
///     ```
///
/// All three forms expose the same event fields through [`Self::events`].
#[derive(Deserialize, Debug)]
#[serde(from = "TriggerWire")]
pub struct Trigger {
    /// The normalized events, independent of the original YAML shape.
    pub events: Box<event::Events>,
    /// The original YAML shape, for locating events in the source document.
    pub syntax: TriggerSyntax,
}

/// The source syntax of a [`Trigger`].
#[derive(Debug)]
pub enum TriggerSyntax {
    /// A single event name at `on`.
    Scalar,
    /// Event names in source order, including any repetitions.
    Sequence(Vec<event::BareEvent>),
    /// Event names appear as keys of the `on` mapping.
    Mapping,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TriggerWire {
    // NOTE: `Events` is before `BareEvent` because serde-yaml appears to capture
    // `pull_request:` (an event with a missing body) as equivalent to `on: pull_request`
    // (a bare event).
    Events(Box<event::Events>),
    BareEvent(event::BareEvent),
    BareEvents(Vec<event::BareEvent>),
}

impl From<TriggerWire> for Trigger {
    fn from(value: TriggerWire) -> Self {
        match value {
            TriggerWire::Events(events) => Self {
                events,
                syntax: TriggerSyntax::Mapping,
            },
            TriggerWire::BareEvent(event) => Self {
                events: Box::new(std::iter::once(&event).collect()),
                syntax: TriggerSyntax::Scalar,
            },
            TriggerWire::BareEvents(events) => Self {
                events: Box::new(events.iter().collect()),
                syntax: TriggerSyntax::Sequence(events),
            },
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Defaults {
    pub run: Option<RunDefaults>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct RunDefaults {
    pub shell: Option<LoE<String>>,
    pub working_directory: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all_fields = "kebab-case", untagged)]
pub enum Concurrency {
    Bare(String),
    Rich {
        group: String,
        #[serde(default)]
        cancel_in_progress: BoE,
    },
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case", untagged)]
pub enum Job {
    NormalJob(Box<job::NormalJob>),
    ReusableWorkflowCallJob(Box<job::ReusableWorkflowCallJob>),
}

impl Job {
    /// Returns the optional `name` field common to both reusable and normal
    /// job definitions.
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::NormalJob(job) => job.name.as_deref(),
            Self::ReusableWorkflowCallJob(job) => job.name.as_deref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        common::expr::BoE,
        workflow::event::{OptionalBody, WorkflowCall, WorkflowDispatch},
    };

    use super::{Concurrency, Trigger};

    #[test]
    fn test_concurrency() {
        let bare = "foo";
        let concurrency: Concurrency = yaml_serde::from_str(bare).unwrap();
        assert!(matches!(concurrency, Concurrency::Bare(_)));

        let rich = "group: foo\ncancel-in-progress: true";
        let concurrency: Concurrency = yaml_serde::from_str(rich).unwrap();
        assert!(matches!(
            concurrency,
            Concurrency::Rich {
                group: _,
                cancel_in_progress: BoE::Literal(true)
            }
        ));
    }

    #[test]
    fn test_workflow_triggers() {
        let on = "
  issues:
  workflow_dispatch:
    inputs:
      foo:
        type: string
  workflow_call:
    inputs:
      bar:
        type: string
  pull_request_target:
        ";

        let trigger: Trigger = yaml_serde::from_str(on).unwrap();
        let events = &trigger.events;

        assert!(matches!(events.issues, OptionalBody::Default));
        assert!(matches!(
            events.workflow_dispatch,
            OptionalBody::Body(WorkflowDispatch { .. })
        ));
        assert!(matches!(
            events.workflow_call,
            OptionalBody::Body(WorkflowCall { .. })
        ));
        assert!(matches!(events.pull_request_target, OptionalBody::Default));
    }
}
