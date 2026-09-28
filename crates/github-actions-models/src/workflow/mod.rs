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
    Env, Permissions,
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
/// All three forms expose the same event fields through [`event::Events`].
/// Bare event names become [`event::OptionalBody::Default`], while absent
/// events remain [`event::OptionalBody::Missing`]. The original syntax is
/// retained separately for consumers that need to locate events in the source.
#[derive(Deserialize, Debug)]
#[serde(from = "TriggerRepr")]
pub struct Trigger {
    events: Box<event::Events>,
    syntax: TriggerSyntax,
}

impl Trigger {
    /// The original YAML shape, for locating events in the source document.
    pub fn syntax(&self) -> &TriggerSyntax {
        &self.syntax
    }
}

impl std::ops::Deref for Trigger {
    type Target = event::Events;

    fn deref(&self) -> &Self::Target {
        &self.events
    }
}

/// The source syntax of a [`Trigger`].
///
/// Use the fields on [`event::Events`] to inspect which events trigger a workflow.
/// This type is only needed to map those events back to their source locations.
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
#[serde(rename = "Trigger", untagged)]
enum TriggerRepr {
    // NOTE: `Events` is before `BareEvent` because serde-yaml appears to capture
    // `pull_request:` (an event with a missing body) as equivalent to `on: pull_request`
    // (a bare event).
    Events(Box<event::Events>),
    BareEvent(event::BareEvent),
    BareEvents(Vec<event::BareEvent>),
}

impl From<TriggerRepr> for Trigger {
    fn from(value: TriggerRepr) -> Self {
        match value {
            TriggerRepr::Events(events) => Self {
                events,
                syntax: TriggerSyntax::Mapping,
            },
            TriggerRepr::BareEvent(event) => Self {
                events: Box::new(std::iter::once(&event).collect()),
                syntax: TriggerSyntax::Scalar,
            },
            TriggerRepr::BareEvents(events) => Self {
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

    use super::{Concurrency, Trigger, TriggerSyntax};

    #[test]
    fn test_bare_triggers_normalize() {
        // Cover every supported bare event, including legacy GHES events.
        let names = [
            "branch_protection_rule",
            "check_run",
            "check_suite",
            "create",
            "delete",
            "deployment",
            "deployment_status",
            "discussion",
            "discussion_comment",
            "fork",
            "gollum",
            "image_version",
            "issue_comment",
            "issues",
            "label",
            "merge_group",
            "milestone",
            "page_build",
            "project",
            "project_card",
            "project_column",
            "public",
            "pull_request",
            "pull_request_review",
            "pull_request_review_comment",
            "pull_request_target",
            "push",
            "registry_package",
            "release",
            "repository_dispatch",
            "status",
            "watch",
            "workflow_call",
            "workflow_dispatch",
            "workflow_run",
        ];

        for name in names {
            let mapping: Trigger = yaml_serde::from_str(&format!("{name}:")).unwrap();
            assert!(matches!(mapping.syntax(), TriggerSyntax::Mapping));
            assert_eq!(mapping.count(), 1, "{name}");
            let expected = yaml_serde::to_value(&*mapping).unwrap();

            for yaml in [
                name.to_owned(),
                format!("[{name}]"),
                format!("{name}: null"),
            ] {
                let trigger: Trigger = yaml_serde::from_str(&yaml).unwrap();
                assert_eq!(yaml_serde::to_value(&*trigger).unwrap(), expected, "{yaml}");
            }
        }
    }

    #[test]
    fn test_trigger_presence_and_syntax() {
        let scalar: Trigger = yaml_serde::from_str("push").unwrap();
        assert!(matches!(scalar.syntax(), TriggerSyntax::Scalar));
        assert!(scalar.push.is_present());
        assert!(!scalar.release.is_present());

        let list: Trigger = yaml_serde::from_str("[release, push, release]").unwrap();
        assert_eq!(list.count(), 2);
        assert!(matches!(list.push, OptionalBody::Default));
        assert!(matches!(list.release, OptionalBody::Default));
        let TriggerSyntax::Sequence(names) = list.syntax() else {
            panic!()
        };
        use super::event::BareEvent;
        assert_eq!(
            names,
            &[BareEvent::Release, BareEvent::Push, BareEvent::Release]
        );

        for yaml in ["[]", "{}"] {
            let empty: Trigger = yaml_serde::from_str(yaml).unwrap();
            assert_eq!(empty.count(), 0);
            assert!(!empty.push.is_present());
        }
    }

    #[test]
    fn test_configured_triggers() {
        let trigger: Trigger = yaml_serde::from_str(
            r#"
push:
  branches: [main]
  tags: ['v*']
pull_request: {}
release: null
schedule:
  - cron: '0 0 * * *'
    timezone: America/New_York
"#,
        )
        .unwrap();

        use super::event::{BranchFilters, TagFilters};
        let OptionalBody::Body(push) = &trigger.push else {
            panic!()
        };
        assert!(matches!(&push.branch_filters, Some(BranchFilters::Branches(b)) if b == &["main"]));
        assert!(matches!(&push.tag_filters, Some(TagFilters::Tags(t)) if t == &["v*"]));
        assert!(matches!(trigger.pull_request, OptionalBody::Body(_)));
        assert!(matches!(trigger.release, OptionalBody::Default));
        assert!(matches!(trigger.workflow_call, OptionalBody::Missing));
        let OptionalBody::Body(schedule) = &trigger.schedule else {
            panic!()
        };
        assert_eq!(schedule[0].cron, "0 0 * * *");
        assert_eq!(schedule[0].timezone.as_deref(), Some("America/New_York"));
        assert_eq!(trigger.count(), 4);
    }

    #[test]
    fn test_invalid_triggers() {
        for yaml in [
            "unknown_event",
            "[push, unknown_event]",
            "schedule",
            "[schedule]",
            "42",
            "true",
            "[42]",
            "push: false",
            "push: []",
            "schedule: {}",
            "workflow_run: {}",
            "image_version: {}",
        ] {
            assert!(yaml_serde::from_str::<Trigger>(yaml).is_err(), "{yaml}");
        }
    }

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

        let events: Trigger = yaml_serde::from_str(on).unwrap();

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
