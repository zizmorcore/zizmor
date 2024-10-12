use anyhow::Result;
use github_actions_models::workflow::event::{BareEvent, OptionalBody};
use github_actions_models::workflow::Trigger;

use super::WorkflowAudit;
use crate::finding::{Confidence, Finding, Severity};
use crate::models::Workflow;
use crate::state::State;

pub(crate) struct DangerousTriggers {
    pub(crate) _state: State,
}

impl WorkflowAudit for DangerousTriggers {
    fn ident() -> &'static str {
        "dangerous-triggers"
    }

    fn desc() -> &'static str
    where
        Self: Sized,
    {
        "use of fundamentally insecure workflow trigger"
    }

    fn new(state: State) -> Result<Self> {
        Ok(Self { _state: state })
    }

    fn audit<'w>(&self, workflow: &'w Workflow) -> Result<Vec<Finding<'w>>> {
        let trigger = &workflow.on;

        let has_pull_request_target = match trigger {
            Trigger::BareEvent(event) => *event == BareEvent::PullRequestTarget,
            Trigger::BareEvents(events) => events.contains(&BareEvent::PullRequestTarget),
            Trigger::Events(events) => !matches!(events.pull_request_target, OptionalBody::Missing),
        };

        let has_workflow_run = match trigger {
            Trigger::BareEvent(event) => *event == BareEvent::WorkflowRun,
            Trigger::BareEvents(events) => events.contains(&BareEvent::WorkflowRun),
            Trigger::Events(events) => !matches!(events.workflow_run, OptionalBody::Missing),
        };

        let mut findings = vec![];
        if has_pull_request_target {
            findings.push(
                Self::finding()
                    .confidence(Confidence::Medium)
                    .severity(Severity::High)
                    .add_location(
                        workflow
                            .location()
                            .with_keys(&["on".into()])
                            .annotated("pull_request_target is almost always used insecurely"),
                    )
                    .build(workflow)?,
            );
        }
        if has_workflow_run {
            findings.push(
                Self::finding()
                    .confidence(Confidence::Medium)
                    .severity(Severity::High)
                    .add_location(
                        workflow
                            .location()
                            .with_keys(&["on".into()])
                            .annotated("workflow_run is almost always used insecurely"),
                    )
                    .build(workflow)?,
            );
        }

        Ok(findings)
    }
}
