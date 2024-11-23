use anyhow::Result;
use github_actions_models::workflow::event::{BareEvent, OptionalBody};
use github_actions_models::workflow::Trigger;

use super::{audit_meta, WorkflowAudit};
use crate::finding::{Confidence, Finding, Severity};
use crate::models::Workflow;
use crate::state::AuditState;

pub(crate) struct DangerousTriggers {}

audit_meta!(
    DangerousTriggers,
    "dangerous-triggers",
    "use of fundamentally insecure workflow trigger"
);

impl DangerousTriggers {
    pub(crate) fn has_pull_request_target(&self, workflow: &Workflow) -> bool {
        match &workflow.on {
            Trigger::BareEvent(event) => *event == BareEvent::PullRequestTarget,
            Trigger::BareEvents(events) => events.contains(&BareEvent::PullRequestTarget),
            Trigger::Events(events) => !matches!(events.pull_request_target, OptionalBody::Missing),
        }
    }

    pub(crate) fn has_workflow_run(&self, workflow: &Workflow) -> bool {
        match &workflow.on {
            Trigger::BareEvent(event) => *event == BareEvent::WorkflowRun,
            Trigger::BareEvents(events) => events.contains(&BareEvent::WorkflowRun),
            Trigger::Events(events) => !matches!(events.workflow_run, OptionalBody::Missing),
        }
    }
}

impl WorkflowAudit for DangerousTriggers {
    fn new(_: AuditState) -> Result<Self> {
        Ok(Self {})
    }

    fn audit<'w>(&self, workflow: &'w Workflow) -> Result<Vec<Finding<'w>>> {
        let mut findings = vec![];
        if self.has_pull_request_target(workflow) {
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
        if self.has_workflow_run(workflow) {
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
