use anyhow::Result;
use github_actions_models::workflow::event::{BareEvent, OptionalBody};
use github_actions_models::workflow::Trigger;

use crate::finding::{Confidence, Finding, Severity};
use crate::models::{AuditConfig, Workflow};

use super::WorkflowAudit;

pub(crate) struct PullRequestTarget<'a> {
    pub(crate) _config: AuditConfig<'a>,
}

impl<'a> WorkflowAudit<'a> for PullRequestTarget<'a> {
    fn ident() -> &'static str {
        "pull-request-target"
    }

    fn new(config: AuditConfig<'a>) -> Result<Self> {
        Ok(Self { _config: config })
    }

    fn audit<'w>(&self, workflow: &'w Workflow) -> Result<Vec<Finding<'w>>> {
        log::debug!("audit: {} evaluating {}", Self::ident(), &workflow.filename);

        let trigger = &workflow.on;

        let has_pull_request_target = match trigger {
            Trigger::BareEvent(event) => *event == BareEvent::PullRequestTarget,
            Trigger::BareEvents(events) => events.contains(&BareEvent::PullRequestTarget),
            Trigger::Events(events) => !matches!(events.pull_request_target, OptionalBody::Missing),
        };

        let mut findings = vec![];
        if has_pull_request_target {
            findings.push(
                Self::finding()
                    .confidence(Confidence::Medium)
                    .severity(Severity::High)
                    .add_location(workflow.location().annotated(
                        "triggers include pull_request_target, which is almost always used \
                         insecurely",
                    ))
                    .build(&workflow)?,
            );
        }

        log::debug!("audit: {} completed {}", Self::ident(), &workflow.filename);

        Ok(findings)
    }
}
