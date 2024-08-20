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
    const AUDIT_IDENT: &'static str = "pull-request-target";

    fn new(config: AuditConfig<'a>) -> Result<Self> {
        Ok(Self { _config: config })
    }

    async fn audit(&self, workflow: &Workflow) -> Result<Vec<Finding>> {
        let trigger = &workflow.on;

        let has_pull_request_target = match trigger {
            Trigger::BareEvent(event) => *event == BareEvent::PullRequestTarget,
            Trigger::BareEvents(events) => events.contains(&BareEvent::PullRequestTarget),
            Trigger::Events(events) => !matches!(events.pull_request_target, OptionalBody::Missing),
        };

        let mut findings = vec![];
        if has_pull_request_target {
            findings.push(Finding {
                ident: "pull-request-target",
                workflow: workflow.filename.clone(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                job: None,
                steps: vec![],
            })
        }

        Ok(findings)
    }
}
