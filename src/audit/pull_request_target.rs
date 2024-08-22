use anyhow::Result;
use github_actions_models::workflow::event::{BareEvent, OptionalBody};
use github_actions_models::workflow::Trigger;

use crate::finding::{Confidence, Determinations, Finding, Severity};
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

    async fn audit<'w>(&self, workflow: &'w Workflow) -> Result<Vec<Finding<'w>>> {
        log::debug!(
            "audit: {} evaluating {}",
            Self::AUDIT_IDENT,
            &workflow.filename
        );

        let trigger = &workflow.on;

        let has_pull_request_target = match trigger {
            Trigger::BareEvent(event) => *event == BareEvent::PullRequestTarget,
            Trigger::BareEvents(events) => events.contains(&BareEvent::PullRequestTarget),
            Trigger::Events(events) => !matches!(events.pull_request_target, OptionalBody::Missing),
        };

        let mut findings = vec![];
        if has_pull_request_target {
            findings.push(Finding {
                ident: PullRequestTarget::AUDIT_IDENT,
                determinations: Determinations {
                    confidence: Confidence::Medium,
                    severity: Severity::High,
                },
                locations: vec![workflow.location()],
            })
        }

        log::debug!(
            "audit: {} completed {}",
            Self::AUDIT_IDENT,
            &workflow.filename
        );

        Ok(findings)
    }
}
