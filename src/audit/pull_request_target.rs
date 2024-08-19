use github_actions_models::workflow::event::{BareEvent, OptionalBody};
use github_actions_models::workflow::Trigger;

use crate::finding::{Confidence, Finding, Severity};
use crate::models::Workflow;

pub(crate) fn audit(workflow: &Workflow) -> Vec<Finding> {
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

    findings
}
