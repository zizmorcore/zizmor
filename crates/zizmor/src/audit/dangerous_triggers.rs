use github_actions_models::common::Uses;
use github_actions_models::workflow::Job;
use github_actions_models::workflow::job::StepBody;

use super::{Audit, AuditLoadError, audit_meta};
use crate::audit::AuditError;
use crate::config::Config;
use crate::finding::{Confidence, Finding, Severity};
use crate::models::uses::RepositoryUsesExt;
use crate::models::workflow::Workflow;
use crate::state::AuditState;

pub(crate) struct DangerousTriggers;

audit_meta!(
    DangerousTriggers,
    "dangerous-triggers",
    "use of fundamentally insecure workflow trigger"
);

impl DangerousTriggers {
    fn is_labeler_exception(workflow: &Workflow) -> bool {
        // If a workflow has exactly one job, that job has exactly one step,
        // and that step is `actions/labeler`, then we suppress any
        // finding for `pull_request_target`. Our rationale for this is
        // that it's a blessed and presumed-secure use of an otherwise
        // fundamentally insecure trigger.
        if workflow.jobs.len() == 1
            && let Some((_, Job::NormalJob(job))) = workflow.jobs.get_index(0)
            && let [step] = job.steps.as_slice()
            && let StepBody::Uses {
                uses: Uses::Repository(uses),
                ..
            } = &step.body
            && uses.matches("actions/labeler")
        {
            return true;
        }
        false
    }
}

#[async_trait::async_trait]
impl Audit for DangerousTriggers {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError> {
        Ok(Self)
    }

    async fn audit_workflow<'doc>(
        &self,
        workflow: &'doc Workflow,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];
        if workflow.has_pull_request_target() && !Self::is_labeler_exception(workflow) {
            findings.push(
                Self::finding()
                    .confidence(Confidence::Medium)
                    .severity(Severity::High)
                    .add_location(
                        workflow
                            .location()
                            .primary()
                            .with_keys(["on".into()])
                            .annotated("pull_request_target is almost always used insecurely"),
                    )
                    .build(workflow)?,
            );
        }
        if workflow.has_workflow_run() {
            findings.push(
                Self::finding()
                    .confidence(Confidence::Medium)
                    .severity(Severity::High)
                    .add_location(
                        workflow
                            .location()
                            .primary()
                            .with_keys(["on".into()])
                            .annotated("workflow_run is almost always used insecurely"),
                    )
                    .build(workflow)?,
            );
        }

        Ok(findings)
    }
}
