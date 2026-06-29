use github_actions_models::workflow::job::Secrets;
use subfeature::Subfeature;

use super::{Audit, AuditLoadError, AuditState, Job, Workflow, audit_meta};
use crate::{
    audit::AuditError,
    config::Config,
    finding::{Confidence, Finding, Severity, location::Locatable as _},
};

pub(crate) struct SecretsInherit;

audit_meta!(
    SecretsInherit,
    "secrets-inherit",
    "secrets unconditionally inherited by called workflow"
);

#[async_trait::async_trait]
impl Audit for SecretsInherit {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_workflow<'doc>(
        &self,
        workflow: &'doc Workflow,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        // Callee-side: a reusable workflow declaring `on.workflow_call.secrets: inherit`
        // forces *every* caller to over-scope by handing it all of their secrets.
        if workflow.has_workflow_call_secrets_inherit() {
            findings.push(
                Self::finding()
                    .add_location(
                        workflow
                            .location()
                            .primary()
                            .with_keys(["on".into(), "workflow_call".into(), "secrets".into()])
                            .annotated("this reusable workflow inherits all caller secrets"),
                    )
                    .confidence(Confidence::High)
                    .severity(Severity::Medium)
                    .build(workflow)?,
            );
        }

        // Caller-side: preserve the per-job auditing that the default
        // `audit_workflow` implementation would otherwise perform.
        for job in workflow.jobs() {
            if let Job::ReusableWorkflowCallJob(reusable) = job {
                findings.extend(self.audit_reusable_job(&reusable, config).await?);
            }
        }

        Ok(findings)
    }

    async fn audit_reusable_job<'doc>(
        &self,
        job: &super::ReusableWorkflowCallJob<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        if matches!(job.secrets, Some(Secrets::Inherit)) {
            findings.push(
                Self::finding()
                    .add_location(
                        job.location()
                            .primary()
                            .with_keys(["uses".into()])
                            .subfeature(Subfeature::new(0, job.uses.raw()))
                            .annotated("this reusable workflow"),
                    )
                    .add_location(
                        job.location()
                            .with_keys(["secrets".into()])
                            .annotated("inherits all parent secrets"),
                    )
                    .confidence(Confidence::High)
                    .severity(crate::finding::Severity::Medium)
                    .build(job)?,
            );
        }

        Ok(findings)
    }
}
