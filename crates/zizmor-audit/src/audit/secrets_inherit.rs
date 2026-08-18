use github_actions_models::workflow::job::Secrets;
use subfeature::Subfeature;

use super::{Audit, AuditLoadError, AuditState};
use crate::audit::AuditError;
use zizmor_core::finding::{Confidence, Severity, location::Locatable as _};

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

    async fn audit_reusable_job<'doc>(
        &self,
        job: &super::ReusableWorkflowCallJob<'doc>,
        _config: &zizmor_config::Config,
    ) -> Result<Vec<super::Finding<'doc>>, AuditError> {
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
                    .severity(Severity::Medium)
                    .build(job)?,
            );
        }

        Ok(findings)
    }
}
