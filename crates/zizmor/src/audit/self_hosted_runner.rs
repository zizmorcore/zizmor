//! Audits workflows for usage of self-hosted runners,
//! which are frequently unsafe to use in public repositories
//! due to the potential for persistence between workflow runs.
//!
//! This audit is "auditor" only, since zizmor can't detect
//! whether self-hosted runners are ephemeral or not.

use super::{Audit, AuditLoadError, audit_meta};
use crate::{
    AuditState,
    audit::AuditError,
    finding::{Confidence, Persona, Severity},
};
use crate::{
    config::Config,
    finding::{Finding, location::Locatable as _},
    models::workflow::NormalJob,
};

pub(crate) struct SelfHostedRunner;

audit_meta!(
    SelfHostedRunner,
    "self-hosted-runner",
    "runs on a self-hosted runner"
);

#[async_trait::async_trait]
impl Audit for SelfHostedRunner {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_normal_job<'doc>(
        &self,
        job: &NormalJob<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        match job.is_self_hosted() {
            // Definitely self hosted.
            Some(true) => Ok(vec![
                Self::finding()
                    .confidence(Confidence::High)
                    .severity(Severity::Medium)
                    .persona(Persona::Auditor)
                    .add_location(
                        job.location()
                            .primary()
                            .with_keys(["runs-on".into()])
                            .annotated("self-hosted runner used here"),
                    )
                    .build(job)?,
            ]),
            // Indeterminate.
            None => Ok(vec![
                Self::finding()
                    .confidence(Confidence::Low)
                    .severity(Severity::Medium)
                    .persona(Persona::Auditor)
                    .add_location(
                        job.location()
                            .primary()
                            .with_keys(["runs-on".into()])
                            .annotated("expression may expand into a self-hosted runner"),
                    )
                    .build(job)?,
            ]),
            // Not self hosted.
            Some(false) => Ok(vec![]),
        }
    }
}
