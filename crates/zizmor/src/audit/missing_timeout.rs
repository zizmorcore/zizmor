use crate::{
    audit::AuditError,
    config::Config,
    finding::{Confidence, Finding, Persona, Severity, location::Locatable as _},
    models::workflow::NormalJob,
    state::AuditState,
};

use super::{Audit, AuditLoadError, audit_meta};

pub(crate) struct MissingTimeout;

audit_meta!(
    MissingTimeout,
    "missing-timeout",
    "job does not set a timeout"
);

#[async_trait::async_trait]
impl Audit for MissingTimeout {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError> {
        Ok(Self)
    }

    async fn audit_normal_job<'doc>(
        &self,
        job: &NormalJob<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        if job.timeout_minutes.is_none() {
            findings.push(
                Self::finding()
                    .severity(Severity::Low)
                    .confidence(Confidence::High)
                    .persona(Persona::Pedantic)
                    .add_location(
                        job.location()
                            .primary()
                            .annotated("job is missing a timeout-minutes setting"),
                    )
                    .tip("set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes")
                    .build(job)?,
            );
        }

        Ok(findings)
    }
}
