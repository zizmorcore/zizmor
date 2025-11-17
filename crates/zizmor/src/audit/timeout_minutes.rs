use anyhow::Result;

use crate::{
    finding::{
        Confidence, Finding, Persona, Severity,
        location::{Locatable as _, SymbolicLocation},
    },
    models::workflow::JobExt as _,
    state::AuditState,
};

use super::{Audit, AuditLoadError, audit_meta};

pub(crate) struct TimeoutMinutes;

impl TimeoutMinutes {
    fn build_finding<'doc>(
        &self,
        location: SymbolicLocation<'doc>,
        annotation: &str,
        job: &super::NormalJob<'doc>,
    ) -> Result<Finding<'doc>> {
        let mut annotated_location = location;
        annotated_location = annotated_location.annotated(annotation);
        Self::finding()
            .severity(Severity::Medium)
            .confidence(Confidence::High)
            .add_location(annotated_location)
            .persona(Persona::Pedantic)
            .build(job.parent())
    }
}

audit_meta!(
    TimeoutMinutes,
    "timeout-minutes",
    "missing timeout-minutes on jobs"
);

impl Audit for TimeoutMinutes {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError> {
        Ok(Self)
    }

    fn audit_normal_job<'doc>(
        &self,
        job: &super::NormalJob<'doc>,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        // Check if timeout-minutes is missing
        if job.timeout_minutes.is_none() {
            findings.push(self.build_finding(
                job.location().primary(),
                "missing timeout-minutes",
                job,
            )?);
        }

        Ok(findings)
    }
}
