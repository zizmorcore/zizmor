use super::{Audit, AuditLoadError, audit_meta};
use crate::{
    audit::AuditError,
    config::Config,
    finding::{
        Confidence, Finding, Persona, Severity,
        location::Locatable as _,
    },
    models::workflow::JobExt as _,
    state::AuditState,
};

pub(crate) struct TimeoutMinutes;

audit_meta!(
    TimeoutMinutes,
    "timeout-minutes",
    "missing timeout-minutes"
);

#[async_trait::async_trait]
impl Audit for TimeoutMinutes {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError> {
        Ok(Self)
    }

    async fn audit_normal_job<'doc>(
        &self,
        job: &super::NormalJob<'doc>,
        _config: &Config,
    ) -> anyhow::Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        // Check if timeout-minutes is set in the job
        match &job.timeout_minutes {
            None => 'label: {
                // If not, check if it's set in any of the job's steps
                for step in job.steps() {
                    match &step.timeout_minutes {
                        Some(_) => {
                            // If so, the job doesn't need to set it
                            break 'label;
                        }
                        None => {}
                    }
                }
                findings.push(
                    Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::Medium)
                        .persona(Persona::Pedantic)
                        .add_location(
                            job
                                .location()
                                .primary()
                                .annotated("job missing timeout-minutes"),
                        )
                        .build(job.parent())?,
                );
            },
            _ => {}
        }

        Ok(findings)
    }

    async fn audit_step<'doc>(
        &self,
        step: &super::Step<'doc>,
        _config: &Config,
    ) -> anyhow::Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        // Check if timeout-minutes is set in the step
        match &step.timeout_minutes {
            None => 'label: {
                // If not, check if it's set by its parent job
                let job = &step.parent;
                match &job.timeout_minutes {
                    None => {
                        // If not, check if it's set in any of the job's other steps
                        for other_step in job.steps() {
                            match &other_step.timeout_minutes {
                                Some(_) => {
                                    // If so, this job should set it, too
                                    findings.push(
                                        Self::finding()
                                            .confidence(Confidence::High)
                                            .severity(Severity::Medium)
                                            .persona(Persona::Pedantic)
                                            .add_location(
                                                step
                                                    .location()
                                                    .primary()
                                                    .annotated("step missing timeout-minutes"),
                                            )
                                            .build(step)?,
                                    );
                                    break 'label;
                                }
                                None => {}
                            }
                        }
                    },
                    _ => {}
                }
            },
            _ => {}
        }

        Ok(findings)
    }
}
