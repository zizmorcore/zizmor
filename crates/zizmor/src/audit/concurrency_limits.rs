use super::{Audit, AuditLoadError, Job, audit_meta};
use crate::finding::location::Locatable as _;
use crate::{
    audit::AuditError,
    config::Config,
    finding::{Confidence, Finding, Persona, Severity},
    models::workflow::Workflow,
    state::AuditState,
};
use github_actions_models::workflow::Concurrency;

pub(crate) struct ConcurrencyLimits;

audit_meta!(
    ConcurrencyLimits,
    "concurrency-limits",
    "insufficient job-level concurrency limits"
);

#[async_trait::async_trait]
impl Audit for ConcurrencyLimits {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError> {
        Ok(Self)
    }

    async fn audit_workflow<'doc>(
        &self,
        workflow: &'doc Workflow,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];
        match &workflow.concurrency {
            Some(Concurrency::Bare(_)) => {
                findings.push(
                    Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::Low)
                        .persona(Persona::Pedantic)
                        .add_location(
                            workflow
                                .location()
                                .primary()
                                .with_keys(["concurrency".into()])
                                .annotated("workflow concurrency is missing cancel-in-progress"),
                        )
                        .build(workflow)?,
                );
            }
            None => {
                for job in workflow.jobs() {
                    let Job::NormalJob(job) = job else {
                        continue;
                    };
                    match &job.concurrency {
                        Some(Concurrency::Bare(_)) => {
                            findings.push(
                                Self::finding()
                                    .confidence(Confidence::High)
                                    .severity(Severity::Low)
                                    .persona(Persona::Pedantic)
                                    .add_location(
                                        job.location()
                                            .primary()
                                            .with_keys(["concurrency".into()])
                                            .annotated(
                                                "job concurrency is missing cancel-in-progress",
                                            ),
                                    )
                                    .build(workflow)?,
                            );
                        }
                        None => {
                            findings.push(
                                Self::finding()
                                    .confidence(Confidence::High)
                                    .severity(Severity::Low)
                                    .persona(Persona::Pedantic)
                                    .add_location(
                                        workflow
                                            .location()
                                            .primary()
                                            .annotated("missing concurrency setting"),
                                    )
                                    .build(workflow)?,
                            );
                        }
                        // NOTE: Per #1302, we don't nag the user if they've explicitly set
                        // `cancel-in-progress: false` or similar. This is like with the
                        // artipacked audit, where `persist-credentials: true` is seen as
                        // a positive signal of user intent.
                        _ => {}
                    }
                }
            }
            // NOTE: Per #1302, we don't nag the user if they've explicitly set
            // `cancel-in-progress: false` or similar. This is like with the
            // artipacked audit, where `persist-credentials: true` is seen as
            // a positive signal of user intent.
            _ => {}
        }

        Ok(findings)
    }
}
