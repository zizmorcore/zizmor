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

        if workflow.is_reusable_only() {
            // If a workflow is reusable-only, then we expect its calling workflow
            // to manage its concurrency settings. Attempting to manage concurrency
            // in the called workflow results in weird bugs like deadlocks and
            // premature cancellations.
            // See: <https://github.com/zizmorcore/zizmor/issues/1511>
            // See: <https://github.com/orgs/community/discussions/30708>
            return Ok(findings);
        }

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
                // Collect all jobs that are missing concurrency or have incomplete settings
                let mut jobs_missing_concurrency = vec![];
                let mut jobs_missing_cancel_in_progress = vec![];

                for job in workflow.jobs() {
                    let Job::NormalJob(job) = job else {
                        continue;
                    };
                    match &job.concurrency {
                        Some(Concurrency::Bare(_)) => {
                            jobs_missing_cancel_in_progress.push(job);
                        }
                        None => {
                            jobs_missing_concurrency.push(job);
                        }
                        // NOTE: Per #1302, we don't nag the user if they've explicitly set
                        // `cancel-in-progress: false` or similar. This is like with the
                        // artipacked audit, where `persist-credentials: true` is seen as
                        // a positive signal of user intent.
                        _ => {}
                    }
                }

                // Create a single finding for jobs missing cancel-in-progress
                if !jobs_missing_cancel_in_progress.is_empty() {
                    let mut finding_builder = Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::Low)
                        .persona(Persona::Pedantic)
                        .add_location(
                            workflow
                                .location()
                                .primary()
                                .with_keys(["on".into()])
                                .annotated("workflow is missing concurrency setting"),
                        );

                    for job in &jobs_missing_cancel_in_progress {
                        finding_builder = finding_builder.add_location(
                            job.location()
                                .with_keys(["concurrency".into()])
                                .annotated("job concurrency is missing cancel-in-progress"),
                        );
                    }

                    findings.push(finding_builder.build(workflow)?);
                }

                // Create a single finding for jobs missing concurrency entirely
                if !jobs_missing_concurrency.is_empty() {
                    let mut finding_builder = Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::Low)
                        .persona(Persona::Pedantic)
                        .add_location(
                            workflow
                                .location()
                                .primary()
                                .with_keys(["on".into()])
                                .annotated("workflow is missing concurrency setting"),
                        );

                    for job in &jobs_missing_concurrency {
                        finding_builder = finding_builder.add_location(
                            job.location()
                                .annotated("job affected by missing workflow concurrency"),
                        );
                    }

                    findings.push(finding_builder.build(workflow)?);
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
