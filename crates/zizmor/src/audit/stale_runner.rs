//! Audits workflows for usage of stale or removed GitHub Actions runner
//! images.
//!
//! GitHub periodically deprecates and removes runner images. Workflows
//! using removed runners will fail outright; workflows using deprecated
//! ("stale") runners will continue working but should be migrated before
//! end-of-life.

use github_actions_models::{
    common::expr::{ExplicitExpr, LoE},
    workflow::job::RunsOn,
};

use super::{Audit, AuditLoadError, Job, audit_meta};
use crate::finding::location::Locatable as _;
use crate::{
    AuditState,
    audit::AuditError,
    finding::{Confidence, Severity},
};

pub(crate) struct StaleRunner;

audit_meta!(
    StaleRunner,
    "stale-runner",
    "uses a stale or removed GitHub Actions runner"
);

/// Whether a runner label is stale (deprecated) or removed.
enum Staleness {
    /// The runner has been removed and is no longer available.
    Removed,
    /// The runner is deprecated and approaching end-of-life.
    Stale,
}

/// Check whether a runner label is stale or removed.
fn runner_staleness(label: &str) -> Option<Staleness> {
    match label {
        // Removed runners.
        "ubuntu-18.04" | "ubuntu-20.04" | "macos-11" | "macos-12" | "macos-13" | "windows-2019" => {
            Some(Staleness::Removed)
        }

        // Stale (deprecated, approaching end-of-life) runners.
        "ubuntu-22.04" | "macos-14" | "windows-2022" => Some(Staleness::Stale),

        _ => None,
    }
}

fn severity_for(staleness: &Staleness) -> Severity {
    match staleness {
        Staleness::Removed => Severity::High,
        Staleness::Stale => Severity::Medium,
    }
}

fn annotation_for(staleness: &Staleness, label: &str) -> String {
    match staleness {
        Staleness::Removed => {
            format!("runner '{label}' has been removed by GitHub")
        }
        Staleness::Stale => {
            format!("runner '{label}' is deprecated")
        }
    }
}

#[async_trait::async_trait]
impl Audit for StaleRunner {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_workflow<'doc>(
        &self,
        workflow: &'doc crate::models::workflow::Workflow,
        _config: &crate::config::Config,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, AuditError> {
        let mut results = vec![];

        for job in workflow.jobs() {
            let Job::NormalJob(job) = job else {
                continue;
            };

            match &job.runs_on {
                LoE::Literal(RunsOn::Target(labels)) => {
                    for label in labels {
                        if let Some(staleness) = runner_staleness(label) {
                            results.push(
                                Self::finding()
                                    .confidence(Confidence::High)
                                    .severity(severity_for(&staleness))
                                    .add_location(
                                        job.location()
                                            .primary()
                                            .with_keys(["runs-on".into()])
                                            .annotated(annotation_for(&staleness, label)),
                                    )
                                    .build(workflow)?,
                            );
                        } else if ExplicitExpr::from_curly(label).is_some() {
                            results.push(
                                Self::finding()
                                    .confidence(Confidence::Low)
                                    .severity(Severity::Medium)
                                    .add_location(
                                        job.location()
                                            .primary()
                                            .with_keys(["runs-on".into()])
                                            .annotated(
                                                "expression may expand to a \
                                                 stale runner",
                                            ),
                                    )
                                    .build(workflow)?,
                            );
                        }
                    }
                }
                LoE::Literal(RunsOn::Group { .. }) => {
                    // Runner groups are user-managed; nothing to flag.
                }
                LoE::Expr(exp) => {
                    let Some(matrix) = job.matrix() else {
                        results.push(
                            Self::finding()
                                .confidence(Confidence::Low)
                                .severity(Severity::Medium)
                                .add_location(
                                    job.location()
                                        .primary()
                                        .with_keys(["runs-on".into()])
                                        .annotated(
                                            "expression may expand to a \
                                             stale runner",
                                        ),
                                )
                                .build(workflow)?,
                        );
                        continue;
                    };

                    for expansion in matrix.expansions().iter() {
                        if exp.as_bare() != expansion.path {
                            continue;
                        }
                        let Some(staleness) = runner_staleness(&expansion.value) else {
                            continue;
                        };
                        results.push(
                            Self::finding()
                                .confidence(Confidence::High)
                                .severity(severity_for(&staleness))
                                .add_location(
                                    job.location()
                                        .with_keys(["strategy".into()])
                                        .annotated(annotation_for(&staleness, &expansion.value)),
                                )
                                .add_location(
                                    job.location()
                                        .primary()
                                        .with_keys(["runs-on".into()])
                                        .annotated(
                                            "expression may expand to \
                                             a stale runner",
                                        ),
                                )
                                .build(workflow)?,
                        );
                    }
                }
            }
        }

        Ok(results)
    }
}
