//! Audits workflows for usage of self-hosted runners,
//! which are frequently unsafe to use in public repositories
//! due to the potential for persistence between workflow runs.
//!
//! This audit is "auditor" only, since zizmor can't detect
//! whether self-hosted runners are ephemeral or not.

use super::{Audit, AuditLoadError, audit_meta};
use crate::config::Config;
use crate::finding::Finding;
use crate::finding::location::Locatable as _;
use crate::models::workflow::runners::{Runner, RunnerEvidence};
use crate::models::workflow::{JobCommon as _, NormalJob};
use crate::{
    AuditState,
    audit::AuditError,
    finding::{Confidence, Persona, Severity},
};
use std::collections::HashSet;
use std::ops::Deref as _;
use std::sync::LazyLock;

pub(crate) struct SelfHostedRunner;

audit_meta!(
    SelfHostedRunner,
    "self-hosted-runner",
    "runs on a self-hosted runner"
);

// https://docs.github.com/en/actions/reference/runners/github-hosted-runners
static KNOWN_GITHUB_HOSTED_RUNNERS: LazyLock<HashSet<String>> = LazyLock::new(|| {
    include_str!("../../data/github-hosted-runners.txt")
        .lines()
        .filter(|line| !line.is_empty())
        .map(|runner| runner.trim().to_string())
        .collect::<HashSet<_>>()
});

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
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let well_known_runners = KNOWN_GITHUB_HOSTED_RUNNERS.deref();
        let included_runners = &config.self_hosted_runner_config.deny_runners;
        let excluded_groups = &config.self_hosted_runner_config.allow_groups;

        let self_hosted_runners = job
            .runners(well_known_runners, included_runners, excluded_groups)
            .filter(|runner| match runner {
                Runner::SelfHosted { .. } => true,
                Runner::Indeterminate {
                    self_hosted_evidence,
                    ..
                } => *self_hosted_evidence,
                _ => false,
            })
            .collect::<Vec<_>>();

        let mut findings = Vec::new();

        for runner in self_hosted_runners {
            match runner {
                Runner::SelfHosted {
                    location,
                    evidence,
                    from_matrix,
                } => match evidence {
                    RunnerEvidence::ClassicSentinel
                    | RunnerEvidence::ExplicitlyFlagged => {
                        let finding_builder = Self::finding()
                            .confidence(Confidence::High)
                            .severity(Severity::Medium)
                            .persona(Persona::Auditor)
                            .add_location(
                                job.location()
                                    .primary()
                                    .with_keys(["runs-on".into()])
                                    .annotated("self-hosted runner used here"),
                            );

                        if from_matrix {
                            findings.push(
                                finding_builder
                                    .add_location(
                                        location
                                            .with_keys(["strategy".into()])
                                            .annotated("matrix declares self-hosted runner"),
                                    )
                                    .build(job.parent())?,
                            );
                        } else {
                            findings.push(finding_builder.build(job.parent())?);
                        };
                    }
                    RunnerEvidence::RunnerGroup => findings.push(
                        Self::finding()
                            .confidence(Confidence::High)
                            .severity(Severity::Medium)
                            .persona(Persona::Auditor)
                            .add_location(
                                job.location()
                                    .primary()
                                    .with_keys(["runs-on".into()])
                                    .annotated("runner group used here"),
                            )
                            .build(job.parent())?,
                    ),
                },
                Runner::Indeterminate {
                    location,
                    from_matrix,
                    ..
                } => {
                    let finding_builder = Self::finding()
                        .confidence(Confidence::Low)
                        .severity(Severity::Medium)
                        .persona(Persona::Auditor)
                        .add_location(
                            job.location()
                                .primary()
                                .with_keys(["runs-on".into()])
                                .annotated("expression may expand into a self-hosted runner"),
                        );

                    if from_matrix {
                        findings.push(
                            finding_builder
                                .add_location(
                                    location
                                        .with_keys(["strategy".into()])
                                        .annotated("matrix may use self-hosted runners"),
                                )
                                .build(job.parent())?,
                        );
                    } else {
                        findings.push(finding_builder.build(job.parent())?);
                    };
                }
                _ => {
                    // should we trace here?
                }
            }
        }

        Ok(findings)
    }
}
