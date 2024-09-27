//! Audits workflows for usage of self-hosted runners,
//! which are frequently unsafe to use in public repositories
//! due to the potential for persistence between workflow runs.
//!
//! This audit is "pedantic" only, since zizmor can't detect
//! whether self-hosted runners are ephemeral or not.

use crate::{
    finding::{Confidence, Severity},
    AuditConfig,
};

use anyhow::Result;
use github_actions_models::{
    common::Expression,
    workflow::{job::RunsOn, Job},
};

use super::WorkflowAudit;

pub(crate) struct SelfHostedRunner<'a> {
    pub(crate) _config: AuditConfig<'a>,
}

impl<'a> SelfHostedRunner<'a> {
    fn runs_on_self_hosted(&self, runs_on: &RunsOn) -> bool {
        todo!()
    }
}

impl<'a> WorkflowAudit<'a> for SelfHostedRunner<'a> {
    fn ident() -> &'static str
    where
        Self: Sized,
    {
        "self-hosted-runner"
    }

    fn desc() -> &'static str
    where
        Self: Sized,
    {
        "runs on a self-hosted runner"
    }

    fn new(config: AuditConfig<'a>) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self { _config: config })
    }

    fn audit<'w>(
        &mut self,
        workflow: &'w crate::models::Workflow,
    ) -> Result<Vec<crate::finding::Finding<'w>>> {
        let mut results = vec![];

        if !self._config.pedantic {
            log::info!("skipping self-hosted runner checks");
            return Ok(results);
        }

        for job in workflow.jobs() {
            let Job::NormalJob(normal) = *job else {
                continue;
            };

            match &normal.runs_on {
                RunsOn::Target(labels) => {
                    let Some(label) = labels.first() else {
                        continue;
                    };

                    if label == "self-hosted" {
                        // All self-hosted runners start with the 'self-hosted'
                        // label followed by any specifiers.
                        results.push(
                            Self::finding()
                                .confidence(Confidence::High)
                                .severity(Severity::Unknown)
                                .add_location(
                                    job.location()
                                        .with_keys(&["runs-on".into()])
                                        .annotated("self-runner used here"),
                                )
                                .build(workflow)?,
                        );
                    } else if let Some(_) = Expression::from_curly(label.to_string()) {
                        // The job might also have its runner expanded via an
                        // expression. Long-term we should perform this evaluation
                        // to increase our confidence, but for now we flag it as
                        // potentially expanding to self-hosted.
                        results.push(
                            Self::finding()
                                .confidence(Confidence::Low)
                                .severity(Severity::Unknown)
                                .add_location(
                                    job.location().with_keys(&["runs-on".into()]).annotated(
                                        "expression may expand into a self-hosted runner",
                                    ),
                                )
                                .build(workflow)?,
                        );
                    }
                }
                // TODO: Figure out how to handle these.
                RunsOn::Group {
                    group: _,
                    labels: _,
                } => continue,
            }
        }

        Ok(results)
    }
}
