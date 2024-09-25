//! Audits workflows for usage of self-hosted runners,
//! which are frequently unsafe to use in public repositories
//! due to the potential for persistence between workflow runs.
//!
//! This audit is "pedantic" only, since zizmor can't detect
//! whether self-hosted runners are ephemeral or not.

use crate::AuditConfig;

use anyhow::Result;
use github_actions_models::workflow::{job::RunsOn, Job};

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

        for job in workflow.jobs() {
            let Job::NormalJob(_normal) = *job else {
                continue;
            };
        }

        Ok(results)
    }
}
