use std::ops::Deref;

use anyhow::Ok;
use github_actions_models::workflow::Job;

use crate::{github_api, models::AuditConfig};

use super::WorkflowAudit;

pub(crate) struct RefConfusion<'a> {
    pub(crate) config: AuditConfig<'a>,
    client: github_api::Client,
}

impl<'a> WorkflowAudit<'a> for RefConfusion<'a> {
    fn ident() -> &'static str
    where
        Self: Sized,
    {
        "ref-confusion"
    }

    fn new(config: AuditConfig<'a>) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            config: config,
            client: github_api::Client::new(&config.gh_token),
        })
    }

    fn audit<'w>(
        &self,
        workflow: &'w crate::models::Workflow,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'w>>> {
        log::debug!("audit: {} evaluating {}", Self::ident(), &workflow.filename);

        let mut findings = vec![];

        for job in workflow.jobs() {
            match job.deref() {
                Job::NormalJob(_) => todo!(),
                Job::ReusableWorkflowCallJob(reusable) => {
                    todo!()
                    // let Some((owner, org, git_ref)) = reusable_workflow_components(&reusable.uses);
                }
            }
        }

        log::debug!("audit: {} completed {}", Self::ident(), &workflow.filename);

        Ok(findings)
    }
}
