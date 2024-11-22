//! Core namespace for zizmor's audits.

use anyhow::Result;

use crate::{
    finding::{Finding, FindingBuilder},
    models::{Job, Step, Workflow},
    state::AuditState,
};

pub(crate) mod artipacked;
pub(crate) mod dangerous_triggers;
pub(crate) mod excessive_permissions;
pub(crate) mod hardcoded_container_credentials;
pub(crate) mod impostor_commit;
pub(crate) mod insecure_commands;
pub(crate) mod known_vulnerable_actions;
pub(crate) mod ref_confusion;
pub(crate) mod self_hosted_runner;
pub(crate) mod template_injection;
pub(crate) mod unpinned_uses;
pub(crate) mod use_trusted_publishing;

pub(crate) trait WorkflowAudit {
    fn ident() -> &'static str
    where
        Self: Sized;

    fn desc() -> &'static str
    where
        Self: Sized;

    fn new(state: AuditState) -> Result<Self>
    where
        Self: Sized;

    fn audit_step<'w>(&self, _step: &Step<'w>) -> Result<Vec<Finding<'w>>> {
        Ok(vec![])
    }

    fn audit_normal_job<'w>(&self, job: &Job<'w>) -> Result<Vec<Finding<'w>>> {
        let mut results = vec![];
        for step in job.steps() {
            results.extend(self.audit_step(&step)?);
        }
        Ok(results)
    }

    fn audit_reusable_job<'w>(&self, _job: &Job<'w>) -> Result<Vec<Finding<'w>>> {
        Ok(vec![])
    }

    fn audit<'w>(&self, workflow: &'w Workflow) -> Result<Vec<Finding<'w>>> {
        let mut results = vec![];

        for job in workflow.jobs() {
            match *job {
                github_actions_models::workflow::Job::NormalJob(_) => {
                    results.extend(self.audit_normal_job(&job)?);
                }
                github_actions_models::workflow::Job::ReusableWorkflowCallJob(_) => {
                    results.extend(self.audit_reusable_job(&job)?);
                }
            }
        }

        Ok(results)
    }

    fn finding<'w>() -> FindingBuilder<'w>
    where
        Self: Sized,
    {
        FindingBuilder::new(Self::ident(), Self::desc())
    }
}
