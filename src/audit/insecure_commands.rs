use crate::audit::WorkflowAudit;
use crate::finding::{Confidence, Finding, Severity, SymbolicLocation};
use crate::models::{Steps, Workflow};
use crate::state::AuditState;
use github_actions_models::common::{Env, EnvValue};
use github_actions_models::workflow::job::StepBody;
use github_actions_models::workflow::Job;
use std::ops::Deref;

use super::audit_meta;

pub(crate) struct InsecureCommands;

audit_meta!(
    InsecureCommands,
    "insecure-commands",
    "execution of insecure workflow commands is enabled"
);

impl InsecureCommands {
    fn insecure_commands_allowed<'w>(
        &self,
        workflow: &'w Workflow,
        location: SymbolicLocation<'w>,
    ) -> Finding<'w> {
        Self::finding()
            .confidence(Confidence::High)
            .severity(Severity::High)
            .add_location(
                location
                    .with_keys(&["env".into()])
                    .annotated("insecure commands enabled here"),
            )
            .build(workflow)
            .expect("Cannot build a Finding instance")
    }

    fn has_insecure_commands_enabled(&self, env: &Env) -> bool {
        if let Some(EnvValue::String(value)) = env.get("ACTIONS_ALLOW_UNSECURE_COMMANDS") {
            !value.is_empty()
        } else {
            false
        }
    }

    fn audit_steps<'w>(&self, workflow: &'w Workflow, steps: Steps<'w>) -> Vec<Finding<'w>> {
        steps
            .into_iter()
            .filter(|step| {
                let StepBody::Run {
                    run: _,
                    working_directory: _,
                    shell: _,
                    ref env,
                } = &step.deref().body
                else {
                    return false;
                };

                self.has_insecure_commands_enabled(env)
            })
            .map(|step| self.insecure_commands_allowed(workflow, step.location()))
            .collect()
    }
}

impl WorkflowAudit for InsecureCommands {
    fn new(_: AuditState) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {})
    }

    fn audit<'w>(&self, workflow: &'w Workflow) -> anyhow::Result<Vec<Finding<'w>>> {
        let mut results = vec![];

        if self.has_insecure_commands_enabled(&workflow.env) {
            results.push(self.insecure_commands_allowed(workflow, workflow.location()))
        }

        for job in workflow.jobs() {
            if let Job::NormalJob(normal) = *job {
                if self.has_insecure_commands_enabled(&normal.env) {
                    results.push(self.insecure_commands_allowed(workflow, job.location()))
                }

                results.extend(self.audit_steps(workflow, job.steps()))
            }
        }

        Ok(results)
    }
}
