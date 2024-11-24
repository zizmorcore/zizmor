use super::{audit_meta, WorkflowAudit};
use crate::finding::{Confidence, Finding, Severity};
use crate::models::Step;
use crate::state::AuditState;
use github_actions_models::workflow::job::StepBody;
use std::ops::Deref;

pub(crate) struct GitHubEnv;

audit_meta!(GitHubEnv, "github-env", "dangerous use of $GITHUB_ENV");

impl GitHubEnv {
    fn uses_github_environment(&self, run_step_body: &str) -> bool {
        // In the future we can improve over this implementation,
        // eventually detecting how $GITHUB_ENV is being used
        // and returning an Option<Confidence> instead

        run_step_body.contains("$GITHUB_ENV") || run_step_body.contains("${GITHUB_ENV}")
    }
}

impl WorkflowAudit for GitHubEnv {
    fn new(_: AuditState) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {})
    }

    fn audit_step<'w>(&self, step: &Step<'w>) -> anyhow::Result<Vec<Finding<'w>>> {
        let mut findings = vec![];

        let workflow = step.workflow();

        let has_dangerous_triggers =
            workflow.has_workflow_run() || workflow.has_pull_request_target();

        if has_dangerous_triggers {
            if let StepBody::Run { run, .. } = &step.deref().body {
                if self.uses_github_environment(run) {
                    findings.push(
                        Self::finding()
                            .severity(Severity::High)
                            .confidence(Confidence::Low)
                            .add_location(step.location().with_keys(&["run".into()]).annotated(
                                "GITHUB_ENV used in the context of a dangerous Workflow trigger",
                            ))
                            .build(step.workflow())?,
                    )
                }
            }
        }

        Ok(findings)
    }
}
