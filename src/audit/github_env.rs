use super::{audit_meta, WorkflowAudit};
use crate::audit::dangerous_triggers::DangerousTriggers;
use crate::finding::{Confidence, Finding, Severity};
use crate::models::Step;
use crate::state::AuditState;
use github_actions_models::workflow::job::StepBody;
use std::ops::Deref;

pub(crate) struct GitHubEnv;

audit_meta!(GitHubEnv, "github-env", "dangerous use of $GITHUB_ENV");

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

        let dangerous_triggers_detector = DangerousTriggers {};

        let has_dangerous_triggers = dangerous_triggers_detector.has_workflow_run(workflow)
            || dangerous_triggers_detector.has_pull_request_target(workflow);

        if has_dangerous_triggers {
            if let StepBody::Run { run, .. } = &step.deref().body {
                if run.contains("$GITHUB_ENV") {
                    findings.push(
                        Self::finding()
                            .severity(Severity::High)
                            .confidence(Confidence::High)
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
