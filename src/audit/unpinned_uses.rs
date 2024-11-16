use github_actions_models::workflow::Job;

use crate::finding::{Confidence, Severity};

use super::{AuditState, Finding, Workflow, WorkflowAudit};

pub(crate) struct UnpinnedUses {}

impl WorkflowAudit for UnpinnedUses {
    fn ident() -> &'static str
    where
        Self: Sized,
    {
        "unpinned-uses"
    }

    fn desc() -> &'static str
    where
        Self: Sized,
    {
        "unpinned action reference"
    }

    fn new(_state: AuditState) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {})
    }

    fn audit<'w>(&self, workflow: &'w Workflow) -> anyhow::Result<Vec<Finding<'w>>> {
        let mut findings = vec![];

        for job in workflow.jobs() {
            // No point in checking reusable workflows, since they
            // require a ref pin when used outside of the local repo.
            let Job::NormalJob(_) = *job else {
                continue;
            };

            for step in job.steps() {
                let Some(uses) = step.uses() else {
                    continue;
                };

                if uses.unpinned() {
                    findings.push(
                        Self::finding()
                            .confidence(Confidence::High)
                            .severity(Severity::Informational)
                            .add_location(
                                step.location().with_keys(&["uses".into()]).annotated(
                                    "action is not pinned to a tag, branch, or hash ref",
                                ),
                            )
                            .build(workflow)?,
                    );
                }
            }
        }

        Ok(findings)
    }
}
