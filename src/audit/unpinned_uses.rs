use crate::finding::{Confidence, Severity};

use super::{AuditState, Finding, Step, WorkflowAudit};

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

    fn audit_step<'w>(&self, step: &Step<'w>) -> anyhow::Result<Vec<Finding<'w>>> {
        let mut findings = vec![];

        let Some(uses) = step.uses() else {
            return Ok(vec![]);
        };

        if uses.unpinned() {
            findings.push(
                Self::finding()
                    .confidence(Confidence::High)
                    .severity(Severity::Informational)
                    .add_location(
                        step.location()
                            .with_keys(&["uses".into()])
                            .annotated("action is not pinned to a tag, branch, or hash ref"),
                    )
                    .build(step.workflow())?,
            );
        }

        Ok(findings)
    }
}
