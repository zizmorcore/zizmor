use crate::finding::{Confidence, Severity};

use super::{audit_meta, AuditState, Finding, Step, WorkflowAudit};

pub(crate) struct UnpinnedUses {
    state: AuditState,
}

audit_meta!(UnpinnedUses, "unpinned-uses", "unpinned action reference");

impl WorkflowAudit for UnpinnedUses {
    fn new(state: AuditState) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self { state })
    }

    fn audit_step<'w>(&self, step: &Step<'w>) -> anyhow::Result<Vec<Finding<'w>>> {
        let mut findings = vec![];

        let Some(uses) = step.uses() else {
            return Ok(vec![]);
        };

        let (annotation, severity) = if uses.unpinned() {
            (
                "action is not pinned to a tag, branch, or hash ref",
                Severity::Medium,
            )
        } else if uses.unhashed() && self.state.pedantic {
            ("action is not pinned to a hash ref", Severity::Low)
        } else {
            return Ok(vec![]);
        };

        findings.push(
            Self::finding()
                .confidence(Confidence::High)
                .severity(severity)
                .add_location(
                    step.location()
                        .with_keys(&["uses".into()])
                        .annotated(annotation),
                )
                .build(step.workflow())?,
        );

        Ok(findings)
    }
}
