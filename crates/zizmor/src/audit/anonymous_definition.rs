pub(crate) struct AnonymousDefinition;

use crate::{
    finding::{Confidence, Persona, Severity, location::Locatable as _},
    state::AuditState,
};

use super::{Audit, AuditLoadError, Job, audit_meta};

// Workflows without a name can be hard to find in the GitHub UI, so
// severity is set higher than for Job.
const ANONYMOUS_DEFINITION_WORKFLOW_SEVERITY: Severity = Severity::Low;
const ANONYMOUS_DEFINITION_JOB_SEVERITY: Severity = Severity::Informational;

audit_meta!(
    AnonymousDefinition,
    "anonymous-definition",
    "workflow or action definition without a name"
);

impl Audit for AnonymousDefinition {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError> {
        Ok(Self)
    }

    fn audit_workflow<'doc>(
        &self,
        workflow: &'doc crate::models::workflow::Workflow,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'doc>>> {
        let mut findings = vec![];

        if workflow.name.is_none() {
            findings.push(
                Self::finding()
                    .severity(ANONYMOUS_DEFINITION_WORKFLOW_SEVERITY)
                    .confidence(Confidence::High)
                    .persona(Persona::Pedantic)
                    .add_location(workflow.location().primary())
                    .build(workflow)?,
            );
        }

        for job in workflow.jobs() {
            match job {
                Job::NormalJob(normal) => {
                    if normal.name.is_none() {
                        let location = normal.location().primary();

                        findings.push(
                            Self::finding()
                                .severity(ANONYMOUS_DEFINITION_JOB_SEVERITY)
                                .confidence(Confidence::High)
                                .persona(Persona::Pedantic)
                                .add_location(location)
                                .build(workflow)?,
                        );
                    }
                }
                _ => continue,
            }
        }

        Ok(findings)
    }
}
