use github_actions_models::common::{Permission, Permissions};

use super::{Audit, AuditLoadError, Job, audit_meta};
use crate::finding::location::Locatable as _;
use crate::{
    AuditState,
    finding::{Confidence, Persona, Severity, location::SymbolicLocation},
};

audit_meta!(
    UndocumentedPermissions,
    "undocumented-permissions",
    "permissions without explanatory comments"
);

pub(crate) struct UndocumentedPermissions;

impl Audit for UndocumentedPermissions {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_workflow<'doc>(
        &self,
        workflow: &'doc crate::models::workflow::Workflow,
        _config: &crate::config::Config,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'doc>>> {
        let mut findings = vec![];

        // Check workflow-level permissions
        if let Some(finding) = self.check_permissions_documentation(
            &workflow.permissions,
            workflow.location(),
            workflow,
        )? {
            findings.push(finding);
        }

        // Check job-level permissions
        for job in workflow.jobs() {
            let (permissions, job_location) = match job {
                Job::NormalJob(job) => (&job.permissions, job.location()),
                Job::ReusableWorkflowCallJob(job) => (&job.permissions, job.location()),
            };

            if let Some(finding) =
                self.check_permissions_documentation(permissions, job_location, workflow)?
            {
                findings.push(finding);
            }
        }

        Ok(findings)
    }
}

impl UndocumentedPermissions {
    fn check_permissions_documentation<'a>(
        &self,
        permissions: &Permissions,
        location: SymbolicLocation<'a>,
        workflow: &'a crate::models::workflow::Workflow,
    ) -> anyhow::Result<Option<crate::finding::Finding<'a>>> {
        // Only check explicit permissions blocks
        match permissions {
            Permissions::Explicit(perms) if !perms.is_empty() => {
                // Check if this permissions block needs documentation
                // Skip if it only contains "contents: read" which is common and self-explanatory
                if perms.len() == 1
                    && perms.get("contents").map_or(false, |p| *p == Permission::Read) {
                    return Ok(None);
                }

                // For explicit permissions, recommend documenting each permission
                let perm_location = location.primary().with_keys(["permissions".into()]);
                Ok(Some(
                    Self::finding()
                        .severity(Severity::Low)
                        .confidence(Confidence::High)
                        .persona(Persona::Pedantic)
                        .add_location(perm_location.annotated(
                            "consider adding comments to document each permission's purpose",
                        ))
                        .build(workflow)?,
                ))
            }
            _ => Ok(None),
        }
    }
}

