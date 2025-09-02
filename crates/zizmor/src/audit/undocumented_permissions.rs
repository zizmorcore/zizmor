use github_actions_models::common::{Permission, Permissions};

use super::{Audit, AuditLoadError, Job, audit_meta};
use crate::finding::location::Locatable as _;
use crate::models::AsDocument;
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
        let Permissions::Explicit(perms) = permissions else {
            return Ok(None);
        };

        if perms.is_empty() {
            return Ok(None);
        }

        // Skip if it only contains "contents: read" which is common and self-explanatory
        if perms.len() == 1
            && perms
                .get("contents")
                .is_some_and(|p| *p == Permission::Read)
        {
            return Ok(None);
        }

        // Check each individual permission for documentation
        let mut undocumented_permissions = Vec::new();
        let base_location = location.clone().primary();

        for (perm_name, _perm_value) in perms {
            let individual_perm_location = base_location
                .clone()
                .with_keys(["permissions".into(), perm_name.as_str().into()]);

            if !self.has_explanatory_comment(&individual_perm_location, workflow) {
                undocumented_permissions.push(perm_name.as_str());
            }
        }

        // Only create a finding if there are actually undocumented permissions
        if !undocumented_permissions.is_empty() {
            let perm_location = base_location.with_keys(["permissions".into()]);

            Ok(Some(
                Self::finding()
                    .severity(Severity::Low)
                    .confidence(Confidence::High)
                    .persona(Persona::Pedantic)
                    .add_location(perm_location.annotated(
                        "consider adding comments to document the purpose of each permission",
                    ))
                    .build(workflow)?,
            ))
        } else {
            Ok(None)
        }
    }

    fn has_explanatory_comment(
        &self,
        location: &SymbolicLocation,
        workflow: &crate::models::workflow::Workflow,
    ) -> bool {
        let document = workflow.as_document();

        // Use the concretize API to get a Location with concrete Feature
        let Ok(concrete_location) = location.clone().concretize(&document) else {
            // If we can't concretize the location, assume it's undocumented to be safe.
            // This handles rare edge cases like malformed routes or yamlpath internal errors.
            return false;
        };

        // Check if there are any comments
        !concrete_location.concrete.comments.is_empty()
    }
}
