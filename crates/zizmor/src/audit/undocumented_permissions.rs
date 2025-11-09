use github_actions_models::common::{Permission, Permissions};

use super::{Audit, AuditLoadError, Job, audit_meta};
use crate::audit::AuditError;
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

#[async_trait::async_trait]
impl Audit for UndocumentedPermissions {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_workflow<'doc>(
        &self,
        workflow: &'doc crate::models::workflow::Workflow,
        _config: &crate::config::Config,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, AuditError> {
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
        permissions: &'a Permissions,
        location: SymbolicLocation<'a>,
        workflow: &'a crate::models::workflow::Workflow,
    ) -> Result<Option<crate::finding::Finding<'a>>, AuditError> {
        // Only check explicit permissions blocks
        let Permissions::Explicit(perms) = permissions else {
            return Ok(None);
        };

        if perms.is_empty() {
            return Ok(None);
        }

        // Check each individual permission for documentation
        let mut finding_builder = Self::finding()
            .severity(Severity::Low)
            .confidence(Confidence::High)
            .persona(Persona::Pedantic);

        let base_location = location.clone().primary();
        let mut has_undocumented = false;

        for (perm_name, perm) in perms {
            if perm_name == "contents" && *perm == Permission::Read {
                // Skip "contents: read" as it's common and self-explanatory
                continue;
            }

            let individual_perm_location = base_location
                .clone()
                .with_keys(["permissions".into(), perm_name.as_str().into()]);

            if !self.has_explanatory_comment(&individual_perm_location, workflow)? {
                finding_builder = finding_builder.add_location(
                    individual_perm_location.annotated("needs an explanatory comment"),
                );
                has_undocumented = true;
            }
        }

        // Only create a finding if there are actually undocumented permissions
        if has_undocumented {
            Ok(Some(finding_builder.build(workflow)?))
        } else {
            Ok(None)
        }
    }

    fn has_explanatory_comment(
        &self,
        location: &SymbolicLocation,
        workflow: &crate::models::workflow::Workflow,
    ) -> Result<bool, AuditError> {
        let document = workflow.as_document();

        // Use the concretize API to get a Location with concrete Feature
        let concrete_location = location.clone().concretize(document).map_err(Self::err)?;

        // Check if there are any meaningful comments
        Ok(concrete_location
            .concrete
            .comments
            .iter()
            .any(|comment| comment.is_meaningful()))
    }
}
