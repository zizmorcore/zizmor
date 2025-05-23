use std::{collections::HashMap, sync::LazyLock};

use github_actions_models::common::{BasePermission, Permission, Permissions};

use super::{Audit, AuditLoadError, Job, audit_meta};
use crate::apply_yaml_patch;
use crate::models::JobExt as _;
use crate::yaml_patch::YamlPatchOperation;
use crate::{
    AuditState,
    finding::{Confidence, Fix, Persona, Severity, SymbolicLocation},
};

// Subjective mapping of permissions to severities, when given `write` access.
static KNOWN_PERMISSIONS: LazyLock<HashMap<&str, Severity>> = LazyLock::new(|| {
    [
        ("actions", Severity::High),
        ("attestations", Severity::High),
        ("checks", Severity::Medium),
        ("contents", Severity::High),
        ("deployments", Severity::High),
        ("discussions", Severity::Medium),
        ("id-token", Severity::High),
        ("issues", Severity::High),
        ("packages", Severity::High),
        ("pages", Severity::High),
        ("pull-requests", Severity::High),
        ("repository-projects", Severity::Medium),
        ("security-events", Severity::Medium),
        // What does the write permission even do here?
        ("statuses", Severity::Low),
    ]
    .into()
});

audit_meta!(
    ExcessivePermissions,
    "excessive-permissions",
    "overly broad permissions"
);

pub(crate) struct ExcessivePermissions;

impl Audit for ExcessivePermissions {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_workflow<'doc>(
        &self,
        workflow: &'doc crate::models::Workflow,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'doc>>> {
        let mut findings = vec![];

        let all_jobs_have_permissions = workflow
            .jobs()
            .map(|job| match job {
                Job::NormalJob(job) => &job.permissions,
                Job::ReusableWorkflowCallJob(job) => &job.permissions,
            })
            .all(|perm| !matches!(perm, Permissions::Base(BasePermission::Default)));

        let explicit_parent_permissions = !matches!(
            &workflow.permissions,
            Permissions::Base(BasePermission::Default)
        );

        let workflow_is_reusable_only =
            workflow.has_workflow_call() && workflow.has_single_trigger();

        // Top-level permissions are a pedantic finding under the following
        // conditions:
        //
        // 1. The workflow has only one job.
        // 2. All jobs in the workflow have their own explicit permissions.
        // 3. The workflow is reusable and has only one trigger.
        let workflow_finding_persona =
            if workflow.jobs.len() == 1 || all_jobs_have_permissions || workflow_is_reusable_only {
                Persona::Pedantic
            } else {
                Persona::Regular
            };

        // Handle top-level permissions.
        let location = workflow.location().primary();

        for (severity, confidence, perm_location, fix) in
            self.check_workflow_permissions(&workflow.permissions, location)
        {
            let mut finding_builder = Self::finding()
                .severity(severity)
                .confidence(confidence)
                .persona(workflow_finding_persona)
                .add_location(perm_location);

            if let Some(fix) = fix {
                finding_builder = finding_builder.fix(fix);
            }

            findings.push(finding_builder.build(workflow)?);
        }

        for job in workflow.jobs() {
            let (permissions, job_location, job_finding_persona, job_id) = match job {
                Job::NormalJob(job) => {
                    // For normal jobs: if the workflow is reusable-only, we
                    // emit pedantic findings.
                    let persona = if workflow_is_reusable_only {
                        Persona::Pedantic
                    } else {
                        Persona::Regular
                    };

                    (&job.permissions, job.location(), persona, job.id())
                }
                Job::ReusableWorkflowCallJob(job) => {
                    // For reusable jobs: the caller is always responsible for
                    // permissions, so we emit regular findings even if
                    // the workflow is reusable-only.
                    (&job.permissions, job.location(), Persona::Regular, job.id())
                }
            };

            if let Some((severity, confidence, perm_location, fix)) = self.check_job_permissions(
                permissions,
                explicit_parent_permissions,
                job_location.clone(),
                job_id,
            ) {
                let mut finding_builder = Self::finding()
                    .severity(severity)
                    .confidence(confidence)
                    .persona(job_finding_persona)
                    .add_location(job_location)
                    .add_location(perm_location.primary());

                if let Some(fix) = fix {
                    finding_builder = finding_builder.fix(fix);
                }

                findings.push(finding_builder.build(workflow)?);
            }
        }

        Ok(findings)
    }
}

impl ExcessivePermissions {
    fn check_workflow_permissions<'a>(
        &self,
        permissions: &'a Permissions,
        location: SymbolicLocation<'a>,
    ) -> Vec<(Severity, Confidence, SymbolicLocation<'a>, Option<Fix>)> {
        let mut results = vec![];

        match &permissions {
            Permissions::Base(base) => match base {
                BasePermission::Default => results.push((
                    Severity::Medium,
                    Confidence::Medium,
                    location.annotated("default permissions used due to no permissions: block"),
                    Some(Self::create_add_permissions_fix("/permissions".to_string())),
                )),
                BasePermission::ReadAll => results.push((
                    Severity::Medium,
                    Confidence::High,
                    location
                        .with_keys(&["permissions".into()])
                        .annotated("uses read-all permissions"),
                    Some(Self::create_replace_permissions_fix(
                        "/permissions".to_string(),
                        "Replace read-all with specific permissions".to_string(),
                        "Replace 'read-all' with specific permissions or no permissions."
                            .to_string(),
                    )),
                )),
                BasePermission::WriteAll => results.push((
                    Severity::High,
                    Confidence::High,
                    location
                        .with_keys(&["permissions".into()])
                        .annotated("uses write-all permissions"),
                    Some(Self::create_replace_permissions_fix(
                        "/permissions".to_string(),
                        "Replace write-all with specific permissions".to_string(),
                        "Replace 'write-all' with specific permissions or no permissions."
                            .to_string(),
                    )),
                )),
            },
            Permissions::Explicit(perms) => {
                for (name, perm) in perms {
                    if *perm != Permission::Write {
                        continue;
                    }

                    let severity = KNOWN_PERMISSIONS.get(name.as_str()).unwrap_or_else(|| {
                        tracing::warn!("unknown permission: {name}");

                        &Severity::Unknown
                    });

                    results.push((
                        *severity,
                        Confidence::High,
                        location
                            .with_keys(&["permissions".into(), name.as_str().into()])
                            .annotated(format!(
                                "{name}: write is overly broad at the workflow level"
                            )),
                        Some(Self::create_write_to_read_fix(name, "/permissions")),
                    ));
                }
            }
        }

        results
    }

    fn check_job_permissions<'a>(
        &self,
        permissions: &Permissions,
        explicit_parent_permissions: bool,
        location: SymbolicLocation<'a>,
        job_id: &str,
    ) -> Option<(Severity, Confidence, SymbolicLocation<'a>, Option<Fix>)> {
        match permissions {
            Permissions::Base(base) => match base {
                // The job has no explicit permissions, meaning it gets
                // the default $GITHUB_TOKEN *if* the workflow doesn't
                // set any permissions.
                BasePermission::Default if !explicit_parent_permissions => Some((
                    Severity::Medium,
                    Confidence::Medium,
                    location.annotated("default permissions used due to no permissions: block"),
                    Some(Self::create_add_permissions_fix(format!(
                        "/jobs/{}/permissions",
                        job_id
                    ))),
                )),
                BasePermission::Default => None,
                BasePermission::ReadAll => Some((
                    Severity::Medium,
                    Confidence::High,
                    location
                        .with_keys(&["permissions".into()])
                        .annotated("uses read-all permissions"),
                    Some(Self::create_replace_permissions_fix(
                        format!("/jobs/{}/permissions", job_id),
                        "Replace read-all with specific permissions".to_string(),
                        "Replace 'read-all' with specific permissions or no permissions."
                            .to_string(),
                    )),
                )),
                BasePermission::WriteAll => Some((
                    Severity::High,
                    Confidence::High,
                    location
                        .with_keys(&["permissions".into()])
                        .annotated("uses write-all permissions"),
                    Some(Self::create_replace_permissions_fix(
                        format!("/jobs/{}/permissions", job_id),
                        "Replace write-all with specific permissions".to_string(),
                        "Replace 'write-all' with specific permissions or no permissions."
                            .to_string(),
                    )),
                )),
            },
            // In the general case, it's impossible to tell whether a job-level
            // permission block is over-scoped.
            // TODO: We could in theory refine this by collecting minimum permission
            // sets for common actions, but that might be overkill.
            Permissions::Explicit(_) => None,
        }
    }

    /// Create a fix for adding an explicit permissions block
    fn create_add_permissions_fix(path: String) -> Fix {
        // For adding permissions, we need to determine if we're adding to root or to a job
        let (parent_path, key) = if path == "/permissions" {
            // Adding to workflow root
            ("/".to_string(), "permissions".to_string())
        } else {
            // Adding to a job, extract parent path and key
            let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
            if parts.len() >= 3 && parts[parts.len() - 1] == "permissions" {
                // Path like "/jobs/job_id/permissions" -> parent "/jobs/job_id", key "permissions"
                let parent_parts = &parts[0..parts.len() - 1];
                let parent_path = format!("/{}", parent_parts.join("/"));
                (parent_path, "permissions".to_string())
            } else {
                // Fallback to treating the whole path as the key to add at root
                ("/".to_string(), path.trim_start_matches('/').to_string())
            }
        };

        Fix {
            title: "Add explicit permissions block".to_string(),
            description: "Add an explicit permissions block to restrict token permissions."
                .to_string(),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Add {
                path: parent_path,
                key: key,
                value: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
            }]),
        }
    }

    /// Create a fix for replacing permissions with empty object (for read-all/write-all cases)
    fn create_replace_permissions_fix(path: String, title: String, description: String) -> Fix {
        Fix {
            title,
            description,
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Replace {
                path: path,
                value: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
            }]),
        }
    }

    /// Create a fix for changing a specific permission from write to read
    fn create_write_to_read_fix(permission_name: &str, base_path: &str) -> Fix {
        let path = format!("{base_path}/{permission_name}");
        Fix {
            title: format!("Change {permission_name} permission from write to read"),
            description: format!(
                "Change {permission_name} permission from 'write' to 'read' to reduce scope."
            ),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Replace {
                path: path,
                value: serde_yaml::Value::String("read".to_string()),
            }]),
        }
    }
}
