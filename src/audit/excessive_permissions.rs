use std::{collections::HashMap, sync::LazyLock};

use github_actions_models::common::{BasePermission, Permission, Permissions};

use super::{audit_meta, Audit, Job};
use crate::models::JobExt as _;
use crate::{
    finding::{Confidence, Persona, Severity, SymbolicLocation},
    AuditState,
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

pub(crate) struct ExcessivePermissions {
    pub(crate) _config: AuditState,
}

impl Audit for ExcessivePermissions {
    fn new(config: AuditState) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self { _config: config })
    }

    fn audit_workflow<'w>(
        &self,
        workflow: &'w crate::models::Workflow,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'w>>> {
        let mut findings = vec![];

        let all_jobs_have_permissions = workflow
            .jobs()
            .filter_map(|job| {
                let Job::NormalJob(job) = job else {
                    return None;
                };

                Some(&job.permissions)
            })
            .all(|perm| !matches!(perm, Permissions::Base(BasePermission::Default)));

        let explicit_parent_permissions = !matches!(
            &workflow.permissions,
            Permissions::Base(BasePermission::Default)
        );

        // Top-level permissions are a minor issue if there's only one
        // job in the workflow, since they're equivalent to job-level
        // permissions in that case. Emit only pedantic findings in
        // that case.
        // Similarly, if all jobs in the workflow have their own explicit
        // permissions, then any permissions set at the top-level are moot.
        let persona = if workflow.jobs.len() == 1 || all_jobs_have_permissions {
            Persona::Pedantic
        } else {
            Persona::Regular
        };

        // Handle top-level permissions.
        let location = workflow.location().primary();

        for (severity, confidence, perm_location) in
            self.check_workflow_permissions(&workflow.permissions, location)
        {
            findings.push(
                Self::finding()
                    .severity(severity)
                    .confidence(confidence)
                    .persona(persona)
                    .add_location(perm_location)
                    .build(workflow)?,
            );
        }

        for job in workflow.jobs() {
            let Job::NormalJob(job) = &job else {
                continue;
            };

            let job_location = job.location();
            if let Some((severity, confidence, perm_location)) = self.check_job_permissions(
                &job.permissions,
                explicit_parent_permissions,
                job_location.clone(),
            ) {
                findings.push(
                    Self::finding()
                        .severity(severity)
                        .confidence(confidence)
                        .add_location(job_location)
                        .add_location(perm_location.primary())
                        .build(workflow)?,
                )
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
    ) -> Vec<(Severity, Confidence, SymbolicLocation<'a>)> {
        let mut results = vec![];

        match &permissions {
            Permissions::Base(base) => match base {
                BasePermission::Default => results.push((
                    Severity::Medium,
                    Confidence::Medium,
                    location.annotated("default permissions used due to no permissions: block"),
                )),
                BasePermission::ReadAll => results.push((
                    Severity::Medium,
                    Confidence::High,
                    location
                        .with_keys(&["permissions".into()])
                        .annotated("uses read-all permissions"),
                )),
                BasePermission::WriteAll => results.push((
                    Severity::High,
                    Confidence::High,
                    location
                        .with_keys(&["permissions".into()])
                        .annotated("uses write-all permissions"),
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
    ) -> Option<(Severity, Confidence, SymbolicLocation<'a>)> {
        match permissions {
            Permissions::Base(base) => match base {
                // The job has no explicit permissions, meaning it gets
                // the default $GITHUB_TOKEN *if* the workflow doesn't
                // set any permissions.
                BasePermission::Default if !explicit_parent_permissions => Some((
                    Severity::Medium,
                    Confidence::Medium,
                    location.annotated("default permissions used due to no permissions: block"),
                )),
                BasePermission::Default => None,
                BasePermission::ReadAll => Some((
                    Severity::Medium,
                    Confidence::High,
                    location
                        .with_keys(&["permissions".into()])
                        .annotated("uses read-all permissions"),
                )),
                BasePermission::WriteAll => Some((
                    Severity::High,
                    Confidence::High,
                    location
                        .with_keys(&["permissions".into()])
                        .annotated("uses write-all permissions"),
                )),
            },
            // In the general case, it's impossible to tell whether a job-level
            // permission block is over-scoped.
            // TODO: We could in theory refine this by collecting minimum permission
            // sets for common actions, but that might be overkill.
            Permissions::Explicit(_) => None,
        }
    }
}
