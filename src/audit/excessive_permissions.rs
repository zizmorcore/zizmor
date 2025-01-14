use std::{collections::HashMap, ops::Deref, sync::LazyLock};

use github_actions_models::{
    common::{BasePermission, Permission, Permissions},
    workflow::Job,
};

use super::{audit_meta, Audit};
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

        // Top-level permissions are a minor issue if there's only one
        // job in the workflow, since they're equivalent to job-level
        // permissions in that case. Emit only pedantic findings in
        // that case.
        let persona = if workflow.jobs.len() == 1 {
            Persona::Pedantic
        } else {
            Persona::Regular
        };

        // Handle top-level permissions.
        let location = workflow.location().primary();
        let explicit_parent_permissions = !matches!(
            &workflow.permissions,
            Permissions::Base(BasePermission::Default)
        );
        match &workflow.permissions {
            Permissions::Base(base) => match base {
                BasePermission::Default => findings.push(
                    Self::finding()
                        .severity(Severity::Medium)
                        .confidence(Confidence::Medium)
                        .persona(persona)
                        .add_location(
                            location
                                .primary()
                                .annotated("default permissions used due to no permissions: block"),
                        )
                        .build(workflow)?,
                ),
                BasePermission::ReadAll => findings.push(
                    Self::finding()
                        .severity(Severity::Medium)
                        .confidence(Confidence::High)
                        .persona(persona)
                        .add_location(
                            location
                                .primary()
                                .with_keys(&["permissions".into()])
                                .annotated("uses read-all permissions"),
                        )
                        .build(workflow)?,
                ),
                BasePermission::WriteAll => findings.push(
                    Self::finding()
                        .severity(Severity::High)
                        .confidence(Confidence::High)
                        .persona(persona)
                        .add_location(
                            location
                                .primary()
                                .with_keys(&["permissions".into()])
                                .annotated("uses write-all permissions"),
                        )
                        .build(workflow)?,
                ),
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

                    findings.push(
                        Self::finding()
                            .severity(*severity)
                            .confidence(Confidence::High)
                            .persona(persona)
                            .add_location(
                                location
                                    .with_keys(&["permissions".into(), name.as_str().into()])
                                    .primary()
                                    .annotated(format!(
                                        "{name}: write is overly broad at the workflow level"
                                    )),
                            )
                            .build(workflow)?,
                    );
                }
            }
        }

        for job in workflow.jobs() {
            let Job::NormalJob(normal) = job.deref() else {
                continue;
            };

            let job_location = job.location();
            if let Some((severity, confidence, perm_location)) = self.check_job_permissions(
                &normal.permissions,
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
