use std::{collections::HashMap, ops::Deref, sync::LazyLock};

use github_actions_models::{
    common::{BasePermission, Permission, Permissions},
    workflow::Job,
};

use super::WorkflowAudit;
use crate::{
    finding::{Confidence, Severity},
    AuditConfig,
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

pub(crate) struct ExcessivePermissions<'a> {
    pub(crate) _config: AuditConfig<'a>,
}

impl<'a> WorkflowAudit<'a> for ExcessivePermissions<'a> {
    fn ident() -> &'static str
    where
        Self: Sized,
    {
        "excessive-permissions"
    }

    fn new(config: AuditConfig<'a>) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self { _config: config })
    }

    fn audit<'w>(
        &mut self,
        workflow: &'w crate::models::Workflow,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'w>>> {
        let mut findings = vec![];
        // Top-level permissions.
        for (severity, confidence, note) in self.check_permissions(&workflow.permissions, None) {
            findings.push(
                Self::finding()
                    .severity(severity)
                    .confidence(confidence)
                    .add_location(workflow.key_location("permissions").annotated(note))
                    .build(workflow)?,
            )
        }

        for job in workflow.jobs() {
            let Job::NormalJob(normal) = job.deref() else {
                continue;
            };

            for (severity, confidence, note) in
                self.check_permissions(&normal.permissions, Some(&workflow.permissions))
            {
                findings.push(
                    Self::finding()
                        .severity(severity)
                        .confidence(confidence)
                        .add_location(job.key_location("permissions").annotated(note))
                        .build(workflow)?,
                )
            }
        }

        Ok(findings)
    }
}

impl<'a> ExcessivePermissions<'a> {
    fn check_permissions(
        &self,
        permissions: &Permissions,
        parent: Option<&Permissions>,
    ) -> Vec<(Severity, Confidence, String)> {
        match permissions {
            Permissions::Base(base) => match base {
                // TODO: Think more about what to do here. Flagging default
                // permissions is likely to be noisy and is annoying to do,
                // since it involves the *absence* of a key in the YAML
                // rather than its presence.
                BasePermission::Default => vec![],
                BasePermission::ReadAll => vec![(
                    Severity::Medium,
                    Confidence::High,
                    "uses read-all permissions, which may grant read access to more resources \
                     than necessary"
                        .into(),
                )],
                BasePermission::WriteAll => vec![(
                    Severity::High,
                    Confidence::High,
                    "uses write-all permissions, which grants destructive access to repository \
                     resources"
                        .into(),
                )],
            },
            Permissions::Explicit(perms) => match parent {
                // In the general case, it's impossible to tell whether a
                // job-level permission block is over-scoped.
                Some(_) => vec![],
                // Top-level permission-blocks should almost never contain
                // write permissions.
                None => {
                    let mut results = vec![];

                    for (name, perm) in perms {
                        if *perm != Permission::Write {
                            continue;
                        }

                        match KNOWN_PERMISSIONS.get(name.as_str()) {
                            Some(sev) => results.push((
                                *sev,
                                Confidence::High,
                                format!(
                                    "{name}: write is overly broad at the workflow level; move to \
                                     the job level"
                                ),
                            )),
                            None => {
                                log::debug!("unknown permission: {name}");

                                results.push((
                                    Severity::Unknown,
                                    Confidence::High,
                                    format!(
                                        "{name}: write is overly broad at the workflow level; \
                                         move to the job level"
                                    ),
                                ))
                            }
                        }
                    }

                    results
                }
            },
        }
    }
}
