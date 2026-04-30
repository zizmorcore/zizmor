use std::{collections::HashMap, sync::LazyLock};

use github_actions_models::common::{BasePermission, Permission, Permissions, Uses};
use indexmap::IndexMap;

use super::{Audit, AuditLoadError, Job, audit_meta};
use crate::audit::AuditError;
use crate::finding::location::Locatable as _;
use crate::finding::{Fix, FixDisposition};
use crate::models::StepCommon as _;
use crate::models::workflow::NormalJob;
use crate::{
    AuditState,
    finding::{Confidence, Persona, Severity, location::SymbolicLocation},
};
use yamlpatch::{Op, Patch};

/// Type alias for an action knowledge base: action slug → scope → minimum permission.
///
/// Keys are `"owner/repo"` or `"owner/repo/subpath"` (lowercase, no `@version`).
/// An empty inner map means the action is known to require no special token permissions.
type ActionKb = HashMap<String, HashMap<String, Permission>>;

/// Built-in action knowledge base, loaded from `data/action-permissions.json` at compile time.
///
/// Absent actions cause inference to return [`PermissionInference::Unknown`], so an entry
/// with an empty map is always better than no entry (it lets inference continue for other steps).
static ACTION_PERMISSIONS: LazyLock<ActionKb> = LazyLock::new(|| {
    serde_json::from_slice(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/action-permissions.json"
    )))
    .expect("internal error: action-permissions.json is not valid JSON")
});

/// A map of permission scope → minimum required permission level.
type PermissionMap = IndexMap<String, Permission>;

/// Subjective mapping of write-capable permission scopes to severity.
///
/// Only scopes where `write` access has meaningful security impact are listed.
/// Scopes marked `Low` have unclear or limited real-world impact from `write`.
static WRITE_SCOPE_SEVERITIES: LazyLock<HashMap<&str, Severity>> = LazyLock::new(|| {
    [
        ("actions", Severity::High),
        ("artifact-metadata", Severity::Medium),
        ("attestations", Severity::High),
        ("checks", Severity::Medium),
        ("contents", Severity::High),
        ("deployments", Severity::High),
        ("discussions", Severity::Medium),
        ("id-token", Severity::High),
        ("issues", Severity::High),
        // GitHub docs are unclear on what `models: write` enables; defaulting to Low.
        ("models", Severity::Low),
        ("packages", Severity::High),
        ("pages", Severity::High),
        ("pull-requests", Severity::High),
        ("repository-projects", Severity::Medium),
        ("security-events", Severity::Medium),
        // `statuses: write` only sets commit status checks; limited privilege escalation risk.
        ("statuses", Severity::Low),
    ]
    .into()
});

/// Outcome of attempting to infer minimum required permissions for a job.
enum PermissionInference {
    /// Minimum permissions computed from all `uses:` steps in the job.
    Known(PermissionMap),
    /// At least one `uses:` step references an action absent from the KB;
    /// we cannot produce a precise minimum.
    Unknown,
}

/// Merge `new` into `current`, keeping the higher of the two (`None < Read < Write`).
fn merge_permission(current: &mut Permission, new: Permission) {
    *current = (*current).max(new);
}

/// Attempt to infer the minimum GITHUB_TOKEN permissions required by a job.
///
/// Known `uses:` steps contribute their required permissions; unknown actions
/// or Docker/local `uses:` immediately return [`PermissionInference::Unknown`].
/// `run:` steps are skipped, so the result may under-approximate real usage.
/// All generated fixes carry [`FixDisposition::Unsafe`] to signal this.
fn infer_job_permissions(job: &NormalJob<'_>) -> PermissionInference {
    let mut required = PermissionMap::new();

    for step in job.steps() {
        let Some(uses) = step.uses() else {
            // run: step — skip; we can't infer permissions from shell scripts.
            continue;
        };

        let Uses::Repository(repo_uses) = uses else {
            // Docker (`docker://…`) or local (`./.github/actions/…`) uses —
            // we can't look these up in the KB, treat as unknown.
            return PermissionInference::Unknown;
        };

        // Build lookup key: "owner/repo" or "owner/repo/subpath", lowercase.
        let key = match repo_uses.subpath() {
            Some(sub) => format!("{}/{}", repo_uses.slug(), sub).to_lowercase(),
            None => repo_uses.slug().to_lowercase(),
        };

        let Some(perms) = ACTION_PERMISSIONS.get(&key) else {
            // Unknown action — cannot infer minimum permissions.
            return PermissionInference::Unknown;
        };

        for (scope, perm) in perms {
            let entry = required.entry(scope.clone()).or_insert(Permission::None);
            merge_permission(entry, *perm);
        }
    }

    PermissionInference::Known(required)
}

/// Build a `serde_yaml::Value` from a `PermissionMap`.
///
/// An empty map produces an empty mapping (`{}`).
fn permissions_to_yaml(perms: &PermissionMap) -> serde_yaml::Value {
    let map: serde_yaml::Mapping = perms
        .iter()
        .map(|(scope, perm)| {
            let s = match perm {
                Permission::Read => "read",
                Permission::Write => "write",
                Permission::None => "none",
            };
            (
                serde_yaml::Value::String(scope.clone()),
                serde_yaml::Value::String(s.into()),
            )
        })
        .collect();
    serde_yaml::Value::Mapping(map)
}

audit_meta!(
    ExcessivePermissions,
    "excessive-permissions",
    "overly broad permissions"
);

pub(crate) struct ExcessivePermissions;

#[async_trait::async_trait]
impl Audit for ExcessivePermissions {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError> {
        Ok(Self)
    }

    async fn audit_workflow<'doc>(
        &self,
        workflow: &'doc crate::models::workflow::Workflow,
        _config: &crate::config::Config,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, AuditError> {
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
            let mut builder = Self::finding()
                .severity(severity)
                .confidence(confidence)
                .persona(workflow_finding_persona)
                .add_location(perm_location);

            if let Some(fix) = fix {
                builder = builder.fix(fix);
            }

            findings.push(builder.build(workflow)?);
        }

        for job in workflow.jobs() {
            let (permissions, job_location, job_finding_persona, inference) = match job {
                Job::NormalJob(job) => {
                    // For normal jobs: if the workflow is reusable-only, we
                    // emit pedantic findings.
                    let persona = if workflow_is_reusable_only {
                        Persona::Pedantic
                    } else {
                        Persona::Regular
                    };

                    let inference = infer_job_permissions(&job);
                    (&job.permissions, job.location(), persona, inference)
                }
                Job::ReusableWorkflowCallJob(job) => {
                    // For reusable jobs: the caller is always responsible for
                    // permissions, so we emit regular findings even if
                    // the workflow is reusable-only.
                    //
                    // Permission inference is not possible here: the steps of the
                    // called workflow are defined externally and are not visible
                    // to the static analyser at this point.
                    (
                        &job.permissions,
                        job.location(),
                        Persona::Regular,
                        PermissionInference::Unknown,
                    )
                }
            };

            if let Some((severity, confidence, perm_location, fix)) = self.check_job_permissions(
                permissions,
                explicit_parent_permissions,
                job_location.clone(),
                inference,
            ) {
                let mut builder = Self::finding()
                    .severity(severity)
                    .confidence(confidence)
                    .persona(job_finding_persona)
                    .add_location(job_location)
                    .add_location(perm_location.primary());

                if let Some(fix) = fix {
                    builder = builder.fix(fix);
                }

                findings.push(builder.build(workflow)?);
            }
        }

        Ok(findings)
    }
}

impl ExcessivePermissions {
    /// Build a result tuple for replacing a `read-all`/`write-all` permission.
    ///
    /// Extracted to reduce boilerplate in [`check_workflow_permissions`] and [`check_job_permissions`].
    fn make_replace_fix_result<'a>(
        severity: Severity,
        annotation: &'static str,
        title: String,
        perm_loc: SymbolicLocation<'a>,
        value: serde_yaml::Value,
    ) -> (Severity, Confidence, SymbolicLocation<'a>, Option<Fix<'a>>) {
        (
            severity,
            Confidence::High,
            perm_loc.clone().annotated(annotation),
            Some(Fix {
                title,
                key: perm_loc.key,
                disposition: FixDisposition::Unsafe,
                patches: vec![Patch {
                    route: perm_loc.route,
                    operation: Op::Replace(value),
                }],
            }),
        )
    }

    fn check_workflow_permissions<'a>(
        &self,
        permissions: &'a Permissions,
        location: SymbolicLocation<'a>,
    ) -> Vec<(Severity, Confidence, SymbolicLocation<'a>, Option<Fix<'a>>)> {
        let mut results = vec![];

        match &permissions {
            Permissions::Base(base) => match base {
                BasePermission::Default => results.push((
                    Severity::Medium,
                    Confidence::Medium,
                    location
                        .clone()
                        .annotated("default permissions used due to no permissions: block"),
                    Some(Fix {
                        title: "Add `permissions: {}` to restrict GITHUB_TOKEN permissions".into(),
                        key: location.key,
                        disposition: FixDisposition::Unsafe,
                        patches: vec![Patch {
                            route: location.route.clone(),
                            operation: Op::Add {
                                key: "permissions".into(),
                                value: serde_yaml::Value::Mapping(Default::default()),
                            },
                        }],
                    }),
                )),
                BasePermission::ReadAll | BasePermission::WriteAll => {
                    let (severity, base_str, annotation) = match base {
                        BasePermission::WriteAll => {
                            (Severity::High, "write-all", "uses write-all permissions")
                        }
                        _ => (Severity::Medium, "read-all", "uses read-all permissions"),
                    };
                    let perm_loc = location.with_keys(["permissions".into()]);
                    results.push(Self::make_replace_fix_result(
                        severity,
                        annotation,
                        format!("Replace `{base_str}` with empty permissions block"),
                        perm_loc,
                        serde_yaml::Value::Mapping(Default::default()),
                    ))
                }
            },
            Permissions::Explicit(perms) => {
                for (name, perm) in perms {
                    if *perm != Permission::Write {
                        continue;
                    }

                    let severity = WRITE_SCOPE_SEVERITIES
                        .get(name.as_str())
                        .unwrap_or_else(|| {
                            tracing::warn!("unknown permission: {name}");

                            &Severity::Medium
                        });

                    let perm_loc = location
                        .clone()
                        .with_keys(["permissions".into(), name.as_str().into()]);
                    results.push((
                        *severity,
                        Confidence::High,
                        perm_loc.clone().annotated(format!(
                            "{name}: write is overly broad at the workflow level"
                        )),
                        // No auto-fix: the correct fix is to move write permissions
                        // to the specific jobs that need them, which requires knowing
                        // the job structure. Users must resolve this manually.
                        None,
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
        inference: PermissionInference,
    ) -> Option<(Severity, Confidence, SymbolicLocation<'a>, Option<Fix<'a>>)> {
        match permissions {
            Permissions::Base(base) => match base {
                // The job has no explicit permissions, meaning it gets
                // the default $GITHUB_TOKEN *if* the workflow doesn't
                // set any permissions.
                BasePermission::Default if !explicit_parent_permissions => {
                    let (title, value) = fix_title_and_value(
                        "Add",
                        "permissions: {}",
                        "Add minimum required permissions to restrict GITHUB_TOKEN",
                        &inference,
                    );
                    Some((
                        Severity::Medium,
                        Confidence::Medium,
                        location
                            .clone()
                            .annotated("default permissions used due to no permissions: block"),
                        Some(Fix {
                            title,
                            key: location.key,
                            disposition: FixDisposition::Unsafe,
                            patches: vec![Patch {
                                route: location.route.clone(),
                                operation: Op::Add {
                                    key: "permissions".into(),
                                    value,
                                },
                            }],
                        }),
                    ))
                }
                BasePermission::Default => None,
                base @ (BasePermission::ReadAll | BasePermission::WriteAll) => {
                    let (severity, base_str, annotation) = match base {
                        BasePermission::WriteAll => {
                            (Severity::High, "write-all", "uses write-all permissions")
                        }
                        _ => (Severity::Medium, "read-all", "uses read-all permissions"),
                    };
                    let fallback_rest = format!("`{base_str}` with empty permissions block");
                    let precise_title =
                        format!("Replace `{base_str}` with minimum required permissions");
                    let perm_loc = location.with_keys(["permissions".into()]);
                    let (title, value) =
                        fix_title_and_value("Replace", &fallback_rest, &precise_title, &inference);
                    Some(Self::make_replace_fix_result(
                        severity, annotation, title, perm_loc, value,
                    ))
                }
            },
            // In the general case, it's impossible to tell whether a job-level
            // permission block is over-scoped.
            Permissions::Explicit(_) => None,
        }
    }
}

/// Choose fix title and YAML value from inference: precise when known non-empty,
/// fallback `"{verb} {rest}"` with `{}` value otherwise.
fn fix_title_and_value(
    fallback_verb: &str,
    fallback_rest: &str,
    precise_title: &str,
    inference: &PermissionInference,
) -> (String, serde_yaml::Value) {
    match inference {
        PermissionInference::Known(map) if !map.is_empty() => {
            (precise_title.into(), permissions_to_yaml(map))
        }
        _ => (
            format!("{fallback_verb} {fallback_rest}"),
            serde_yaml::Value::Mapping(Default::default()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config,
        models::{AsDocument, workflow::Workflow},
        registry::input::InputKey,
        state::AuditState,
    };

    async fn run_audit(yaml: &str, check: impl FnOnce(&Workflow, &[crate::finding::Finding])) {
        let key = InputKey::local("fakegroup".into(), "test.yml", None::<&str>);
        let workflow = Workflow::from_string(yaml.to_string(), key).unwrap();
        let state = AuditState::default();
        let audit = ExcessivePermissions::new(&state).unwrap();
        let findings = audit.audit_workflow(&workflow, &Config::default()).await.unwrap();
        check(&workflow, &findings);
    }

    fn fix_source(workflow: &Workflow, findings: &[crate::finding::Finding]) -> String {
        let finding = findings
            .iter()
            .find(|f| !f.fixes.is_empty())
            .expect("no fixable finding");
        finding.fixes[0].apply(workflow.as_document()).unwrap().source().to_string()
    }

    const WORKFLOW_READ_ALL: &str = r#"
on: push
name: Test
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"#;

    const WORKFLOW_WRITE_ALL: &str = r#"
on: push
name: Test
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"#;

    const WORKFLOW_DEFAULT_PERMISSIONS: &str = r#"
on: push
name: Test
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"#;

    const JOB_READ_ALL: &str = r#"
on: push
name: Test
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: read-all
    steps:
      - run: echo hello
"#;

    const JOB_WRITE_ALL_KNOWN_ACTIONS: &str = r#"
on: push
name: Test
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
      - uses: github/codeql-action/analyze@v3
"#;

    const JOB_WRITE_ALL_UNKNOWN_ACTION: &str = r#"
on: push
name: Test
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - uses: actions/checkout@v4
      - uses: some-unknown-org/mystery-action@v1
"#;

    #[tokio::test]
    async fn workflow_read_all_fix_replaces_with_empty_mapping() {
        run_audit(WORKFLOW_READ_ALL, |wf, findings| {
            assert_eq!(
                fix_source(wf, findings),
                "\non: push\nname: Test\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n"
            );
        }).await;
    }

    #[tokio::test]
    async fn workflow_write_all_fix_replaces_with_empty_mapping() {
        run_audit(WORKFLOW_WRITE_ALL, |wf, findings| {
            assert_eq!(
                fix_source(wf, findings),
                "\non: push\nname: Test\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n"
            );
        }).await;
    }

    #[tokio::test]
    async fn workflow_default_permissions_fix_adds_empty_block() {
        run_audit(WORKFLOW_DEFAULT_PERMISSIONS, |wf, findings| {
            if findings.iter().any(|f| !f.fixes.is_empty()) {
                assert_eq!(
                    fix_source(wf, findings),
                    "\non: push\nname: Test\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\npermissions: {}\n"
                );
            }
        }).await;
    }

    #[tokio::test]
    async fn explicit_write_at_workflow_level_has_no_autofix() {
        // Explicit write at workflow level: no auto-fix because the correct
        // remediation requires moving the permission to the specific job(s)
        // that need it, which requires knowing the job structure.
        let yaml = r#"
on: push
name: Test
permissions:
  contents: write
  issues: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"#;
        run_audit(yaml, |_wf, findings| {
            assert!(!findings.is_empty(), "expected findings for explicit write");
            assert!(
                findings.iter().all(|f| f.fixes.is_empty()),
                "expected no auto-fix for explicit write at workflow level"
            );
        }).await;
    }

    #[tokio::test]
    async fn job_read_all_fix_replaces_with_empty_mapping() {
        run_audit(JOB_READ_ALL, |wf, findings| {
            assert_eq!(
                fix_source(wf, findings),
                "\non: push\nname: Test\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions: {}\n    steps:\n      - run: echo hello\n"
            );
        }).await;
    }

    #[tokio::test]
    async fn job_write_all_known_actions_fix_infers_minimum_permissions() {
        run_audit(JOB_WRITE_ALL_KNOWN_ACTIONS, |wf, findings| {
            let finding = findings
                .iter()
                .find(|f| !f.fixes.is_empty())
                .expect("expected a finding with a fix");
            assert!(
                finding.fixes[0].title.contains("minimum required"),
                "expected precise fix title, got: {}",
                finding.fixes[0].title
            );
            assert_eq!(
                finding.fixes[0].apply(wf.as_document()).unwrap().source(),
                "\non: push\nname: Test\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n      security-events: write\n    steps:\n      - uses: actions/checkout@v4\n      - uses: github/codeql-action/init@v3\n      - uses: github/codeql-action/analyze@v3\n"
            );
        }).await;
    }

    #[tokio::test]
    async fn job_write_all_unknown_action_fix_replaces_with_empty_mapping() {
        // When a job uses an unknown action, the fix falls back to `{}`.
        run_audit(JOB_WRITE_ALL_UNKNOWN_ACTION, |wf, findings| {
            assert_eq!(
                fix_source(wf, findings),
                "\non: push\nname: Test\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions: {}\n    steps:\n      - uses: actions/checkout@v4\n      - uses: some-unknown-org/mystery-action@v1\n"
            );
        }).await;
    }
}
