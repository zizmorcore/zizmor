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

/// Merge `new` into `current`, keeping the higher of the two.
fn merge_permission(current: &mut Permission, new: &Permission) {
    *current = match (&*current, new) {
        (Permission::Write, _) | (_, Permission::Write) => Permission::Write,
        (Permission::Read, _) | (_, Permission::Read) => Permission::Read,
        _ => Permission::None,
    };
}

/// Attempt to infer the minimum GITHUB_TOKEN permissions required by a job.
///
/// Iterates over every step:
/// - `uses:` steps pointing to a known action contribute that action's
///   required permissions to the aggregate set.
/// - `uses:` steps pointing to an **unknown** action cause the function to
///   return [`PermissionInference::Unknown`] immediately.
/// - `run:` steps and Docker/local `uses:` are **skipped** (we cannot
///   statically determine what permissions a shell script may use).
///
/// Note: because `run:` steps are skipped, the inferred set may be an
/// under-approximation for jobs that also call the GitHub API via scripts.
/// All generated fixes carry [`FixDisposition::Unsafe`] to signal this.
///
/// `extra_kb` entries take precedence over the built-in [`ACTION_PERMISSIONS`].
fn infer_job_permissions(job: &NormalJob<'_>, extra_kb: &ActionKb) -> PermissionInference {
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

        // Extra KB takes precedence over the built-in KB.
        // Both have type ActionKb so the lookup is identical.
        let perms = extra_kb
            .get(&key)
            .or_else(|| ACTION_PERMISSIONS.get(&key));

        let Some(perms) = perms else {
            // Unknown action — cannot infer minimum permissions.
            return PermissionInference::Unknown;
        };

        for (scope, perm) in perms {
            let entry = required.entry(scope.clone()).or_insert(Permission::None);
            merge_permission(entry, perm);
        }
    }

    PermissionInference::Known(required)
}

/// Build a `serde_yaml::Value` from a `PermissionMap`.
///
/// An empty map produces an empty mapping (`{}`).
fn permissions_to_yaml(perms: &PermissionMap) -> serde_yaml::Value {
    if perms.is_empty() {
        return serde_yaml::Value::Mapping(Default::default());
    }

    let mut map = serde_yaml::Mapping::new();
    for (scope, perm) in perms {
        let perm_str = match perm {
            Permission::Read => "read",
            Permission::Write => "write",
            Permission::None => "none",
        };
        map.insert(
            serde_yaml::Value::String(scope.clone()),
            serde_yaml::Value::String(perm_str.into()),
        );
    }
    serde_yaml::Value::Mapping(map)
}

audit_meta!(
    ExcessivePermissions,
    "excessive-permissions",
    "overly broad permissions"
);

pub(crate) struct ExcessivePermissions {
    /// Extra action KB loaded from `--action-kb` / `ZIZMOR_ACTION_KB`.
    extra_kb: ActionKb,
}

#[async_trait::async_trait]
impl Audit for ExcessivePermissions {
    fn new(state: &AuditState) -> Result<Self, AuditLoadError> {
        Ok(Self {
            extra_kb: state.action_kb.clone(),
        })
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

                    let inference = infer_job_permissions(&job, &self.extra_kb);
                    (&job.permissions, job.location(), persona, inference)
                }
                Job::ReusableWorkflowCallJob(job) => {
                    // For reusable jobs: the caller is always responsible for
                    // permissions, so we emit regular findings even if
                    // the workflow is reusable-only.
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
                BasePermission::ReadAll => {
                    let perm_loc = location.clone().with_keys(["permissions".into()]);
                    results.push((
                        Severity::Medium,
                        Confidence::High,
                        perm_loc.clone().annotated("uses read-all permissions"),
                        Some(Fix {
                            title: "Replace `read-all` with empty permissions block".into(),
                            key: perm_loc.key,
                            disposition: FixDisposition::Unsafe,
                            patches: vec![Patch {
                                route: perm_loc.route.clone(),
                                operation: Op::Replace(serde_yaml::Value::Mapping(
                                    Default::default(),
                                )),
                            }],
                        }),
                    ))
                }
                BasePermission::WriteAll => {
                    let perm_loc = location.clone().with_keys(["permissions".into()]);
                    results.push((
                        Severity::High,
                        Confidence::High,
                        perm_loc.clone().annotated("uses write-all permissions"),
                        Some(Fix {
                            title: "Replace `write-all` with empty permissions block".into(),
                            key: perm_loc.key,
                            disposition: FixDisposition::Unsafe,
                            patches: vec![Patch {
                                route: perm_loc.route.clone(),
                                operation: Op::Replace(serde_yaml::Value::Mapping(
                                    Default::default(),
                                )),
                            }],
                        }),
                    ))
                }
            },
            Permissions::Explicit(perms) => {
                for (name, perm) in perms {
                    if *perm != Permission::Write {
                        continue;
                    }

                    let severity = WRITE_SCOPE_SEVERITIES.get(name.as_str()).unwrap_or_else(|| {
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
                BasePermission::ReadAll => {
                    let perm_loc = location.clone().with_keys(["permissions".into()]);
                    let (title, value) = fix_title_and_value(
                        "Replace",
                        "`read-all` with empty permissions block",
                        "Replace `read-all` with minimum required permissions",
                        &inference,
                    );
                    Some((
                        Severity::Medium,
                        Confidence::High,
                        perm_loc.clone().annotated("uses read-all permissions"),
                        Some(Fix {
                            title,
                            key: perm_loc.key,
                            disposition: FixDisposition::Unsafe,
                            patches: vec![Patch {
                                route: perm_loc.route.clone(),
                                operation: Op::Replace(value),
                            }],
                        }),
                    ))
                }
                BasePermission::WriteAll => {
                    let perm_loc = location.clone().with_keys(["permissions".into()]);
                    let (title, value) = fix_title_and_value(
                        "Replace",
                        "`write-all` with empty permissions block",
                        "Replace `write-all` with minimum required permissions",
                        &inference,
                    );
                    Some((
                        Severity::High,
                        Confidence::High,
                        perm_loc.clone().annotated("uses write-all permissions"),
                        Some(Fix {
                            title,
                            key: perm_loc.key,
                            disposition: FixDisposition::Unsafe,
                            patches: vec![Patch {
                                route: perm_loc.route.clone(),
                                operation: Op::Replace(value),
                            }],
                        }),
                    ))
                }
            },
            // In the general case, it's impossible to tell whether a job-level
            // permission block is over-scoped.
            Permissions::Explicit(_) => None,
        }
    }
}

/// Choose the fix title and YAML value based on the permission inference result.
///
/// Returns the fallback title/value when inference yielded `Unknown` or an
/// empty permission set, and the precise title/value when a non-empty minimum
/// permission set was inferred.
fn fix_title_and_value(
    fallback_verb: &str,
    fallback_rest: &str,
    precise_title: &str,
    inference: &PermissionInference,
) -> (String, serde_yaml::Value) {
    match inference {
        PermissionInference::Known(map) if !map.is_empty() => (
            precise_title.into(),
            permissions_to_yaml(map),
        ),
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

    macro_rules! test_workflow_audit {
        ($filename:expr, $workflow_content:expr, $test_fn:expr) => {{
            let key = InputKey::local("fakegroup".into(), $filename, None::<&str>);
            let workflow = Workflow::from_string($workflow_content.to_string(), key).unwrap();
            let audit_state = AuditState::default();
            let audit = ExcessivePermissions::new(&audit_state).unwrap();
            let findings = audit
                .audit_workflow(&workflow, &Config::default())
                .await
                .unwrap();
            $test_fn(&workflow, findings)
        }};
    }

    fn apply_first_fix(
        document: &yamlpath::Document,
        findings: &[crate::finding::Finding],
    ) -> yamlpath::Document {
        assert!(!findings.is_empty(), "Expected findings but got none");
        let finding = findings
            .iter()
            .find(|f| !f.fixes.is_empty())
            .expect("Expected at least one finding with a fix");
        let fix = &finding.fixes[0];
        fix.apply(document).unwrap()
    }

    #[tokio::test]
    async fn test_fix_workflow_read_all() {
        let content = r#"
on: push
name: Test
permissions: read-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"#;
        test_workflow_audit!(
            "test_fix_workflow_read_all.yml",
            content,
            |workflow: &Workflow, findings: Vec<crate::finding::Finding>| {
                let finding = findings
                    .iter()
                    .find(|f| !f.fixes.is_empty())
                    .expect("Expected a finding with a fix");
                assert!(
                    finding.fixes[0].title.contains("read-all"),
                    "Expected fix title to mention read-all"
                );

                let fixed = apply_first_fix(workflow.as_document(), &findings);
                assert_eq!(
                    fixed.source(),
                    "\non: push\nname: Test\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n"
                );
            }
        );
    }

    #[tokio::test]
    async fn test_fix_workflow_write_all() {
        let content = r#"
on: push
name: Test
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"#;
        test_workflow_audit!(
            "test_fix_workflow_write_all.yml",
            content,
            |workflow: &Workflow, findings: Vec<crate::finding::Finding>| {
                let finding = findings
                    .iter()
                    .find(|f| !f.fixes.is_empty())
                    .expect("Expected a finding with a fix");
                assert!(
                    finding.fixes[0].title.contains("write-all"),
                    "Expected fix title to mention write-all"
                );

                let fixed = apply_first_fix(workflow.as_document(), &findings);
                assert_eq!(
                    fixed.source(),
                    "\non: push\nname: Test\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n"
                );
            }
        );
    }

    #[tokio::test]
    async fn test_fix_workflow_default_permissions() {
        let content = r#"
on: push
name: Test
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"#;
        test_workflow_audit!(
            "test_fix_workflow_default_permissions.yml",
            content,
            |workflow: &Workflow, findings: Vec<crate::finding::Finding>| {
                let finding_with_fix = findings.iter().find(|f| !f.fixes.is_empty());
                if let Some(finding) = finding_with_fix {
                    assert!(
                        finding.fixes[0].title.contains("permissions"),
                        "Expected fix title to mention permissions"
                    );
                    let fixed = apply_first_fix(workflow.as_document(), &findings);
                    assert_eq!(
                        fixed.source(),
                        "\non: push\nname: Test\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\npermissions: {}\n"
                    );
                }
            }
        );
    }

    #[tokio::test]
    async fn test_fix_explicit_write_permissions_no_fix() {
        // Explicit write permissions at the workflow level should NOT have an
        // auto-fix, since the correct remediation is to move the write permission
        // to the specific job(s) that need it — which requires knowing the job
        // structure.
        let content = r#"
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
        test_workflow_audit!(
            "test_fix_explicit_write_no_fix.yml",
            content,
            |_workflow: &Workflow, findings: Vec<crate::finding::Finding>| {
                assert!(!findings.is_empty(), "Expected findings for explicit write");
                // All findings for explicit write should have no fix.
                for finding in &findings {
                    assert!(
                        finding.fixes.is_empty(),
                        "Expected no auto-fix for explicit write at workflow level"
                    );
                }
            }
        );
    }

    #[tokio::test]
    async fn test_fix_job_read_all() {
        let content = r#"
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
        test_workflow_audit!(
            "test_fix_job_read_all.yml",
            content,
            |workflow: &Workflow, findings: Vec<crate::finding::Finding>| {
                assert!(!findings.is_empty(), "Expected findings for job read-all");
                let fixed = apply_first_fix(workflow.as_document(), &findings);
                assert_eq!(
                    fixed.source(),
                    "\non: push\nname: Test\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions: {}\n    steps:\n      - run: echo hello\n"
                );
            }
        );
    }

    #[tokio::test]
    async fn test_fix_job_write_all_known_actions() {
        // When all steps use known actions, the fix should use inferred permissions
        // rather than the generic `{}`.
        let content = r#"
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
        test_workflow_audit!(
            "test_fix_job_write_all_known_actions.yml",
            content,
            |workflow: &Workflow, findings: Vec<crate::finding::Finding>| {
                assert!(!findings.is_empty(), "Expected findings for job write-all");
                let finding = findings
                    .iter()
                    .find(|f| !f.fixes.is_empty())
                    .expect("Expected a finding with a fix");
                assert!(
                    finding.fixes[0].title.contains("minimum required"),
                    "Expected precise fix title, got: {}",
                    finding.fixes[0].title
                );
                let fixed = apply_first_fix(workflow.as_document(), &findings);
                assert_eq!(
                    fixed.source(),
                    "\non: push\nname: Test\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n      security-events: write\n    steps:\n      - uses: actions/checkout@v4\n      - uses: github/codeql-action/init@v3\n      - uses: github/codeql-action/analyze@v3\n"
                );
            }
        );
    }

    #[tokio::test]
    async fn test_fix_job_write_all_unknown_action() {
        // When a job uses an unknown action, the fix falls back to `{}`.
        let content = r#"
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
        test_workflow_audit!(
            "test_fix_job_write_all_unknown_action.yml",
            content,
            |workflow: &Workflow, findings: Vec<crate::finding::Finding>| {
                assert!(!findings.is_empty(), "Expected findings for job write-all");
                let finding = findings
                    .iter()
                    .find(|f| !f.fixes.is_empty())
                    .expect("Expected a finding with a fix");
                // Should fall back to the generic empty-block fix
                assert!(
                    finding.fixes[0].title.contains("write-all"),
                    "Expected fallback fix title, got: {}",
                    finding.fixes[0].title
                );
                let fixed = apply_first_fix(workflow.as_document(), &findings);
                assert_eq!(
                    fixed.source(),
                    "\non: push\nname: Test\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions: {}\n    steps:\n      - uses: actions/checkout@v4\n      - uses: some-unknown-org/mystery-action@v1\n"
                );
            }
        );
    }
}
