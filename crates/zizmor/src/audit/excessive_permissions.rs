use std::{collections::HashMap, sync::LazyLock};

use github_actions_models::common::{BasePermission, Permission, Permissions, Uses, expr::LoE};

use super::{Audit, AuditLoadError, Job, audit_meta};
use crate::audit::AuditError;
use crate::finding::location::Locatable as _;
use crate::finding::{Fix, FixDisposition};
use crate::models::workflow::NormalJob;
use crate::models::{StepBodyCommon, StepCommon as _, uses::RepositoryUsesExt as _};
use crate::{
    AuditState,
    finding::{Confidence, Persona, Severity, location::SymbolicLocation},
};
use yamlpatch::{Op, Patch};

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

/// Returns `true` if it is safe to emit a `permissions: {}` auto-fix for this job.
///
/// The fix is considered safe when:
/// - No step uses `actions/checkout` with `persist-credentials: true` (which would
///   break downstream git operations that rely on the persisted credential).
/// - No step (run script, `with:` input, or `env:` value) explicitly references
///   `secrets.GITHUB_TOKEN` or `github.token`, because those references imply the
///   job needs at least the default token permissions.
fn job_can_safely_drop_permissions(job: &NormalJob<'_>) -> bool {
    for step in job.steps() {
        match step.body() {
            StepBodyCommon::Uses { uses, with } => {
                // Check for persist-credentials: true in checkout steps.
                if let Uses::Repository(repo_uses) = uses
                    && repo_uses.matches("actions/checkout")
                    && let LoE::Literal(with_map) = with
                    && with_map
                        .get("persist-credentials")
                        .map(|v| v.to_string().eq_ignore_ascii_case("true"))
                        .unwrap_or(false)
                {
                    return false;
                }
                // Check for token references in with: values.
                if let LoE::Literal(with_map) = with {
                    for val in with_map.values() {
                        if contains_token_ref(&val.to_string()) {
                            return false;
                        }
                    }
                }
            }
            StepBodyCommon::Run { run, .. } => {
                if contains_token_ref(run) {
                    return false;
                }
            }
        }
        // Check step-level env values.
        if let LoE::Literal(env_map) = &step.env {
            for val in env_map.values() {
                if contains_token_ref(&val.to_string()) {
                    return false;
                }
            }
        }
    }
    true
}

/// Returns `true` if the string contains an explicit reference to the GitHub token.
fn contains_token_ref(s: &str) -> bool {
    let lower = s.to_lowercase();
    lower.contains("secrets.github_token") || lower.contains("github.token")
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

        for (severity, confidence, perm_location, fix) in self.check_workflow_permissions(
            &workflow.permissions,
            location,
            all_jobs_have_permissions,
        ) {
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
            let (permissions, job_location, job_finding_persona, can_fix) = match job {
                Job::NormalJob(job) => {
                    // For normal jobs: if the workflow is reusable-only, we
                    // emit pedantic findings.
                    let persona = if workflow_is_reusable_only {
                        Persona::Pedantic
                    } else {
                        Persona::Regular
                    };
                    let can_fix = job_can_safely_drop_permissions(&job);
                    (&job.permissions, job.location(), persona, can_fix)
                }
                Job::ReusableWorkflowCallJob(job) => {
                    // For reusable jobs: the caller is always responsible for
                    // permissions, so we emit regular findings even if
                    // the workflow is reusable-only.
                    //
                    // Permission inference is not possible here: the steps of the
                    // called workflow are defined externally and are not visible
                    // to the static analyser at this point.
                    (&job.permissions, job.location(), Persona::Regular, false)
                }
            };

            if let Some((severity, confidence, perm_location, fix)) = self.check_job_permissions(
                permissions,
                explicit_parent_permissions,
                job_location.clone(),
                can_fix,
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
        title: &str,
        perm_loc: SymbolicLocation<'a>,
        value: serde_yaml::Value,
    ) -> (Severity, Confidence, SymbolicLocation<'a>, Option<Fix<'a>>) {
        (
            severity,
            Confidence::High,
            perm_loc.clone().annotated(annotation),
            Some(Fix {
                title: title.into(),
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
        add_default_fix: bool,
    ) -> Vec<(Severity, Confidence, SymbolicLocation<'a>, Option<Fix<'a>>)> {
        let mut results = vec![];

        match &permissions {
            Permissions::Base(base) => match base {
                BasePermission::Default => {
                    let fix = if add_default_fix {
                        Some(Fix {
                            title: "Add `permissions: {}` to restrict GITHUB_TOKEN permissions"
                                .into(),
                            key: location.key,
                            disposition: FixDisposition::Unsafe,
                            patches: vec![Patch {
                                route: location.route.clone(),
                                operation: Op::Add {
                                    key: "permissions".into(),
                                    value: serde_yaml::Value::Mapping(Default::default()),
                                },
                            }],
                        })
                    } else {
                        None
                    };
                    results.push((
                        Severity::Medium,
                        Confidence::Medium,
                        location
                            .clone()
                            .annotated("default permissions used due to no permissions: block"),
                        fix,
                    ));
                }
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
                        &format!("Replace `{base_str}` with empty permissions block"),
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
        can_fix: bool,
    ) -> Option<(Severity, Confidence, SymbolicLocation<'a>, Option<Fix<'a>>)> {
        match permissions {
            Permissions::Base(base) => match base {
                // The job has no explicit permissions, meaning it gets
                // the default $GITHUB_TOKEN *if* the workflow doesn't
                // set any permissions.
                BasePermission::Default if !explicit_parent_permissions => {
                    let fix = if can_fix {
                        Some(Fix {
                            title: "Add `permissions: {}` to restrict GITHUB_TOKEN permissions"
                                .into(),
                            key: location.key,
                            disposition: FixDisposition::Unsafe,
                            patches: vec![Patch {
                                route: location.route.clone(),
                                operation: Op::Add {
                                    key: "permissions".into(),
                                    value: serde_yaml::Value::Mapping(Default::default()),
                                },
                            }],
                        })
                    } else {
                        None
                    };
                    Some((
                        Severity::Medium,
                        Confidence::Medium,
                        location
                            .clone()
                            .annotated("default permissions used due to no permissions: block"),
                        fix,
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
                    let perm_loc = location.with_keys(["permissions".into()]);
                    let fix_opt = if can_fix {
                        Some(Self::make_replace_fix_result(
                            severity,
                            annotation,
                            &format!("Replace `{base_str}` with empty permissions block"),
                            perm_loc.clone(),
                            serde_yaml::Value::Mapping(Default::default()),
                        ))
                    } else {
                        None
                    };
                    // If we couldn't build a fix, still return the finding (no fix).
                    Some(if let Some(result) = fix_opt {
                        result
                    } else {
                        (
                            severity,
                            Confidence::High,
                            perm_loc.annotated(annotation),
                            None,
                        )
                    })
                }
            },
            // In the general case, it's impossible to tell whether a job-level
            // permission block is over-scoped.
            Permissions::Explicit(_) => None,
        }
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
        let result = audit.audit_workflow(&workflow, &Config::default()).await;
        let findings = result.unwrap();
        check(&workflow, &findings);
    }

    fn fix_source(workflow: &Workflow, findings: &[crate::finding::Finding]) -> String {
        let finding = findings
            .iter()
            .find(|f| !f.fixes.is_empty())
            .expect("no fixable finding");
        let patched = finding.fixes[0].apply(workflow.as_document()).unwrap();
        patched.source().to_string()
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

    const WORKFLOW_DEFAULT_ALL_JOBS_HAVE_PERMS: &str = r#"
on: push
name: Test
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - run: echo hello
  test:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - run: echo test
"#;

    const WORKFLOW_DEFAULT_NOT_ALL_JOBS_HAVE_PERMS: &str = r#"
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

    const JOB_WRITE_ALL_SAFE: &str = r#"
on: push
name: Test
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - uses: actions/checkout@v4
      - run: echo hello
"#;

    const JOB_WRITE_ALL_PERSIST_CREDENTIALS: &str = r#"
on: push
name: Test
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: "true"
      - run: echo hello
"#;

    const JOB_WRITE_ALL_GITHUB_TOKEN: &str = r#"
on: push
name: Test
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - run: |
          curl -H "Authorization: token ${{ secrets.GITHUB_TOKEN }}" https://api.github.com
"#;

    const JOB_DEFAULT_SAFE: &str = r#"
on: push
name: Test
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo hello
"#;

    const JOB_DEFAULT_GITHUB_TOKEN_WITH: &str = r#"
on: push
name: Test
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some-action/deploy@v1
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
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
    async fn workflow_default_with_all_job_perms_has_fix() {
        run_audit(WORKFLOW_DEFAULT_ALL_JOBS_HAVE_PERMS, |wf, findings| {
            assert!(
                findings.iter().any(|f| !f.fixes.is_empty()),
                "expected a fixable finding when all jobs have explicit permissions"
            );
            assert_eq!(
                fix_source(wf, findings),
                "\non: push\nname: Test\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions: {}\n    steps:\n      - run: echo hello\n  test:\n    runs-on: ubuntu-latest\n    permissions: {}\n    steps:\n      - run: echo test\npermissions: {}\n"
            );
        }).await;
    }

    #[tokio::test]
    async fn job_level_default_gets_fix_regardless_of_workflow_perms() {
        // Even when the workflow-level finding has no fix (because not all jobs
        // have explicit permissions), the job-level finding should still get
        // an auto-fix if the job itself is safe (no token refs, no persist-creds).
        run_audit(WORKFLOW_DEFAULT_NOT_ALL_JOBS_HAVE_PERMS, |_wf, findings| {
            // In non-pedantic mode, the workflow-level finding is suppressed.
            // The job-level finding is regular and should have a fix.
            assert!(
                findings.iter().any(|f| !f.fixes.is_empty()),
                "expected at least one fixable finding (job-level)"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn explicit_write_at_workflow_level_has_no_autofix() {
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
        })
        .await;
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
    async fn job_write_all_safe_has_fix() {
        run_audit(JOB_WRITE_ALL_SAFE, |wf, findings| {
            assert_eq!(
                fix_source(wf, findings),
                "\non: push\nname: Test\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions: {}\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo hello\n"
            );
        }).await;
    }

    #[tokio::test]
    async fn job_write_all_persist_credentials_has_no_fix() {
        run_audit(JOB_WRITE_ALL_PERSIST_CREDENTIALS, |_wf, findings| {
            assert!(
                !findings.is_empty(),
                "expected at least one finding for write-all job"
            );
            assert!(
                findings.iter().all(|f| f.fixes.is_empty()),
                "expected no auto-fix when persist-credentials: true is set"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn job_write_all_github_token_run_has_no_fix() {
        run_audit(JOB_WRITE_ALL_GITHUB_TOKEN, |_wf, findings| {
            assert!(
                findings.iter().all(|f| f.fixes.is_empty()),
                "expected no auto-fix when run: references secrets.GITHUB_TOKEN"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn job_default_safe_has_fix() {
        run_audit(JOB_DEFAULT_SAFE, |wf, findings| {
            assert!(
                findings.iter().any(|f| !f.fixes.is_empty()),
                "expected a fixable finding for safe job with default permissions"
            );
            let _ = fix_source(wf, findings); // just ensure it applies without panic
        })
        .await;
    }

    #[tokio::test]
    async fn job_default_github_token_with_has_no_fix() {
        run_audit(JOB_DEFAULT_GITHUB_TOKEN_WITH, |_wf, findings| {
            assert!(
                findings.iter().all(|f| f.fixes.is_empty()),
                "expected no auto-fix when with: passes secrets.GITHUB_TOKEN"
            );
        })
        .await;
    }
}
