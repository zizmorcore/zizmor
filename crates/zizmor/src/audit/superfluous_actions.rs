use std::sync::LazyLock;

use github_actions_models::common::Uses;
use subfeature::Subfeature;

use crate::{
    audit::{Audit, AuditError, AuditLoadError, audit_meta},
    config::Config,
    finding::{Confidence, Finding, Persona, Severity},
    models::{
        StepCommon, action::CompositeStep, uses::RepositoryUsesPattern, workflow::{NormalJob, Step},
    },
    state::AuditState,
};

pub(crate) struct SuperfluousActions;

audit_meta!(
    SuperfluousActions,
    "superfluous-actions",
    "action functionality is already included by the runner"
);

#[async_trait::async_trait]
impl Audit for SuperfluousActions {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_step<'doc>(
        &self,
        step: &Step<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step, Some(step.job())).await
    }

    async fn audit_composite_step<'doc>(
        &self,
        step: &CompositeStep<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        // Composite steps don't have access to a workflow job context.
        self.process_step(step, None).await
    }
}

#[allow(clippy::unwrap_used)]
static SUPERFLUOUS_ACTIONS: LazyLock<Vec<(RepositoryUsesPattern, &str, Persona, Confidence)>> =
    LazyLock::new(|| {
        vec![
            (
                "ncipollo/release-action".parse().unwrap(),
                "use `gh release` in a script step",
                Persona::Regular,
                Confidence::High,
            ),
            (
                "softprops/action-gh-release".parse().unwrap(),
                "use `gh release` in a script step",
                Persona::Regular,
                Confidence::High,
            ),
            (
                "elgohr/Github-Release-Action".parse().unwrap(),
                "use `gh release` in a script step",
                Persona::Regular,
                Confidence::High,
            ),
            (
                "peter-evans/create-pull-request".parse().unwrap(),
                "use `gh pr create` in a script step",
                // NOTE(ww): Currently pedantic because creating a PR
                // with just `gh` and `git` is pretty cumbersome.
                Persona::Pedantic,
                Confidence::Low,
            ),
            (
                "peter-evans/create-or-update-comment".parse().unwrap(),
                "use `gh pr comment` or `gh issue comment` in a script step",
                // NOTE(ww): Currently pedantic because `gh` doesn't support
                // editing a comment by ID.
                // See: <https://github.com/cli/cli/issues/3613>
                Persona::Pedantic,
                Confidence::Low,
            ),
            (
                "dacbd/create-issue-action".parse().unwrap(),
                "use `gh issue create` in a script step",
                Persona::Regular,
                Confidence::High,
            ),
            (
                "svenstaro/upload-release-action".parse().unwrap(),
                "use `gh release create` and `gh release upload` in a script step",
                Persona::Regular,
                Confidence::High,
            ),
            (
                "addnab/docker-run-action".parse().unwrap(),
                "use `docker run` in a script step, or use a container step",
                Persona::Regular,
                Confidence::High,
            ),
            (
                "dtolnay/rust-toolchain".parse().unwrap(),
                "use `rustup` and/or `cargo` in a script step",
                // NOTE(ww): Currently pedantic because this action does
                // some additional environment setup, and users find the
                // finding here disruptive.
                // See: <https://github.com/zizmorcore/zizmor/issues/1817>
                Persona::Pedantic,
                Confidence::Medium,
            ),
        ]
    });

impl SuperfluousActions {
    async fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
        job: Option<&NormalJob<'doc>>,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let Some(Uses::Repository(uses)) = step.uses() else {
            return Ok(vec![]);
        };

        // For dtolnay/rust-toolchain, check if running on a self-hosted runner.
        // On self-hosted runners, rustup/cargo may not be pre-installed, so
        // dtolnay/rust-toolchain is NOT superfluous.
        let is_self_hosted = job.map_or(false, |j| Self::is_self_hosted_runner(j));
        let is_rust_toolchain = uses.repository() == "dtolnay/rust-toolchain";

        let mut findings = vec![];
        for (pattern, recommendation, persona, confidence) in SUPERFLUOUS_ACTIONS.iter() {
            if pattern.matches(uses) {
                // Skip dtolnay/rust-toolchain on self-hosted runners.
                if is_self_hosted && is_rust_toolchain {
                    continue;
                }

                findings.push(
                    Self::finding()
                        .confidence(*confidence)
                        .severity(Severity::Informational)
                        .persona(*persona)
                        .add_location(step.location_with_grip())
                        .add_location(
                            step.location()
                                .with_keys(["uses".into()])
                                .subfeature(Subfeature::new(0, uses.raw()))
                                .annotated(*recommendation)
                                .primary(),
                        )
                        .build(step)?,
                );
            }
        }

        Ok(findings)
    }

    /// Returns true if the job runs on a self-hosted runner.
    fn is_self_hosted_runner(job: &NormalJob<'_>) -> bool {
        use github_actions_models::common::expr::LoE;
        use github_actions_models::workflow::job::RunsOn;

        match &job.runs_on {
            // Expression-based runs-on: only treat as self-hosted if the
            // matrix expansion actually contains "self-hosted".
            LoE::Expr(exp) => {
                let Some(matrix) = job.matrix() else {
                    return false;
                };
                matrix.expansions().iter().any(|expansion| {
                    exp.as_bare() == expansion.path && expansion.value.contains("self-hosted")
                })
            }
            // Runner groups always imply self-hosted runners.
            LoE::Literal(RunsOn::Group { .. }) => true,
            LoE::Literal(RunsOn::Target(labels)) => {
                // A runner is considered self-hosted if no label matches
                // known GitHub-hosted runner patterns (ubuntu-*, macos*, windows-*).
                !labels.iter().any(|label| {
                    let l = label.as_str();
                    l.contains("ubuntu-") || l.contains("macos") || l.contains("windows-")
                })
            }
        }
    }
}
