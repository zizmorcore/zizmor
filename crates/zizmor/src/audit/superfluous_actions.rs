use std::sync::LazyLock;

use github_actions_models::common::Uses;
use subfeature::Subfeature;

use crate::{
    audit::{Audit, AuditError, AuditLoadError, audit_meta},
    config::Config,
    finding::{Confidence, Finding, Persona, Severity},
    models::{StepCommon, action::CompositeStep, uses::RepositoryUsesPattern, workflow::Step},
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
        self.process_step(step).await
    }

    async fn audit_composite_step<'doc>(
        &self,
        step: &CompositeStep<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step).await
    }
}

#[allow(clippy::unwrap_used)]
static SUPERFLUOUS_ACTIONS: LazyLock<Vec<(RepositoryUsesPattern, &str, Persona)>> =
    LazyLock::new(|| {
        vec![
            (
                "ncipollo/release-action".parse().unwrap(),
                "use `gh release` in a script step",
                Persona::Regular,
            ),
            (
                "softprops/action-gh-release".parse().unwrap(),
                "use `gh release` in a script step",
                Persona::Regular,
            ),
            (
                "elgohr/Github-Release-Action".parse().unwrap(),
                "use `gh release` in a script step",
                Persona::Regular,
            ),
            (
                "peter-evans/create-pull-request".parse().unwrap(),
                "use `gh pr create` in a script step",
                // NOTE(ww): Currently pedantic because creating a PR
                // with just `gh` and `git` is pretty cumbersome.
                Persona::Pedantic,
            ),
            (
                "peter-evans/create-or-update-comment".parse().unwrap(),
                "use `gh pr comment` or `gh issue comment` in a script step",
                Persona::Regular,
            ),
            (
                "addnab/docker-run-action".parse().unwrap(),
                "use `docker run` in a script step, or use a container step",
                Persona::Regular,
            ),
            (
                "dtolnay/rust-toolchain".parse().unwrap(),
                "use `rustup` and/or `cargo` in a script step",
                Persona::Regular,
            ),
        ]
    });

impl SuperfluousActions {
    async fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let Some(Uses::Repository(uses)) = step.uses() else {
            return Ok(vec![]);
        };

        let mut findings = vec![];
        for (pattern, recommendation, persona) in SUPERFLUOUS_ACTIONS.iter() {
            if pattern.matches(uses) {
                findings.push(
                    Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::Low)
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
}
