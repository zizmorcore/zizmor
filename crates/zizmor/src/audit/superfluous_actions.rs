use std::sync::LazyLock;

use github_actions_models::common::Uses;
use subfeature::Subfeature;

use crate::models::workflow::runners::Runner;
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
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let included_runners = &config.self_hosted_runner_config.deny_runners;
        let excluded_groups = &config.self_hosted_runner_config.allow_groups;

        // note : suboptimal since `NormalJob#runners` recomputes values
        // each time it's invoked
        let runs_on_self_hosted =
            step.job()
                .runners(included_runners, excluded_groups)
                .any(|runner| match runner {
                    Runner::SelfHosted { .. } => true,
                    Runner::Indeterminate {
                        self_hosted_evidence,
                        ..
                    } => self_hosted_evidence,
                    _ => false,
                });

        self.process_step(step, runs_on_self_hosted).await
    }

    async fn audit_composite_step<'doc>(
        &self,
        step: &CompositeStep<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step, false).await
    }
}

#[derive(PartialEq)]
enum SkipCriteria {
    Never,
    SelfHostedRunner,
}

#[allow(clippy::unwrap_used, clippy::type_complexity)]
static SUPERFLUOUS_ACTIONS: LazyLock<
    Vec<(
        RepositoryUsesPattern,
        &str,
        Persona,
        Confidence,
        SkipCriteria,
    )>,
> = LazyLock::new(|| {
    vec![
        (
            "ncipollo/release-action".parse().unwrap(),
            "use `gh release` in a script step",
            Persona::Regular,
            Confidence::High,
            SkipCriteria::Never,
        ),
        (
            "softprops/action-gh-release".parse().unwrap(),
            "use `gh release` in a script step",
            Persona::Regular,
            Confidence::High,
            SkipCriteria::Never,
        ),
        (
            "elgohr/Github-Release-Action".parse().unwrap(),
            "use `gh release` in a script step",
            Persona::Regular,
            Confidence::High,
            SkipCriteria::Never,
        ),
        (
            "peter-evans/create-pull-request".parse().unwrap(),
            "use `gh pr create` in a script step",
            // NOTE(ww): Currently pedantic because creating a PR
            // with just `gh` and `git` is pretty cumbersome.
            Persona::Pedantic,
            Confidence::Low,
            SkipCriteria::Never,
        ),
        (
            "peter-evans/create-or-update-comment".parse().unwrap(),
            "use `gh pr comment` or `gh issue comment` in a script step",
            // NOTE(ww): Currently pedantic because `gh` doesn't support
            // editing a comment by ID.
            // See: <https://github.com/cli/cli/issues/3613>
            Persona::Pedantic,
            Confidence::Low,
            SkipCriteria::Never,
        ),
        (
            "dacbd/create-issue-action".parse().unwrap(),
            "use `gh issue create` in a script step",
            Persona::Regular,
            Confidence::High,
            SkipCriteria::Never,
        ),
        (
            "actions-ecosystem/action-add-labels".parse().unwrap(),
            "use `gh issue edit --add-label` or `gh pr edit --add-label` in a script step",
            Persona::Regular,
            Confidence::High,
            SkipCriteria::Never,
        ),
        (
            "actions-ecosystem/action-remove-labels".parse().unwrap(),
            "use `gh issue edit --remove-label` or `gh pr edit --remove-label` in a script step",
            Persona::Regular,
            Confidence::High,
            SkipCriteria::Never,
        ),
        (
            "svenstaro/upload-release-action".parse().unwrap(),
            "use `gh release create` and `gh release upload` in a script step",
            Persona::Regular,
            Confidence::High,
            SkipCriteria::Never,
        ),
        (
            "addnab/docker-run-action".parse().unwrap(),
            "use `docker run` in a script step, or use a container step",
            Persona::Regular,
            Confidence::High,
            SkipCriteria::Never,
        ),
        (
            "sergeysova/jq-action".parse().unwrap(),
            "use `jq` in a script step",
            Persona::Regular,
            Confidence::High,
            SkipCriteria::Never,
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
            SkipCriteria::SelfHostedRunner,
        ),
        (
            "stefanzweifel/git-auto-commit-action".parse().unwrap(),
            "use `git add`, `git commit`, and `git push` in a script step",
            // NOTE: Currently pedantic because replicating this action's
            // full behaviour (empty commit detection, auth setup, etc.)
            // requires multiple git commands and some care.
            Persona::Pedantic,
            Confidence::Low,
            SkipCriteria::Never,
        ),
        (
            "EndBug/add-and-commit".parse().unwrap(),
            "use `git add`, `git commit`, and `git push` in a script step",
            // NOTE: Currently pedantic because replicating this action's
            // full behaviour (empty commit detection, auth setup, etc.)
            // requires multiple git commands and some care.
            Persona::Pedantic,
            Confidence::Low,
            SkipCriteria::Never,
        ),
    ]
});

impl SuperfluousActions {
    async fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
        runs_on_self_hosted_runner: bool,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let Some(Uses::Repository(uses)) = step.uses() else {
            return Ok(vec![]);
        };

        let mut findings = vec![];
        for (pattern, recommendation, persona, confidence, skip_criteria) in
            SUPERFLUOUS_ACTIONS.iter()
        {
            if *skip_criteria == SkipCriteria::SelfHostedRunner && runs_on_self_hosted_runner {
                continue;
            }

            if pattern.matches(&uses.into()) {
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
                        .add_location(step.location().hidden())
                        .build(step)?,
                );
            }
        }

        Ok(findings)
    }
}
