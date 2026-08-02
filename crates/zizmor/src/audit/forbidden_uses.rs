use github_actions_models::common::Uses;
use subfeature::Subfeature;

use super::{Audit, AuditLoadError, AuditState, audit_meta};
use crate::audit::AuditError;
use crate::config::{Config, ForbiddenUsesConfigInner};
use crate::finding::location::Locatable as _;
use crate::finding::{Confidence, Finding, Persona, Severity};
use crate::models::pre_commit::PreCommitConfig;
use crate::models::repo_ref::RepoRef;
use crate::models::{StepCommon, action::CompositeStep, workflow::Step};

pub(crate) struct ForbiddenUses;

audit_meta!(
    ForbiddenUses,
    "forbidden-uses",
    "forbidden action or repository used"
);

impl ForbiddenUses {
    fn use_denied<'doc>(
        &self,
        repo: impl Into<RepoRef<'doc>>,
        config: &ForbiddenUsesConfigInner,
    ) -> bool {
        let repo = repo.into();

        match config {
            ForbiddenUsesConfigInner::Allow(allow) => {
                !allow.iter().any(|pattern| pattern.matches(&repo))
            }
            ForbiddenUsesConfigInner::Deny(deny) => {
                deny.iter().any(|pattern| pattern.matches(&repo))
            }
        }
    }

    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        let Some(config) = config.forbidden_uses_config.as_ref() else {
            tracing::trace!("no forbidden-uses config for this input; skipping");
            return Ok(findings);
        };

        let Some(Uses::Repository(uses)) = step.uses() else {
            return Ok(findings);
        };

        if self.use_denied(uses, config) {
            findings.push(
                Self::finding()
                    .confidence(Confidence::High)
                    .severity(Severity::High)
                    .persona(Persona::Regular)
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(["uses".into()])
                            .subfeature(Subfeature::new(0, uses.raw()))
                            .annotated("use of this action is forbidden"),
                    )
                    .build(step)?,
            );
        };

        Ok(findings)
    }
}

#[async_trait::async_trait]
impl Audit for ForbiddenUses {
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
        self.process_step(step, config)
    }

    async fn audit_composite_step<'doc>(
        &self,
        step: &CompositeStep<'doc>,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step, config)
    }

    async fn audit_pre_commit_config<'doc>(
        &self,
        pre_commit: &'doc PreCommitConfig,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        let Some(config) = config.forbidden_uses_config.as_ref() else {
            tracing::trace!("no forbidden-uses config for this input; skipping");
            return Ok(findings);
        };

        for repo in pre_commit.repos() {
            let Some(remote) = repo.repo() else {
                continue;
            };

            if self.use_denied(remote, config) {
                findings.push(
                    Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::High)
                        .persona(Persona::Regular)
                        .add_location(
                            repo.location()
                                .with_keys(["repo".into()])
                                .subfeature(Subfeature::new(0, remote.repo.as_str()))
                                .annotated("use of this repository is forbidden")
                                .primary(),
                        )
                        .build(pre_commit)?,
                );
            }
        }

        Ok(findings)
    }
}
