//! Detects actions pinned by commit hash, which don't point to a Git tag.

use anyhow::anyhow;
use github_actions_models::common::{RepositoryUses, Uses};
use subfeature::Subfeature;

use super::{Audit, AuditLoadError, audit_meta};
use crate::{
    Persona,
    audit::AuditError,
    config::Config,
    finding::{Confidence, Finding, Severity},
    github,
    models::{StepCommon, action::CompositeStep, uses::RepositoryUsesExt as _, workflow::Step},
    state::AuditState,
};

pub(crate) struct StaleActionRefs {
    client: github::Client,
}

audit_meta!(
    StaleActionRefs,
    "stale-action-refs",
    "commit hash does not point to a Git tag"
);

impl StaleActionRefs {
    async fn is_stale_action_ref(&self, uses: &RepositoryUses) -> Result<bool, AuditError> {
        let tag = match &uses.commit_ref() {
            Some(commit_ref) => self
                .client
                .longest_tag_for_commit(uses.owner(), uses.repo(), commit_ref)
                .await
                .map_err(Self::err)?,
            None => return Ok(false),
        };
        Ok(tag.is_none())
    }

    async fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        let Some(Uses::Repository(uses)) = step.uses() else {
            return Ok(findings);
        };

        if self.is_stale_action_ref(uses).await? {
            findings.push(
                Self::finding()
                    .confidence(Confidence::High)
                    .severity(Severity::Low)
                    .persona(Persona::Pedantic)
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(["uses".into()])
                            .subfeature(Subfeature::new(0, uses.raw())),
                    )
                    .build(step)?,
            );
        }

        Ok(findings)
    }
}

#[async_trait::async_trait]
impl Audit for StaleActionRefs {
    fn new(state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        if state.no_online_audits {
            return Err(AuditLoadError::Skip(anyhow!(
                "offline audits only requested"
            )));
        }

        state
            .gh_client
            .clone()
            .ok_or_else(|| AuditLoadError::Skip(anyhow!("can't run without a GitHub API token")))
            .map(|client| StaleActionRefs { client })
    }

    async fn audit_step<'w>(
        &self,
        step: &Step<'w>,
        _config: &Config,
    ) -> Result<Vec<Finding<'w>>, AuditError> {
        self.process_step(step).await
    }

    async fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
        _config: &Config,
    ) -> Result<Vec<Finding<'a>>, AuditError> {
        self.process_step(step).await
    }
}
