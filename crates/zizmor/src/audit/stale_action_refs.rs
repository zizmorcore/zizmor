//! Detects actions pinned by commit hash, which don't point to a Git tag.

use anyhow::anyhow;
use github_actions_models::common::{RepositoryUses, Uses};
use subfeature::Subfeature;

use super::{Audit, AuditLoadError, audit_meta};
use crate::{
    Persona,
    audit::AuditError,
    config::Config,
    finding::{Confidence, Finding, Severity, location::Locatable},
    github,
    models::{
        AsDocument, StepCommon,
        action::CompositeStep,
        uses::RepositoryUsesExt as _,
        workflow::{ReusableWorkflowCallJob, Step},
    },
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
        let tag = match uses.commit_ref() {
            Some(commit_ref) => self
                .client
                .longest_tag_for_commit(&uses.into(), uses.subpath(), commit_ref)
                .await
                .map_err(Self::err)?,
            None => return Ok(false),
        };
        Ok(tag.is_none())
    }

    async fn process_uses<'a, 'doc, S>(
        &self,
        uses: &'doc RepositoryUses,
        parent: &'a S,
    ) -> Result<Option<Finding<'doc>>, AuditError>
    where
        S: Locatable<'doc> + AsDocument<'a, 'doc>,
    {
        if self.is_stale_action_ref(uses).await? {
            Ok(Some(
                Self::finding()
                    .confidence(Confidence::High)
                    .severity(Severity::Low)
                    .persona(Persona::Pedantic)
                    .add_location(
                        parent
                            .location()
                            .primary()
                            .with_keys(["uses".into()])
                            .subfeature(Subfeature::new(0, uses.raw())),
                    )
                    .build(parent)?,
            ))
        } else {
            Ok(None)
        }
    }

    async fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> Result<Option<Finding<'doc>>, AuditError> {
        let Some(Uses::Repository(uses)) = step.uses() else {
            return Ok(None);
        };

        self.process_uses(uses, step).await
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
            .map(|client| Self { client })
    }

    async fn audit_step<'w>(
        &self,
        step: &Step<'w>,
        _config: &Config,
    ) -> Result<Vec<Finding<'w>>, AuditError> {
        Ok(self.process_step(step).await?.into_iter().collect())
    }

    async fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
        _config: &Config,
    ) -> Result<Vec<Finding<'a>>, AuditError> {
        Ok(self.process_step(step).await?.into_iter().collect())
    }

    async fn audit_reusable_job<'doc>(
        &self,
        job: &ReusableWorkflowCallJob<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let Uses::Repository(uses) = &job.uses else {
            return Ok(vec![]);
        };

        Ok(self.process_uses(uses, job).await?.into_iter().collect())
    }
}
