//! Detects actions pinned by commit hash, which doesn't point to a Git tag.

use anyhow::{Result, anyhow};
use github_actions_models::common::{RepositoryUses, Uses};

use super::{Audit, AuditLoadError, audit_meta};
use crate::{
    Persona,
    finding::{Confidence, Finding, Severity},
    github_api,
    models::{CompositeStep, Step, StepCommon, uses::RepositoryUsesExt as _},
    state::AuditState,
};

pub(crate) struct StaleActionRefs {
    client: github_api::Client,
}

audit_meta!(
    StaleActionRefs,
    "stale-action-refs",
    "commit hash does not point to a Git tag"
);

impl StaleActionRefs {
    fn is_stale_action_ref(&self, uses: &RepositoryUses) -> Result<bool> {
        let tag = match &uses.commit_ref() {
            Some(commit_ref) => {
                self.client
                    .longest_tag_for_commit(&uses.owner, &uses.repo, commit_ref)?
            }
            None => return Ok(false),
        };
        Ok(tag.is_none())
    }

    fn process_step<'w>(&self, step: &impl StepCommon<'w>) -> Result<Vec<Finding<'w>>> {
        let mut findings = vec![];

        let Some(Uses::Repository(uses)) = step.uses() else {
            return Ok(findings);
        };

        if self.is_stale_action_ref(uses)? {
            findings.push(
                Self::finding()
                    .confidence(Confidence::High)
                    .severity(Severity::Low)
                    .persona(Persona::Pedantic)
                    .add_location(step.location().primary().with_keys(&["uses".into()]))
                    .build(step)?,
            );
        }

        Ok(findings)
    }
}

impl Audit for StaleActionRefs {
    fn new(state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        if state.no_online_audits {
            return Err(AuditLoadError::Skip(anyhow!(
                "offline audits only requested"
            )));
        }

        let Some(client) = state.github_client() else {
            return Err(AuditLoadError::Skip(anyhow!(
                "can't run without a GitHub API token"
            )));
        };

        Ok(Self { client })
    }

    fn audit_step<'w>(&self, step: &Step<'w>) -> Result<Vec<Finding<'w>>> {
        self.process_step(step)
    }

    fn audit_composite_step<'a>(&self, step: &CompositeStep<'a>) -> Result<Vec<Finding<'a>>> {
        self.process_step(step)
    }
}
