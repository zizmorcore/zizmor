use github_actions_models::common::Uses;
use subfeature::Subfeature;

use super::{Audit, AuditLoadError, AuditState, audit_meta};
use crate::audit::AuditError;
use crate::config::{Config, UsesPolicy};
use crate::finding::location::{Locatable, SymbolicLocation};
use crate::finding::{Confidence, Finding, Persona, Severity};
use crate::models::uses::RepositoryUsesPattern;
use crate::models::workflow::ReusableWorkflowCallJob;
use crate::models::{
    AsDocument, StepCommon, action::CompositeStep, uses::UsesExt as _, workflow::Step,
};

pub(crate) struct UnpinnedUses;

audit_meta!(UnpinnedUses, "unpinned-uses", "unpinned action reference");

impl UnpinnedUses {
    pub fn evaluate_pinning(
        &self,
        uses: &Uses,
        config: &Config,
    ) -> Option<(String, Severity, Persona)> {
        match uses {
            // Don't evaluate pinning for local `uses:`, since unpinned references
            // are fully controlled by the repository anyways.
            // TODO: auditor-level findings instead, perhaps?
            Uses::Local(_) => None,
            // We don't have detailed policies for `uses: docker://` yet,
            // in part because evaluating the risk of a tagged versus hash-pinned
            // Docker image depends on the image and its registry).
            //
            // Instead, we produce a blanket finding for unpinned images,
            // and a pedantic-only finding for unhashed images.
            Uses::Docker(_) => {
                if uses.unpinned() {
                    Some((
                        "image is not pinned to a tag, branch, or hash ref".into(),
                        Severity::Medium,
                        Persona::default(),
                    ))
                } else if uses.unhashed() {
                    Some((
                        "action is not pinned to a hash".into(),
                        Severity::Low,
                        Persona::Pedantic,
                    ))
                } else {
                    None
                }
            }
            Uses::Repository(repo_uses) => {
                let (pattern, policy) = config.unpinned_uses_policies.get_policy(repo_uses);

                let pat_desc = match pattern {
                    Some(RepositoryUsesPattern::Any) | None => "blanket".into(),
                    Some(RepositoryUsesPattern::InOwner(owner)) => format!("{owner}/*"),
                    Some(RepositoryUsesPattern::InRepo { owner, repo }) => {
                        format!("{owner}/{repo}/*")
                    }
                    Some(RepositoryUsesPattern::ExactRepo { owner, repo }) => {
                        format!("{owner}/{repo}")
                    }
                    Some(RepositoryUsesPattern::ExactPath {
                        owner,
                        repo,
                        subpath,
                    }) => {
                        format!("{owner}/{repo}/{subpath}")
                    }
                    // Not allowed in this audit.
                    Some(RepositoryUsesPattern::ExactWithRef { .. }) => unreachable!(),
                };

                match policy {
                    UsesPolicy::Any => None,
                    UsesPolicy::RefPin => uses.unpinned().then_some((
                        format!(
                            "action is not pinned to a ref or hash (required by {pat_desc} policy)"
                        ),
                        Severity::High,
                        Persona::default(),
                    )),
                    UsesPolicy::HashPin => uses.unhashed().then_some((
                        format!("action is not pinned to a hash (required by {pat_desc} policy)"),
                        Severity::High,
                        Persona::default(),
                    )),
                }
            }
        }
    }

    fn process_uses<'a, 'doc>(
        &self,
        uses: &'doc Uses,
        location: SymbolicLocation<'doc>,
        document: &'a impl AsDocument<'a, 'doc>,
        config: &Config,
    ) -> Result<Option<Finding<'doc>>, AuditError> {
        let Some((annotation, severity, persona)) = self.evaluate_pinning(uses, config) else {
            return Ok(None);
        };

        Ok(Some(
            Self::finding()
                .confidence(Confidence::High)
                .severity(severity)
                .persona(persona)
                .add_location(
                    location
                        .primary()
                        .with_keys(["uses".into()])
                        .subfeature(Subfeature::new(0, uses.raw()))
                        .annotated(annotation),
                )
                .build(document)?,
        ))
    }

    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let Some(uses) = step.uses() else {
            return Ok(vec![]);
        };

        Ok(self
            .process_uses(uses, step.location(), step, config)?
            .into_iter()
            .collect())
    }
}

#[async_trait::async_trait]
impl Audit for UnpinnedUses {
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

    async fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
        config: &Config,
    ) -> Result<Vec<Finding<'a>>, AuditError> {
        self.process_step(step, config)
    }

    async fn audit_reusable_job<'doc>(
        &self,
        job: &ReusableWorkflowCallJob<'doc>,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        Ok(self
            .process_uses(&job.uses, job.location(), job, config)?
            .into_iter()
            .collect())
    }
}
