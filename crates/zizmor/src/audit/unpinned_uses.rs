use github_actions_models::common::Uses;

use super::{Audit, AuditLoadError, AuditState, audit_meta};
use crate::config::{Config, UsesPolicy};
use crate::finding::{Confidence, Finding, Persona, Severity};
use crate::models::uses::RepositoryUsesPattern;
use crate::models::{StepCommon, action::CompositeStep, uses::UsesExt as _, workflow::Step};

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
                        "action is not pinned to a tag, branch, or hash ref".into(),
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

    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
        config: &Config,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        let Some(uses) = step.uses() else {
            return Ok(findings);
        };

        if let Some((annotation, severity, persona)) = self.evaluate_pinning(uses, config) {
            findings.push(
                Self::finding()
                    .confidence(Confidence::High)
                    .severity(severity)
                    .persona(persona)
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(["uses".into()])
                            .annotated(annotation),
                    )
                    .build(step)?,
            );
        };

        Ok(findings)
    }
}

impl Audit for UnpinnedUses {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_step<'doc>(
        &self,
        step: &Step<'doc>,
        config: &Config,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        self.process_step(step, config)
    }

    fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
        config: &Config,
    ) -> anyhow::Result<Vec<Finding<'a>>> {
        self.process_step(step, config)
    }
}
