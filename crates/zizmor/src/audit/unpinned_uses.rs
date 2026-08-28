use std::borrow::Cow;

use github_actions_models::common::Uses;
use subfeature::Subfeature;
use yamlpatch::{Op, Patch};

use super::{Audit, AuditLoadError, AuditState, audit_meta};
use crate::audit::AuditError;
use crate::config::{Config, UsesPolicy};
use crate::finding::location::{Locatable, Routable as _};
use crate::finding::{Confidence, Finding, Fix, Persona, Severity};
use crate::github;
use crate::models::uses::{RepositoryUsesExt as _, RepositoryUsesPattern};
use crate::models::version::Version;
use crate::models::workflow::ReusableWorkflowCallJob;
use crate::models::{
    AsDocument, StepCommon, action::CompositeStep, uses::UsesExt as _, workflow::Step,
};

pub(crate) struct UnpinnedUses {
    client: Option<github::Client>,
}

audit_meta!(UnpinnedUses, "unpinned-uses", "unpinned action reference");

impl UnpinnedUses {
    async fn attempt_fix<'a, 'doc>(
        &self,
        parent: &impl Locatable<'doc>,
        uses: &Uses,
    ) -> Option<Fix<'doc>> {
        // We need to be online to attempt fixes for this audit.
        let client = self.client.as_ref()?;

        // We can only fix repository uses for now.
        let Uses::Repository(uses) = uses else {
            return None;
        };

        // There's nothing to fix if the ref is already a commit SHA.
        if uses.ref_is_commit() {
            return None;
        }

        // Only attempt a fix if the git ref _looks_ like it might be a
        // version, e.g. `@v1`, `@1.2.3`, etc. Technically we can hash-pin
        // any symbolic ref, but we don't want to do so automatically for refs
        // like `@main`, `@stable`, etc. because other tools like Dependabot
        // and pinact don't handle those gracefully.
        // The user can always pin manually if they so desire.
        if Version::parse(uses.git_ref()).is_err() {
            tracing::debug!("not proposing an auto-fix for a non-version ref: {uses}");
            return None;
        }

        let git_ref = match client.lookup_ref(&uses.into(), uses.git_ref()).await {
            Ok(Some(git_ref)) => git_ref,
            Ok(None) => {
                tracing::warn!("no commit matching {uses}");
                return None;
            }
            Err(e) => {
                // TODO: hard-fail here instead?
                tracing::warn!(
                    "failed to look up commit for {uses}: {e}",
                    uses = uses.raw()
                );
                return None;
            }
        };

        // Resolve the commit back to its longest tag; pinning to the full
        // version avoids any later `ref-version-mismatch` findings when the
        // major tag is mutated by the upstream.
        let longest_tag = match client
            .longest_tag_for_commit(&uses.into(), uses.subpath(), git_ref.commit())
            .await
        {
            Ok(Some(tag)) => Cow::Owned(tag.name),
            // Our original tag -> commit lookup succeeded, but this reverse lookup
            // failed, which makes no sense. Just fall back to what we know.
            _ => Cow::Borrowed(uses.git_ref()),
        };

        let action = if let Some(subpath) = uses.subpath() {
            format!("{}/{}", uses.slug(), subpath)
        } else {
            uses.slug().to_string()
        };

        // For the fix itself, we need to situate two patches:
        // 1. `uses: foo/bar@ref` -> `uses: foo/bar@hashhashhash`
        // 2. A `# <ref>` comment following the `uses:` clause.
        Some(Fix {
            title: format!("pin {action}@{ref} to {commit}", ref = uses.git_ref(), commit = git_ref.commit()),
            key: parent.location().key,
            disposition: Default::default(),
            patches: vec![
                Patch {
                    route: parent.route().with_key("uses"),
                    operation: Op::Replace(
                        format!("{action}@{commit}", commit = git_ref.commit()).into(),
                    ),
                },
                Patch {
                    route: parent.route().with_key("uses"),
                    operation: Op::EmplaceComment {
                        new: format!("# {longest_tag}").into(),
                    },
                },
            ],
        })
    }

    async fn evaluate_pinning<'doc>(
        &self,
        parent: &impl Locatable<'doc>,
        uses: &'doc Uses,
        config: &Config,
    ) -> Option<(String, Severity, Persona, Option<Fix<'doc>>)> {
        match uses {
            // Don't evaluate pinning for local `uses:`, since unpinned references
            // are fully controlled by the repository anyways.
            // TODO: auditor-level findings instead, perhaps?
            Uses::Local(_) => None,
            // This is handled by the `unpinned-images` audit.
            Uses::Docker(_) => None,
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
                        self.attempt_fix(parent, uses).await,
                    )),
                    UsesPolicy::HashPin => uses.unhashed().then_some((
                        format!("action is not pinned to a hash (required by {pat_desc} policy)"),
                        Severity::High,
                        Persona::default(),
                        self.attempt_fix(parent, uses).await,
                    )),
                }
            }
        }
    }

    async fn process_uses<'a, 'doc, S>(
        &self,
        uses: &'doc Uses,
        parent: &'a S,
        config: &Config,
    ) -> Result<Option<Finding<'doc>>, AuditError>
    where
        S: Locatable<'doc> + AsDocument<'a, 'doc>,
    {
        let Some((annotation, severity, persona, fix)) =
            self.evaluate_pinning(parent, uses, config).await
        else {
            return Ok(None);
        };

        let mut builder = Self::finding()
            .confidence(Confidence::High)
            .severity(severity)
            .persona(persona)
            .add_location(parent.location().hidden())
            .add_location(
                parent
                    .location()
                    .primary()
                    .with_keys(["uses".into()])
                    .subfeature(Subfeature::new(0, uses.raw()))
                    .annotated(annotation),
            );

        if let Some(fix) = fix {
            builder = builder.fix(fix);
        }

        Ok(Some(builder.build(parent)?))
    }

    async fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let Some(uses) = step.uses() else {
            return Ok(vec![]);
        };

        Ok(self
            .process_uses(uses, step, config)
            .await?
            .into_iter()
            .collect())
    }
}

#[async_trait::async_trait]
impl Audit for UnpinnedUses {
    fn new(state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self {
            client: state.gh_client.clone(),
        })
    }

    async fn audit_step<'doc>(
        &self,
        step: &Step<'doc>,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step, config).await
    }

    async fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
        config: &Config,
    ) -> Result<Vec<Finding<'a>>, AuditError> {
        self.process_step(step, config).await
    }

    async fn audit_reusable_job<'doc>(
        &self,
        job: &ReusableWorkflowCallJob<'doc>,
        config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        Ok(self
            .process_uses(&job.uses, job, config)
            .await?
            .into_iter()
            .collect())
    }
}
