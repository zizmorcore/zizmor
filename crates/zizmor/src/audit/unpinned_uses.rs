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
use crate::models::pre_commit::{PreCommitConfig, Repo};
use crate::models::repo_ref::RepoRef;
use crate::models::uses::RepositoryUsesPattern;
use crate::models::version::Version;
use crate::models::workflow::ReusableWorkflowCallJob;
use crate::models::{AsDocument, StepCommon, action::CompositeStep, workflow::Step};
use crate::registry::input::InputGroup;
use crate::utils::once::debug_once;

pub(crate) struct UnpinnedUses {
    client: Option<github::Client>,
}

audit_meta!(UnpinnedUses, "unpinned-uses", "unpinned action reference");

impl UnpinnedUses {
    async fn attempt_fix<'a, 'doc>(
        &self,
        parent: &impl Locatable<'doc>,
        uses: &RepoRef<'doc>,
    ) -> Option<Fix<'doc>> {
        // We need to be online to attempt fixes for this audit.
        let client = self.client.as_ref()?;

        // There's nothing to fix if we don't have a GitHub slug.
        let slug = uses.slug()?;

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
            tracing::debug!("not proposing an auto-fix for a non-version ref: {uses:?}");
            return None;
        }

        let git_ref = match client.lookup_ref(&slug, uses.git_ref()).await {
            Ok(Some(git_ref)) => git_ref,
            Ok(None) => {
                tracing::warn!("no commit matching {uses:?}");
                return None;
            }
            Err(e) => {
                // TODO: hard-fail here instead?
                tracing::warn!("failed to look up commit for {slug}: {e}");
                return None;
            }
        };

        // Resolve the commit back to its longest tag; pinning to the full
        // version avoids any later `ref-version-mismatch` findings when the
        // major tag is mutated by the upstream.
        let longest_tag = match client
            .longest_tag_for_commit(&slug, uses.subpath(), git_ref.commit())
            .await
        {
            Ok(Some(tag)) => Cow::Owned(tag.name),
            // Our original tag -> commit lookup succeeded, but this reverse lookup
            // failed, which makes no sense. Just fall back to what we know.
            _ => Cow::Borrowed(uses.git_ref()),
        };

        let action = if let Some(subpath) = uses.subpath() {
            format!("{}/{}", slug, subpath)
        } else {
            slug.to_string()
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

    /// Evaluate a [`RepoRef`]'s pinning against the configured policies.
    async fn evaluate_pinning<'doc>(
        &self,
        parent: Option<&impl Locatable<'doc>>,
        uses: impl Into<RepoRef<'doc>>,
        config: &Config,
    ) -> Option<(String, Severity, Persona, Option<Fix<'doc>>)> {
        let uses = uses.into();

        let (pattern, policy) = config.unpinned_uses_policies.get_policy(&uses);

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
            // [`RepoRef`] instances are at least ref-pinned, by construction.
            UsesPolicy::RefPin => None,
            UsesPolicy::HashPin => (!uses.ref_is_commit()).then_some((
                format!("is not pinned to a hash (required by {pat_desc} policy)"),
                Severity::High,
                Persona::default(),
                match parent.map(async |parent| self.attempt_fix(parent, &uses).await) {
                    Some(fut) => fut.await,
                    None => None,
                },
            )),
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
        // Local `uses:` are not meaningfully pinnable, and Docker-based
        // `uses:` are checked by the `unpinned-images` audit.
        let Uses::Repository(uses) = uses else {
            return Ok(None);
        };

        let Some((annotation, severity, persona, fix)) =
            self.evaluate_pinning(Some(parent), uses, config).await
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
        group: &crate::registry::input::InputGroup,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        // If we have a lockfile and this step's workflow is present in it,
        // then all steps are pinned regardless of their `uses:` form.
        if let Some(lock) = group.lock()
            && lock.is_locked(step.as_ref())
        {
            debug_once!(
                "{input} is covered by a lockfile, no unpinned uses checks needed",
                input = step.as_ref()
            );

            return Ok(vec![]);
        }

        self.process_step(step, group.config()).await
    }

    async fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
        group: &crate::registry::input::InputGroup,
    ) -> Result<Vec<Finding<'a>>, AuditError> {
        // NOTE: observe that we have no lockfile check here,
        // since action definitions cannot be directly locked
        // yet.
        // See: <https://github.com/github/gh-actions-lock/issues/183>
        self.process_step(step, group.config()).await
    }

    async fn audit_reusable_job<'doc>(
        &self,
        job: &ReusableWorkflowCallJob<'doc>,
        group: &crate::registry::input::InputGroup,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        // NOTE: GitHub's lockfile does not support reusable workflows
        // yet, so we have no lockfile check here.
        // See: <https://github.com/github/gh-actions-lock/issues/179>
        Ok(self
            .process_uses(&job.uses, job, group.config())
            .await?
            .into_iter()
            .collect())
    }

    async fn audit_pre_commit_config<'doc>(
        &self,
        pre_commit: &'doc PreCommitConfig,
        group: &InputGroup,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        let config = group.config();
        for repo in pre_commit.repos() {
            let Some(remote) = repo.repo() else {
                continue;
            };

            let repo_ref = RepoRef::from(remote);

            let Some((annotation, severity, persona, fix)) =
                self.evaluate_pinning(None::<&Repo>, repo_ref, config).await
            else {
                continue;
            };

            let mut builder = Self::finding()
                .confidence(Confidence::High)
                .severity(severity)
                .persona(persona)
                .add_location(repo.location().hidden())
                .add_location(
                    repo.location()
                        .with_keys(["repo".into()])
                        .subfeature(Subfeature::new(0, remote.repo.as_str()))
                        .annotated("this pre-commit hook"),
                )
                .add_location(
                    repo.location()
                        .with_keys(["rev".into()])
                        .subfeature(Subfeature::new(0, remote.rev.as_str()))
                        .annotated(annotation)
                        .primary(),
                );

            // TODO: This is always `None` at the moment because we don't
            // pass in a parent location above. Figure out a good auto-fix
            // strategy here.
            if let Some(fix) = fix {
                builder = builder.fix(fix);
            }

            findings.push(builder.build(pre_commit)?);
        }

        Ok(findings)
    }
}
