use github_actions_models::common::Uses;
use subfeature::Subfeature;
use yamlpatch::{Op, Patch};

use super::{Audit, AuditLoadError, AuditState, audit_meta};
use crate::audit::AuditError;
use crate::config::{Config, UsesPolicy};
use crate::finding::location::Locatable;
use crate::finding::{Confidence, Finding, Fix, Severity};
use crate::github;
use crate::models::pre_commit;
use crate::models::repo_ref::RepoRef;
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
    /// Pin a version-like GitHub ref to its commit and record the tag in a comment.
    async fn attempt_fix<'doc>(
        &self,
        parent: &impl Locatable<'doc>,
        repo: &RepoRef<'doc>,
    ) -> Option<Fix<'doc>> {
        let client = self.client.as_ref()?;
        let slug = repo.slug()?;
        let git_ref = repo.git_ref();

        // Only attempt a fix if the git ref _looks_ like it might be a
        // version, e.g. `@v1`, `@1.2.3`, etc. Technically we can hash-pin
        // any symbolic ref, but we don't want to do so automatically for refs
        // like `@main`, `@stable`, etc. because other tools like Dependabot
        // and pinact don't handle those gracefully.
        // The user can always pin manually if they so desire.
        if Version::parse(git_ref).is_err() {
            tracing::debug!("not proposing an auto-fix for a non-version ref: {repo:?}");
            return None;
        }

        let resolved = match client.lookup_ref(&slug, git_ref).await {
            Ok(Some(resolved)) => resolved,
            Ok(None) => {
                tracing::warn!("no commit matching {repo:?}");
                return None;
            }
            Err(e) => {
                // TODO: hard-fail here instead?
                tracing::warn!("failed to look up commit for {slug}: {e}");
                return None;
            }
        };
        let commit = resolved.commit();

        // Resolve the commit back to its longest tag; pinning to the full
        // version avoids any later `ref-version-mismatch` findings when the
        // major tag is mutated by the upstream.
        let longest_tag = match client
            .longest_tag_for_commit(&slug, repo.subpath(), commit)
            .await
        {
            Ok(Some(tag)) => tag.name,
            // Our original tag -> commit lookup succeeded, but this reverse lookup
            // failed, which makes no sense. Just fall back to what we know.
            _ => git_ref.to_owned(),
        };

        let (field, title, replacement) = match repo {
            RepoRef::Uses(uses) => {
                let action = match uses.subpath() {
                    Some(subpath) => format!("{slug}/{subpath}"),
                    None => slug.to_string(),
                };
                (
                    "uses",
                    format!("pin {action}@{git_ref} to {commit}"),
                    format!("{action}@{commit}"),
                )
            }
            RepoRef::Url { .. } | RepoRef::Scp { .. } => {
                ("rev", format!("pin {slug} to {commit}"), commit.to_owned())
            }
        };
        let location = parent.location().with_keys([field.into()]);

        Some(Fix {
            title,
            key: location.key,
            disposition: Default::default(),
            patches: vec![
                Patch {
                    route: location.route.clone(),
                    operation: Op::Replace(replacement.into()),
                },
                Patch {
                    route: location.route,
                    operation: Op::EmplaceComment {
                        new: format!("# {longest_tag}").into(),
                    },
                },
            ],
        })
    }

    fn pinning_annotation(repo: &RepoRef<'_>, config: &Config) -> Option<String> {
        if repo.ref_is_commit() {
            return None;
        }

        // Every repository reference already satisfies a ref-pin policy.
        let (pattern, UsesPolicy::HashPin) = config.unpinned_uses_policies.get_policy(repo) else {
            return None;
        };

        let policy = pattern.map_or_else(|| "blanket".to_owned(), ToString::to_string);

        Some(format!(
            "is not pinned to a hash (required by {policy} policy)"
        ))
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

        let repo = RepoRef::from(uses);
        let Some(annotation) = Self::pinning_annotation(&repo, config) else {
            return Ok(None);
        };

        let mut builder = Self::finding()
            .confidence(Confidence::High)
            .severity(Severity::High)
            .add_location(parent.location().hidden())
            .add_location(
                parent
                    .location()
                    .primary()
                    .with_keys(["uses".into()])
                    .subfeature(Subfeature::new(0, uses.raw()))
                    .annotated(annotation),
            );

        if let Some(fix) = self.attempt_fix(parent, &repo).await {
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

    async fn audit_pre_commit_config_repo<'doc>(
        &self,
        repo: &pre_commit::Repo<'doc>,
        group: &InputGroup,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let Some(remote) = repo.repo() else {
            return Ok(vec![]);
        };
        let repo_ref = RepoRef::from(remote);
        let Some(annotation) = Self::pinning_annotation(&repo_ref, group.config()) else {
            return Ok(vec![]);
        };

        let mut builder = Self::finding()
            .confidence(Confidence::High)
            .severity(Severity::High)
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

        if let Some(fix) = self.attempt_fix(repo, &repo_ref).await {
            builder = builder.fix(fix);
        }

        Ok(vec![builder.build(repo)?])
    }
}
