//! Audits reusable workflows and pinned actions for "impostor" commits,
//! using the ref lookup technique from [`clank`].
//!
//! `clank` is licensed by Chainguard under the Apache-2.0 License.
//!
//! [`clank`]: https://github.com/chainguard-dev/clank

use std::borrow::Cow;

use anyhow::anyhow;
use github_actions_models::common::{RepositoryUses, Uses};
use subfeature::Subfeature;

use super::{Audit, AuditLoadError, Job, audit_meta};
use crate::{
    audit::AuditError,
    config::Config,
    finding::{Confidence, Finding, Severity, location::Locatable as _},
    github::{self, ComparisonStatus},
    models::{StepCommon as _, uses::RepositoryUsesExt as _, workflow::Workflow},
    state::AuditState,
};

pub const IMPOSTOR_ANNOTATION: &str = "uses a commit that doesn't belong to the specified org/repo";

pub(crate) struct ImpostorCommit {
    pub(crate) client: github::Client,
}

audit_meta!(
    ImpostorCommit,
    "impostor-commit",
    "commit with no history in referenced repository"
);

/// An intermediate result type for the impostor check. This is used to
/// encode our fallthroughs from fastest -> fast -> slow paths for
/// impostor checks.
enum IntermediateDetermination {
    /// Definitely an impostor.
    NotImpostor,
    /// Definitely not an impostor.
    Impostor,
    /// Not sure yet.
    Indeterminate,
}

impl ImpostorCommit {
    async fn named_ref_contains_commit(
        &self,
        uses: &RepositoryUses,
        base_ref: &str,
        head_ref: &str,
    ) -> Result<bool, AuditError> {
        Ok(
            match self
                .client
                .compare_commits(uses.owner(), uses.repo(), base_ref, head_ref)
                .await
                .map_err(Self::err)?
            {
                // A base ref "contains" a commit if the base is either identical
                // to the head ("identical") or the target is behind the base ("behind").
                Some(comp) => {
                    matches!(comp, ComparisonStatus::Behind | ComparisonStatus::Identical)
                }
                // GitHub's API returns 404 when the refs under comparison
                // are completely divergent, i.e. no contains relationship is possible.
                None => false,
            },
        )
    }

    /// Our "fastest path" impostor check: iterate through the remote's tags and branches
    /// and see if any of them point directly at `candidate_sha`. This is fast for two reasons:
    ///
    /// 1. We expect the majority of users to be on the happy path where their hash-pin
    ///    is directly at the tip of some tag or branch.
    /// 2. Internally, listing refs is very cheap within zizmor (since we GitHub's
    ///    Git backend directly, not the REST API), at least compared to a REST API roundtrip.
    async fn fastest_path_impostor_check(
        &self,
        tags: &[github::Tag],
        branches: &[github::Branch],
        candidate_sha: &str,
    ) -> Result<IntermediateDetermination, AuditError> {
        for tag in tags {
            if tag.commit.sha == candidate_sha {
                return Ok(IntermediateDetermination::NotImpostor);
            }
        }

        for branch in branches {
            if branch.commit.sha == candidate_sha {
                return Ok(IntermediateDetermination::NotImpostor);
            }
        }

        Ok(IntermediateDetermination::Indeterminate)
    }

    /// Our second fastest impostor check: we use GitHub's undocumented
    /// `branch_commits` API, which is what GitHub's own frontend uses to
    /// perform a fast check for which tags and/or branches a commit SHA
    /// appears on.
    ///
    /// TODO: Benchmark this more; this might actually be faster than listing refs?
    /// We currently assume this is slower because it's through the REST API.
    async fn fast_path_impostor_check(
        &self,
        uses: &RepositoryUses,
        candidate_sha: &str,
    ) -> IntermediateDetermination {
        match self
            .client
            .branch_commits(uses.owner(), uses.repo(), candidate_sha)
            .await
        {
            Ok(branch_commits) => {
                if branch_commits.is_empty() {
                    IntermediateDetermination::Impostor
                } else {
                    IntermediateDetermination::NotImpostor
                }
            }
            Err(e) => {
                tracing::warn!("fast path impostor check failed for {uses}: {e}");
                IntermediateDetermination::Indeterminate
            }
        }
    }

    /// Perform both our fastest path and fast path impostor check on the candidate SHA.
    async fn combined_fast_paths_impostor_check(
        &self,
        uses: &RepositoryUses,
        tags: &[github::Tag],
        branches: &[github::Branch],
        candidate_sha: &str,
    ) -> Result<IntermediateDetermination, AuditError> {
        match self
            .fastest_path_impostor_check(tags, branches, candidate_sha)
            .await?
        {
            IntermediateDetermination::Indeterminate => {
                Ok(self.fast_path_impostor_check(uses, candidate_sha).await)
            }
            determination => Ok(determination),
        }
    }

    /// Our slow path for impostor checks: we use GitHub's comparison API
    /// to see whether any tag or branch in the repo has the candidate SHA
    /// in its history.
    ///
    /// This is ludicrously slow, both because this endpoint is slow
    /// and because in the worst case it requires pathological numbers
    /// of requests (thousands for repos with thousands of branches or tags).
    async fn slow_path_impostor_check(
        &self,
        uses: &RepositoryUses,
        tags: &[github::Tag],
        branches: &[github::Branch],
        candidate_sha: &str,
    ) -> Result<IntermediateDetermination, AuditError> {
        for branch in branches {
            if self
                .named_ref_contains_commit(
                    uses,
                    &format!("refs/heads/{}", branch.name),
                    candidate_sha,
                )
                .await?
            {
                return Ok(IntermediateDetermination::NotImpostor);
            }
        }

        for tag in tags {
            if self
                .named_ref_contains_commit(uses, &format!("refs/tags/{}", tag.name), candidate_sha)
                .await?
            {
                return Ok(IntermediateDetermination::NotImpostor);
            }
        }

        // At this point we pretty much know it's an impostor commit,
        // but we don't make that classification here.
        Ok(IntermediateDetermination::Indeterminate)
    }

    /// Returns a boolean indicating whether or not this commit is an "impostor",
    /// i.e. resolves due to presence in GitHub's fork network but is not actually
    /// present in any of the specified `owner/repo`'s tags or branches.
    async fn impostor(&self, uses: &RepositoryUses) -> Result<bool, AuditError> {
        // If there's no ref or the ref is not a commit, there's nothing to impersonate.
        let Some(initial_candidate_sha) = uses.commit_ref() else {
            return Ok(false);
        };

        // Our logic is a little nuanced here: we have two fast paths, and we want to try
        // both fast paths on the commit SHA before we fall back to the slow path.
        // So what we do is first try the fast paths while *assuming* that the user has
        // hash-pinned to a commit SHA. If that fails we then treat their hash-pin
        // as a tag SHA, try the fast paths again, and then only fall through
        // to the slow path after that.

        let tags = self
            .client
            .list_tags(uses.owner(), uses.repo())
            .await
            .map_err(Self::err)?;

        let branches = self
            .client
            .list_branches(uses.owner(), uses.repo())
            .await
            .map_err(Self::err)?;

        match self
            .combined_fast_paths_impostor_check(uses, &tags, &branches, initial_candidate_sha)
            .await?
        {
            IntermediateDetermination::NotImpostor => return Ok(false),
            IntermediateDetermination::Impostor => return Ok(true),
            IntermediateDetermination::Indeterminate => {
                // Fall through.
            }
        }

        // If our first set of fast paths didn't work then `initial_candidate_sha`
        // might actually be a tag SHA, so we need to peel it to find the real
        // underlying commit SHA for the checks below.
        let final_candidate_sha: Cow<'_, str> = match self
            .client
            .tag_sha_to_commit_sha(uses.owner(), uses.repo(), initial_candidate_sha)
            .await
            .map_err(Self::err)?
        {
            Some(sha) => sha.into(),
            None => initial_candidate_sha.into(),
        };

        // At this point we definitely have a commit SHA, so try the fast
        // paths again if the SHA has changed.
        if initial_candidate_sha != final_candidate_sha {
            match self
                .combined_fast_paths_impostor_check(uses, &tags, &branches, &final_candidate_sha)
                .await?
            {
                IntermediateDetermination::NotImpostor => return Ok(false),
                IntermediateDetermination::Impostor => return Ok(true),
                IntermediateDetermination::Indeterminate => {
                    // Fall through.
                }
            }
        }

        match self
            .slow_path_impostor_check(uses, &tags, &branches, &final_candidate_sha)
            .await?
        {
            IntermediateDetermination::NotImpostor => Ok(false),
            // If we've made it here, the commit isn't present in any commit or tag's history,
            // strongly suggesting that it's an impostor.
            _ => Ok(true),
        }
    }
}

#[async_trait::async_trait]
impl Audit for ImpostorCommit {
    fn new(state: &AuditState) -> Result<Self, AuditLoadError> {
        if state.no_online_audits {
            return Err(AuditLoadError::Skip(anyhow!(
                "offline audits only requested"
            )));
        }

        state
            .gh_client
            .clone()
            .ok_or_else(|| AuditLoadError::Skip(anyhow!("can't run without a GitHub API token")))
            .map(|client| ImpostorCommit { client })
    }

    async fn audit_workflow<'doc>(
        &self,
        workflow: &'doc Workflow,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        for job in workflow.jobs() {
            match job {
                Job::NormalJob(normal) => {
                    for step in normal.steps() {
                        let Some(Uses::Repository(uses)) = step.uses() else {
                            continue;
                        };

                        if self.impostor(uses).await? {
                            let finding_builder = Self::finding()
                                .severity(Severity::High)
                                .confidence(Confidence::High)
                                .add_location(step.location_with_grip())
                                .add_location(
                                    step.location()
                                        .with_keys(["uses".into()])
                                        .subfeature(Subfeature::new(0, uses.raw()))
                                        .primary()
                                        .annotated(IMPOSTOR_ANNOTATION),
                                );

                            findings.push(finding_builder.build(workflow).map_err(Self::err)?);
                        }
                    }
                }
                Job::ReusableWorkflowCallJob(reusable) => {
                    // Reusable workflows can also be commit pinned, meaning
                    // they can also be impersonated.
                    let Uses::Repository(uses) = &reusable.uses else {
                        continue;
                    };

                    if self.impostor(uses).await? {
                        let finding_builder = Self::finding()
                            .severity(Severity::High)
                            .confidence(Confidence::High)
                            .add_location(reusable.location_with_grip())
                            .add_location(
                                reusable
                                    .location()
                                    .with_keys(["uses".into()])
                                    .subfeature(Subfeature::new(0, uses.raw()))
                                    .primary()
                                    .annotated(IMPOSTOR_ANNOTATION),
                            );

                        findings.push(finding_builder.build(workflow).map_err(Self::err)?);
                    }
                }
            }
        }

        Ok(findings)
    }

    async fn audit_composite_step<'a>(
        &self,
        step: &super::CompositeStep<'a>,
        _config: &Config,
    ) -> Result<Vec<Finding<'a>>, AuditError> {
        let mut findings = vec![];
        let Some(Uses::Repository(uses)) = step.uses() else {
            return Ok(findings);
        };

        if self.impostor(uses).await? {
            let finding_builder = Self::finding()
                .severity(Severity::High)
                .confidence(Confidence::High)
                .add_location(step.location_with_grip())
                .add_location(
                    step.location()
                        .with_keys(["uses".into()])
                        .subfeature(Subfeature::new(0, uses.raw()))
                        .primary()
                        .annotated(IMPOSTOR_ANNOTATION),
                );

            findings.push(finding_builder.build(step).map_err(Self::err)?);
        }

        Ok(findings)
    }
}
