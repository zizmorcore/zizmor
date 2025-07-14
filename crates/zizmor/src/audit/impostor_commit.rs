//! Audits reusable workflows and pinned actions for "impostor" commits,
//! using the ref lookup technique from [`clank`].
//!
//! `clank` is licensed by Chainguard under the Apache-2.0 License.
//!
//! [`clank`]: https://github.com/chainguard-dev/clank

use anyhow::{Result, anyhow};
use github_actions_models::common::{RepositoryUses, Uses};

use super::{Audit, AuditLoadError, Job, audit_meta};
use crate::{
    finding::{Confidence, Finding, Severity, location::Locatable as _},
    github_api::{self, ComparisonStatus},
    models::{StepCommon, uses::RepositoryUsesExt as _, workflow::Workflow},
    state::AuditState,
};

pub const IMPOSTOR_ANNOTATION: &str = "uses a commit that doesn't belong to the specified org/repo";

pub(crate) struct ImpostorCommit {
    pub(crate) client: github_api::Client,
}

audit_meta!(
    ImpostorCommit,
    "impostor-commit",
    "commit with no history in referenced repository"
);

impl ImpostorCommit {
    fn named_ref_contains_commit(
        &self,
        uses: &RepositoryUses,
        base_ref: &str,
        head_ref: &str,
    ) -> Result<bool> {
        Ok(
            match self
                .client
                .compare_commits(&uses.owner, &uses.repo, base_ref, head_ref)?
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

    /// Returns a boolean indicating whether or not this commit is an "impostor",
    /// i.e. resolves due to presence in GitHub's fork network but is not actually
    /// present in any of the specified `owner/repo`'s tags or branches.
    fn impostor(&self, uses: &RepositoryUses) -> Result<bool> {
        // If there's no ref or the ref is not a commit, there's nothing to impersonate.
        let Some(head_ref) = uses.commit_ref() else {
            return Ok(false);
        };

        // Fast path: almost all commit refs will be at the tip of
        // the branch or tag's history, so check those first.
        // Check tags before branches, since in practice version tags
        // are more commonly pinned.
        let tags = self.client.list_tags(&uses.owner, &uses.repo)?;

        for tag in &tags {
            if tag.commit.sha == head_ref {
                return Ok(false);
            }
        }

        let branches = self.client.list_branches(&uses.owner, &uses.repo)?;

        for branch in &branches {
            if branch.commit.sha == head_ref {
                return Ok(false);
            }
        }

        for branch in &branches {
            if self.named_ref_contains_commit(
                uses,
                &format!("refs/heads/{}", &branch.name),
                head_ref,
            )? {
                return Ok(false);
            }
        }

        for tag in &tags {
            if self.named_ref_contains_commit(
                uses,
                &format!("refs/tags/{}", &tag.name),
                head_ref,
            )? {
                return Ok(false);
            }
        }

        // If we've made it here, the commit isn't present in any commit or tag's history,
        // strongly suggesting that it's an impostor.
        tracing::warn!(
            "strong impostor candidate: {head_ref} for {org}/{repo}",
            org = uses.owner,
            repo = uses.repo
        );
        Ok(true)
    }
}

impl Audit for ImpostorCommit {
    fn new(state: &AuditState<'_>) -> Result<Self, AuditLoadError> {
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

    fn audit_workflow<'doc>(&self, workflow: &'doc Workflow) -> Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        for job in workflow.jobs() {
            match job {
                Job::NormalJob(normal) => {
                    for step in normal.steps() {
                        let Some(Uses::Repository(uses)) = step.uses() else {
                            continue;
                        };

                        if self.impostor(uses)? {
                            findings.push(
                                Self::finding()
                                    .severity(Severity::High)
                                    .confidence(Confidence::High)
                                    .add_location(
                                        step.location().primary().annotated(IMPOSTOR_ANNOTATION),
                                    )
                                    .build(workflow)?,
                            );
                        }
                    }
                }
                Job::ReusableWorkflowCallJob(reusable) => {
                    // Reusable workflows can also be commit pinned, meaning
                    // they can also be impersonated.
                    let Uses::Repository(uses) = &reusable.uses else {
                        continue;
                    };

                    if self.impostor(uses)? {
                        findings.push(
                            Self::finding()
                                .severity(Severity::High)
                                .confidence(Confidence::High)
                                .add_location(
                                    reusable.location().primary().annotated(IMPOSTOR_ANNOTATION),
                                )
                                .build(workflow)?,
                        );
                    }
                }
            }
        }

        Ok(findings)
    }

    fn audit_composite_step<'a>(
        &self,
        step: &super::CompositeStep<'a>,
    ) -> Result<Vec<Finding<'a>>> {
        let mut findings = vec![];
        let Some(Uses::Repository(uses)) = step.uses() else {
            return Ok(findings);
        };

        if self.impostor(uses)? {
            findings.push(
                Self::finding()
                    .severity(Severity::High)
                    .confidence(Confidence::High)
                    .add_location(step.location().primary().annotated(IMPOSTOR_ANNOTATION))
                    .build(step.action())?,
            );
        }

        Ok(findings)
    }
}
