//! Audits reusable workflows and pinned actions for "impostor" commits,
//! using the ref lookup technique from [`clank`].
//!
//! `clank` is licensed by Chainguard under the Apache-2.0 License.
//!
//! [`clank`]: https://github.com/chainguard-dev/clank

use std::{
    collections::{hash_map::Entry, HashMap},
    ops::Deref,
};

use anyhow::{anyhow, Result};
use github_actions_models::workflow::{job::StepBody, Job};

use super::WorkflowAudit;
use crate::{
    finding::{Confidence, Finding, Severity},
    github_api::{self, Branch, ComparisonStatus, Tag},
    models::{Uses, Workflow},
    AuditConfig,
};

pub const IMPOSTOR_ANNOTATION: &str = "uses a commit that doesn't belong to the specified org/repo";

pub(crate) struct ImpostorCommit<'a> {
    pub(crate) _config: AuditConfig<'a>,
    pub(crate) client: github_api::Client,
    pub(crate) ref_cache: HashMap<(String, String), (Vec<Branch>, Vec<Tag>)>,
    /// A cache of `(base_ref, head_ref) => status`.
    ///
    /// We don't bother disambiguating this cache by org/repo, since `head_ref`
    /// is a commit ref and we expect those to be globally unique.
    /// This is not technically true of Git SHAs due to SHAttered, but is
    /// effectively true for SHAs on GitHub due to GitHub's collision detection.
    pub(crate) ref_comparison_cache: HashMap<(String, String), bool>,
}

impl<'a> ImpostorCommit<'a> {
    fn named_refs(&mut self, uses: Uses<'_>) -> Result<(Vec<Branch>, Vec<Tag>)> {
        let entry = match self
            .ref_cache
            .entry((uses.owner.to_string(), uses.repo.to_string()))
        {
            Entry::Occupied(o) => o.into_mut(),
            Entry::Vacant(v) => {
                let branches = self.client.list_branches(uses.owner, uses.repo)?;
                let tags = self.client.list_tags(uses.owner, uses.repo)?;

                v.insert((branches, tags))
            }
        };

        // Dumb: we shold be able to borrow immutably here.
        Ok((entry.0.clone(), entry.1.clone()))
    }

    fn named_ref_contains_commit(
        &mut self,
        uses: &Uses<'_>,
        base_ref: &str,
        head_ref: &str,
    ) -> Result<bool> {
        let presence = match self
            .ref_comparison_cache
            .entry((base_ref.to_string(), head_ref.to_string()))
        {
            Entry::Occupied(o) => {
                log::debug!("cache hit: {base_ref}..{head_ref}");
                o.into_mut()
            }
            Entry::Vacant(v) => {
                let presence = match self
                    .client
                    .compare_commits(uses.owner, uses.repo, base_ref, head_ref)?
                {
                    // A base ref "contains" a commit if the base is either identical
                    // to the head ("identical") or the target is behind the base ("behind").
                    Some(comp) => matches!(
                        comp.status,
                        ComparisonStatus::Behind | ComparisonStatus::Identical
                    ),
                    // GitHub's API returns 404 when the refs under comparison
                    // are completely divergent, i.e. no contains relationship is possible.
                    None => false,
                };

                v.insert(presence)
            }
        };

        Ok(*presence)
    }

    /// Returns a boolean indicating whether or not this commit is an "impostor",
    /// i.e. resolves due to presence in GitHub's fork network but is not actually
    /// present in any of the specified `owner/repo`'s tags or branches.
    fn impostor(&mut self, uses: Uses<'_>) -> Result<bool> {
        let (branches, tags) = self.named_refs(uses)?;

        // If there's no ref or the ref is not a commit, there's nothing to impersonate.
        let Some(head_ref) = uses.commit_ref() else {
            return Ok(false);
        };

        for branch in branches {
            if self.named_ref_contains_commit(
                &uses,
                &format!("refs/heads/{}", &branch.name),
                head_ref,
            )? {
                return Ok(false);
            }
        }

        for tag in tags {
            if self.named_ref_contains_commit(
                &uses,
                &format!("refs/tags/{}", &tag.name),
                head_ref,
            )? {
                return Ok(false);
            }
        }

        // If we've made it here, the commit isn't present in any commit or tag's history,
        // strongly suggesting that it's an impostor.
        log::warn!(
            "strong impostor candidate: {head_ref} for {org}/{repo}",
            org = uses.owner,
            repo = uses.repo
        );
        Ok(true)
    }
}

impl<'a> WorkflowAudit<'a> for ImpostorCommit<'a> {
    fn ident() -> &'static str {
        "impostor-commit"
    }

    fn new(config: AuditConfig<'a>) -> Result<Self> {
        if config.offline {
            return Err(anyhow!("offline audits only requested"));
        }

        let Some(gh_token) = config.gh_token else {
            return Err(anyhow!("can't audit without a GitHub API token"));
        };

        let client = github_api::Client::new(gh_token);

        Ok(ImpostorCommit {
            _config: config,
            client,
            ref_cache: Default::default(),
            ref_comparison_cache: Default::default(),
        })
    }

    fn audit<'w>(&mut self, workflow: &'w Workflow) -> Result<Vec<Finding<'w>>> {
        let mut findings = vec![];

        for job in workflow.jobs() {
            match *job {
                Job::NormalJob(_) => {
                    for step in job.steps() {
                        let StepBody::Uses { uses, .. } = &step.deref().body else {
                            continue;
                        };

                        let Some(uses) = Uses::from_step(uses) else {
                            continue;
                        };

                        if self.impostor(uses)? {
                            findings.push(
                                Self::finding()
                                    .severity(Severity::High)
                                    .confidence(Confidence::High)
                                    .add_location(step.location().annotated(IMPOSTOR_ANNOTATION))
                                    .build(workflow)?,
                            );
                        }
                    }
                }
                Job::ReusableWorkflowCallJob(reusable) => {
                    // Reusable workflows can also be commit pinned, meaning
                    // they can also be impersonated.
                    let Some(uses) = Uses::from_reusable(&reusable.uses) else {
                        continue;
                    };

                    if self.impostor(uses)? {
                        findings.push(
                            Self::finding()
                                .severity(Severity::High)
                                .confidence(Confidence::High)
                                .add_location(job.location().annotated(IMPOSTOR_ANNOTATION))
                                .build(workflow)?,
                        );
                    }
                }
            }
        }

        Ok(findings)
    }
}
