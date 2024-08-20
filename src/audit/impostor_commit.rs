//! Audits reusable workflows and pinned actions for "impostor" commits,
//! using the ref lookup technique from [`clank`].
//!
//! `clank` is licensed by Chainguard under the Apache-2.0 License.
//!
//! [`clank`]: https://github.com/chainguard-dev/clank

use crate::{
    finding::{Confidence, Finding, JobIdentity, Severity, StepIdentity},
    models::{AuditConfig, Workflow},
};

use anyhow::Result;
use github_actions_models::workflow::{job::StepBody, Job};
use octocrab::{models::commits::GithubCommitStatus, Error, Octocrab};

use super::WorkflowAudit;

pub(crate) struct ImpostorCommit<'a> {
    pub(crate) _config: AuditConfig<'a>,
    pub(crate) client: Octocrab,
}

impl<'a> ImpostorCommit<'a> {
    /// Returns a boolean indicating whether or not this commit is an "impostor",
    /// i.e. resolves due to presence in GitHub's fork network but is not actually
    /// present in any of the specified `owner/repo`'s tags or branches.
    async fn impostor(&self, owner: &str, repo: &str, commit: &str) -> Result<bool> {
        let branches = self
            .client
            .repos(owner, repo)
            .list_branches()
            .send()
            .await?;

        for branch in &branches {
            if self
                .named_ref_contains_commit(
                    owner,
                    repo,
                    &format!("refs/heads/{}", &branch.name),
                    commit,
                )
                .await?
            {
                return Ok(false);
            }
        }

        let tags = self.client.repos(owner, repo).list_tags().send().await?;

        for tag in &tags {
            if self
                .named_ref_contains_commit(owner, repo, &format!("refs/tags/{}", &tag.name), commit)
                .await?
            {
                return Ok(false);
            }
        }

        // If we've made it here, the commit isn't present in any commit or tag's history,
        // strongly suggesting that it's an impostor.
        Ok(true)
    }

    async fn named_ref_contains_commit(
        &self,
        owner: &str,
        repo: &str,
        named_ref: &str,
        commit: &str,
    ) -> Result<bool> {
        match self
            .client
            .commits(owner, repo)
            .compare(named_ref, commit)
            .send()
            .await
        {
            Ok(diff) => Ok(matches!(
                diff.status,
                GithubCommitStatus::Behind | GithubCommitStatus::Identical
            )),
            Err(Error::GitHub { source, .. }) if source.status_code.as_u16() == 404 => Ok(false),
            Err(err) => Err(err.into()),
        }
    }
}

impl<'a> WorkflowAudit<'a> for ImpostorCommit<'a> {
    const AUDIT_IDENT: &'static str = "impostor-commit";

    fn new(config: AuditConfig<'a>) -> Result<Self> {
        let client = octocrab::OctocrabBuilder::new()
            .personal_token(config.gh_token.to_string())
            .build()?;

        Ok(ImpostorCommit {
            _config: config,
            client,
        })
    }

    async fn audit(&self, workflow: &Workflow) -> Result<Vec<Finding>> {
        log::debug!(
            "audit: {} evaluating {}",
            Self::AUDIT_IDENT,
            &workflow.filename
        );

        let mut findings = vec![];

        for (jobid, job) in workflow.jobs.iter() {
            match job {
                Job::NormalJob(job) => {
                    for (stepno, step) in job.steps.iter().enumerate() {
                        let StepBody::Uses { uses, .. } = &step.body else {
                            continue;
                        };

                        let Some((owner, repo, commit)) = action_components(uses) else {
                            continue;
                        };

                        if self.impostor(owner, repo, commit).await? {
                            findings.push(Finding {
                                ident: "impostor-commit",
                                workflow: workflow.filename.clone(),
                                severity: Severity::High,
                                confidence: Confidence::High,
                                job: Some(JobIdentity::new(jobid, job.name.as_deref())),
                                steps: vec![StepIdentity::new(stepno, step)],
                            })
                        }
                    }
                }
                Job::ReusableWorkflowCallJob(job) => {
                    // Reusable workflows can also be commit pinned, meaning
                    // they can also be impersonated.
                    let Some((owner, org, commit)) = reusable_workflow_components(&job.uses) else {
                        continue;
                    };

                    if self.impostor(owner, org, commit).await? {
                        findings.push(Finding {
                            ident: "impostor-commit",
                            workflow: workflow.filename.clone(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            job: Some(JobIdentity::new(jobid, job.name.as_deref())),
                            steps: vec![],
                        })
                    }
                }
            }
        }

        log::debug!(
            "audit: {} completed {}",
            Self::AUDIT_IDENT,
            &workflow.filename
        );

        Ok(findings)
    }
}

/// Returns a three-tuple of `(owner, repo, commit)` if the given action reference
/// is fully pinned to a commit, or `None` if the reference is either invalid or not pinned
/// to a commit.
fn action_components(uses: &str) -> Option<(&str, &str, &str)> {
    let (action_path, maybe_commit) = uses.rsplit_once('@')?;

    // Commit refs are always 40 hex characters; truncated commits are not permitted.
    if !maybe_commit.chars().all(|c| c.is_ascii_hexdigit()) || maybe_commit.len() != 40 {
        return None;
    }

    // We don't currently have enough context to resolve same-repository actions,
    // including third-party actions that get cloned into the current repo context.
    if action_path.starts_with("./") {
        log::warn!("can't infer org/repo for {uses}; skipping");
        return None;
    }

    // Docker actions are not pinned by commit.
    if action_path.starts_with("docker://") {
        return None;
    }

    // The action path begins with `owner/repo`. We can't assume there's only one
    // `/`, since the action may be in an arbitrary subdirectory within `repo`.
    let components = action_path.splitn(3, '/').collect::<Vec<_>>();
    if components.len() < 2 {
        return None;
    }

    Some((components[0], components[1], maybe_commit))
}

/// Returns a three-tuple of `(owner, repo, commit)` if the given reusable workflow reference
/// is fully pinned to a commit, or `None` if the reference is either invalid or not pinned
/// to a commit.
fn reusable_workflow_components(uses: &str) -> Option<(&str, &str, &str)> {
    let (workflow_path, maybe_commit) = uses.rsplit_once('@')?;

    // Commit refs are always 40 hex characters; truncated commits are not permitted.
    if !maybe_commit.chars().all(|c| c.is_ascii_hexdigit()) || maybe_commit.len() != 40 {
        return None;
    }

    // We don't currently have enough context to resolve same-repository reusable workflows.
    if workflow_path.starts_with("./") {
        log::warn!("can't infer org/repo for {uses}; skipping");
        return None;
    }

    // The workflow path begins with `owner/repo`
    let components = workflow_path.splitn(3, '/').collect::<Vec<_>>();
    if components.len() != 3 {
        return None;
    }

    Some((components[0], components[1], maybe_commit))
}

#[cfg(test)]
mod tests {
    use crate::audit::impostor_commit::{action_components, reusable_workflow_components};

    #[test]
    fn action_components_parses() {
        let vectors = [
            // Valid, as expected.
            (
                "actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3",
                Some((
                    "actions",
                    "checkout",
                    "8f4b7f84864484a7bf31766abe9204da3cbe65b3",
                )),
            ),
            // Valid: arbitrary parts don't interfere with parsing.
            (
                "actions/aws/ec2@8f4b7f84864484a7bf31766abe9204da3cbe65b3",
                Some(("actions", "aws", "8f4b7f84864484a7bf31766abe9204da3cbe65b3")),
            ),
            // Invalid: not a commit ref.
            ("actions/checkout@v4", None),
            // Invalid: not a valid commit ref (too short).
            ("actions/checkout@abcd", None),
            // Invalid: no ref at all
            ("actions/checkout", None),
            // Invalid: missing user/repo
            ("checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3", None),
            // Invalid: local action refs not supported
            (
                "./.github/actions/hello-world-action@172239021f7ba04fe7327647b213799853a9eb89",
                None,
            ),
            // Invalid: Docker refs not supported
            ("docker://alpine:3.8", None),
        ];

        for (input, expected) in vectors {
            assert_eq!(action_components(input), expected);
        }
    }

    #[test]
    fn reusable_workflow_components_parses() {
        let vectors = [
            // Valid, as expected.
            ("octo-org/this-repo/.github/workflows/workflow-1.yml@172239021f7ba04fe7327647b213799853a9eb89", Some(("octo-org", "this-repo", "172239021f7ba04fe7327647b213799853a9eb89"))),
            // Invalid: not a commit ref.
            ("octo-org/this-repo/.github/workflows/workflow-1.yml@notahash", None),
            // Invalid: not a valid commit ref (too short).
            ("octo-org/this-repo/.github/workflows/workflow-1.yml@abcd", None),
            // Invalid: no ref at all
            ("octo-org/this-repo/.github/workflows/workflow-1.yml", None),
            // Invalid: missing user/repo
            ("workflow-1.yml@172239021f7ba04fe7327647b213799853a9eb89", None),
            // Invalid: local reusable workflow refs not supported
            ("./.github/workflows/workflow-1.yml@172239021f7ba04fe7327647b213799853a9eb89", None),
        ];

        for (input, expected) in vectors {
            assert_eq!(reusable_workflow_components(input), expected);
        }
    }
}
