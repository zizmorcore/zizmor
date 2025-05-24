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
    apply_yaml_patch,
    finding::{Confidence, Finding, Fix, Severity},
    github_api::{self, ComparisonStatus},
    models::{JobExt as _, StepCommon, Workflow, uses::RepositoryUsesExt as _},
    state::AuditState,
    yaml_patch::YamlPatchOperation,
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

    /// Create a fix that replaces an impostor commit with a legitimate tag reference
    fn create_tag_replacement_fix(path: &str, uses: &RepositoryUses, suggested_tag: &str) -> Fix {
        let current_ref = uses.git_ref.as_deref().unwrap_or("unknown");
        let replacement_uses = format!("{}/{}@{}", uses.owner, uses.repo, suggested_tag);

        Fix {
            title: format!("Replace impostor commit with tag {}", suggested_tag),
            description: format!(
                "Replace the impostor commit '{}' with the legitimate tag '{}'. \
                This ensures you're using a verified release from the actual repository. \
                The suggested tag '{}' is the latest available tag from {}/{}.",
                current_ref, suggested_tag, suggested_tag, uses.owner, uses.repo
            ),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Replace {
                path: path.to_string(),
                value: serde_yaml::Value::String(replacement_uses),
            }]),
        }
    }

    /// Create a fix that replaces an impostor commit with a branch reference
    fn create_branch_replacement_fix(
        path: &str,
        uses: &RepositoryUses,
        suggested_branch: &str,
    ) -> Fix {
        let current_ref = uses.git_ref.as_deref().unwrap_or("unknown");
        let replacement_uses = format!("{}/{}@{}", uses.owner, uses.repo, suggested_branch);

        Fix {
            title: format!("Replace impostor commit with branch {}", suggested_branch),
            description: format!(
                "Replace the impostor commit '{}' with the legitimate branch '{}'. \
                This ensures you're using code from the actual repository. \
                Note that using branch references may introduce variability as the branch can change. \
                Consider using a specific tag for more stability.",
                current_ref, suggested_branch
            ),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Replace {
                path: path.to_string(),
                value: serde_yaml::Value::String(replacement_uses),
            }]),
        }
    }

    /// Create a fix that removes the step or job entirely
    fn create_removal_fix(path: &str, item_type: &str) -> Fix {
        Fix {
            title: format!("Remove {} with impostor commit", item_type),
            description: format!(
                "Remove this {} that uses an impostor commit. This eliminates the security risk \
                but you may need to replace the functionality with an alternative action or implementation. \
                Only use this fix if you cannot find a legitimate alternative reference.",
                item_type
            ),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Remove {
                path: path.to_string(),
            }]),
        }
    }

    /// Get the most appropriate fix for an impostor commit
    fn get_impostor_fix(&self, uses: &RepositoryUses, path: &str, item_type: &str) -> Result<Fix> {
        // Try to get tags and branches for suggestions
        let tags_result = self.client.list_tags(&uses.owner, &uses.repo);
        let branches_result = self.client.list_branches(&uses.owner, &uses.repo);

        // If we can get tags, suggest the latest tag
        if let Ok(tags) = tags_result {
            if let Some(latest_tag) = tags.first() {
                return Ok(Self::create_tag_replacement_fix(
                    path,
                    uses,
                    &latest_tag.name,
                ));
            }
        }

        // If no tags available, try to suggest a main/master branch
        if let Ok(branches) = branches_result {
            // Look for common default branch names
            for default_branch in &["main", "master"] {
                if branches.iter().any(|b| b.name == *default_branch) {
                    return Ok(Self::create_branch_replacement_fix(
                        path,
                        uses,
                        default_branch,
                    ));
                }
            }

            // If no standard default branch, suggest the first available branch
            if let Some(first_branch) = branches.first() {
                return Ok(Self::create_branch_replacement_fix(
                    path,
                    uses,
                    &first_branch.name,
                ));
            }
        }

        // If we can't suggest an alternative, offer removal as last resort
        Ok(Self::create_removal_fix(path, item_type))
    }
}

impl Audit for ImpostorCommit {
    fn new(state: &AuditState<'_>) -> Result<Self, AuditLoadError> {
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

        Ok(ImpostorCommit { client })
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
                            let step_path =
                                format!("/jobs/{}/steps/{}/uses", normal.id(), step.index);

                            let mut finding_builder = Self::finding()
                                .severity(Severity::High)
                                .confidence(Confidence::High)
                                .add_location(
                                    step.location().primary().annotated(IMPOSTOR_ANNOTATION),
                                );

                            // Try to add a fix
                            if let Ok(fix) = self.get_impostor_fix(uses, &step_path, "step") {
                                finding_builder = finding_builder.fix(fix);
                            }

                            findings.push(finding_builder.build(workflow)?);
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
                        let job_path = format!("/jobs/{}/uses", reusable.id());

                        let mut finding_builder = Self::finding()
                            .severity(Severity::High)
                            .confidence(Confidence::High)
                            .add_location(
                                reusable.location().primary().annotated(IMPOSTOR_ANNOTATION),
                            );

                        // Try to add a fix
                        if let Ok(fix) =
                            self.get_impostor_fix(uses, &job_path, "reusable workflow call")
                        {
                            finding_builder = finding_builder.fix(fix);
                        }

                        findings.push(finding_builder.build(workflow)?);
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
            let step_path = format!("/runs/steps/{}/uses", step.index);

            let mut finding_builder = Self::finding()
                .severity(Severity::High)
                .confidence(Confidence::High)
                .add_location(step.location().primary().annotated(IMPOSTOR_ANNOTATION));

            // Try to add a fix
            if let Ok(fix) = self.get_impostor_fix(uses, &step_path, "composite step") {
                finding_builder = finding_builder.fix(fix);
            }

            findings.push(finding_builder.build(step.action())?);
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use github_actions_models::common::RepositoryUses;

    #[test]
    fn test_create_tag_replacement_fix() {
        let uses = RepositoryUses {
            owner: "actions".to_string(),
            repo: "checkout".to_string(),
            git_ref: Some("abcd1234567890abcd1234567890abcd12345678".to_string()),
            subpath: None,
        };

        let fix =
            ImpostorCommit::create_tag_replacement_fix("/jobs/test/steps/0/uses", &uses, "v4");

        assert_eq!(fix.title, "Replace impostor commit with tag v4");
        assert!(
            fix.description
                .contains("abcd1234567890abcd1234567890abcd12345678")
        );
        assert!(fix.description.contains("v4"));
        assert!(fix.description.contains("actions/checkout"));
    }

    #[test]
    fn test_create_branch_replacement_fix() {
        let uses = RepositoryUses {
            owner: "actions".to_string(),
            repo: "checkout".to_string(),
            git_ref: Some("abcd1234567890abcd1234567890abcd12345678".to_string()),
            subpath: None,
        };

        let fix =
            ImpostorCommit::create_branch_replacement_fix("/jobs/test/steps/0/uses", &uses, "main");

        assert_eq!(fix.title, "Replace impostor commit with branch main");
        assert!(
            fix.description
                .contains("abcd1234567890abcd1234567890abcd12345678")
        );
        assert!(fix.description.contains("main"));
        assert!(fix.description.contains("legitimate branch"));
        assert!(fix.description.contains("actual repository"));
    }

    #[test]
    fn test_create_removal_fix() {
        let fix = ImpostorCommit::create_removal_fix("/jobs/test/steps/0", "step");

        assert_eq!(fix.title, "Remove step with impostor commit");
        assert!(fix.description.contains("Remove this step"));
        assert!(fix.description.contains("security risk"));
    }
}
