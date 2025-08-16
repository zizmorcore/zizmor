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
    finding::{
        Confidence, Finding, Fix, FixDisposition, Severity,
        location::{Locatable as _, Routable},
    },
    github_api::{self, ComparisonStatus},
    models::{
        StepCommon,
        uses::RepositoryUsesExt as _,
        workflow::{ReusableWorkflowCallJob, Workflow},
    },
    registry::InputKey,
    state::AuditState,
};

use yamlpatch::{Op, Patch};

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

    /// Get the latest tag for a repository, preferring semantic version tags
    fn get_latest_tag(&self, uses: &RepositoryUses) -> Result<Option<String>> {
        let tags = self.client.list_tags(&uses.owner, &uses.repo)?;

        // Prefer semantic version tags (starting with 'v') over other tags
        let semver_tags: Vec<_> = tags
            .iter()
            .filter(|tag| {
                tag.name.starts_with('v')
                    && tag
                        .name
                        .chars()
                        .nth(1)
                        .map_or(false, |c| c.is_ascii_digit())
            })
            .collect();

        let latest_tag = if !semver_tags.is_empty() {
            // Use the first semver tag (GitHub returns tags in chronological order, newest first)
            semver_tags.first().map(|tag| &tag.name)
        } else {
            // Fallback to the first tag if no semver tags are found
            tags.first().map(|tag| &tag.name)
        };

        Ok(latest_tag.map(|s| s.clone()))
    }

    /// Create a fix for an impostor commit by replacing it with the latest tag
    fn create_impostor_fix<'doc, T>(&self, uses: &RepositoryUses, step: &T) -> Option<Fix<'doc>>
    where
        T: StepCommon<'doc> + for<'a> Routable<'a, 'doc>,
    {
        self.create_fix_for_location(uses, step.location().key, step.route().with_key("uses"))
    }

    /// Create a fix for a reusable workflow job
    fn create_reusable_fix<'doc>(
        &self,
        uses: &RepositoryUses,
        job: &ReusableWorkflowCallJob<'doc>,
    ) -> Option<Fix<'doc>> {
        self.create_fix_for_location(
            uses,
            job.location().key,
            job.location().route.with_key("uses"),
        )
    }

    /// Create a fix for the given location parameters
    fn create_fix_for_location<'doc>(
        &self,
        uses: &RepositoryUses,
        key: &'doc InputKey,
        route: yamlpath::Route<'doc>,
    ) -> Option<Fix<'doc>> {
        // Get the latest tag for this repository
        let latest_tag = match self.get_latest_tag(uses) {
            Ok(Some(tag)) => tag,
            Ok(None) => {
                tracing::warn!(
                    "No tags found for {}/{}, cannot create fix",
                    uses.owner,
                    uses.repo
                );
                return None;
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to get latest tag for {}/{}: {}",
                    uses.owner,
                    uses.repo,
                    e
                );
                return None;
            }
        };

        // Build the new uses string with the latest tag
        let mut uses_slug = format!("{}/{}", uses.owner, uses.repo);
        if let Some(subpath) = &uses.subpath {
            uses_slug.push_str(&format!("/{subpath}"));
        }
        let fixed_uses = format!("{}@{}", uses_slug, latest_tag);

        Some(Fix {
            title: format!("pin to latest tag {}", latest_tag),
            key,
            disposition: FixDisposition::Safe,
            patches: vec![Patch {
                route,
                operation: Op::Replace(fixed_uses.into()),
            }],
        })
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
                            let mut finding_builder = Self::finding()
                                .severity(Severity::High)
                                .confidence(Confidence::High)
                                .add_location(
                                    step.location().primary().annotated(IMPOSTOR_ANNOTATION),
                                );

                            if let Some(fix) = self.create_impostor_fix(uses, &step) {
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
                        let mut finding_builder = Self::finding()
                            .severity(Severity::High)
                            .confidence(Confidence::High)
                            .add_location(
                                reusable.location().primary().annotated(IMPOSTOR_ANNOTATION),
                            );

                        if let Some(fix) = self.create_reusable_fix(uses, &reusable) {
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
            let mut finding_builder = Self::finding()
                .severity(Severity::High)
                .confidence(Confidence::High)
                .add_location(step.location().primary().annotated(IMPOSTOR_ANNOTATION));

            if let Some(fix) = self.create_impostor_fix(uses, step) {
                finding_builder = finding_builder.fix(fix);
            }

            findings.push(finding_builder.build(step.action())?);
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use insta::assert_snapshot;

    use super::*;
    use crate::{
        models::{AsDocument, workflow::Workflow},
        registry::InputKey,
    };

    #[cfg(feature = "gh-token-tests")]
    #[test]
    fn test_impostor_commit_fix_snapshot() {
        // Test with a workflow that uses a commit hash that doesn't exist in the target repository
        // We'll use actions/hello-world-javascript-action with a commit from actions/checkout
        // This creates an impostor scenario: valid commit, wrong repository
        let workflow_content = r#"
name: Test Impostor Commit Fix
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/hello-world-javascript-action@692973e3d937129bcbf40652eb9f2f61becf3332  # This is a commit from actions/checkout, not hello-world
"#;

        let key = InputKey::local("test.yml", None::<&str>).unwrap();
        let workflow = Workflow::from_string(workflow_content.to_string(), key).unwrap();

        let config = crate::config::Config::default();
        let state = crate::state::AuditState {
            config: &config,
            no_online_audits: false,
            gh_client: Some(
                crate::github_api::Client::new(
                    &crate::github_api::GitHubHost::Standard("github.com".to_string()),
                    &crate::github_api::GitHubToken::new(&std::env::var("GH_TOKEN").unwrap())
                        .unwrap(),
                    Path::new("/tmp"),
                )
                .unwrap(),
            ),
            gh_hostname: crate::github_api::GitHubHost::Standard("github.com".to_string()),
        };

        let audit = ImpostorCommit::new(&state).unwrap();
        let input = workflow.into();
        let findings = audit.audit(&input).unwrap();

        // If we detect an impostor commit, there should be a fix available
        if !findings.is_empty() {
            assert!(
                !findings[0].fixes.is_empty(),
                "Expected fix for impostor commit"
            );

            // Apply the fix and snapshot test the result
            let new_doc = findings[0].fixes[0].apply(input.as_document()).unwrap();
            assert_snapshot!(new_doc.source(), @r"
            name: Test Impostor Commit Fix
            on: push
            jobs:
              test:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/hello-world-javascript-action@v1.1  # This is a commit from actions/checkout, not hello-world
            ");
        }
    }

    #[cfg(feature = "gh-token-tests")]
    #[test]
    fn test_no_impostor_with_valid_tag() {
        // Test with a valid tag to ensure we don't get false positives
        let workflow_content = r#"
name: Test Valid Tag
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"#;

        let key = InputKey::local("test.yml", None::<&str>).unwrap();
        let workflow = Workflow::from_string(workflow_content.to_string(), key).unwrap();

        let config = crate::config::Config::default();
        let state = crate::state::AuditState {
            config: &config,
            no_online_audits: false,
            gh_client: Some(
                crate::github_api::Client::new(
                    &crate::github_api::GitHubHost::Standard("github.com".to_string()),
                    &crate::github_api::GitHubToken::new(&std::env::var("GH_TOKEN").unwrap())
                        .unwrap(),
                    Path::new("/tmp"),
                )
                .unwrap(),
            ),
            gh_hostname: crate::github_api::GitHubHost::Standard("github.com".to_string()),
        };

        let audit = ImpostorCommit::new(&state).unwrap();
        let input = workflow.into();
        let findings = audit.audit(&input).unwrap();

        // With a valid tag, we should not find any impostor commits
        assert!(
            findings.is_empty(),
            "Valid tags should not be flagged as impostor commits"
        );
    }

    #[test]
    fn test_audit_requires_github_client() {
        // Test that the audit correctly fails when no GitHub client is available
        let workflow_content = r#"
name: Test Workflow
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: some/action@abc123def456abc123def456abc123def456abc12
"#;

        let key = InputKey::local("test-workflow.yml", None::<&str>).unwrap();
        let _workflow = Workflow::from_string(workflow_content.to_string(), key).unwrap();
        let audit_state = crate::state::AuditState {
            config: &Default::default(),
            no_online_audits: false,
            gh_client: None, // No GitHub client
            gh_hostname: crate::github_api::GitHubHost::Standard("github.com".into()),
        };

        match ImpostorCommit::new(&audit_state) {
            Err(crate::audit::AuditLoadError::Skip(_)) => {
                // Expected behavior when no GitHub client is available
            }
            _ => panic!("Expected audit to skip when no GitHub client is available"),
        }
    }
}
