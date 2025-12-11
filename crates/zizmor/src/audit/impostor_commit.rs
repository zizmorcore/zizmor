//! Audits reusable workflows and pinned actions for "impostor" commits,
//! using the ref lookup technique from [`clank`].
//!
//! `clank` is licensed by Chainguard under the Apache-2.0 License.
//!
//! [`clank`]: https://github.com/chainguard-dev/clank

use anyhow::anyhow;
use github_actions_models::common::{RepositoryUses, Uses};
use subfeature::Subfeature;

use super::{Audit, AuditLoadError, Job, audit_meta};
use crate::{
    audit::AuditError,
    config::Config,
    finding::{
        Confidence, Finding, Fix, FixDisposition, Severity,
        location::{Locatable as _, Routable},
    },
    github::{self, ComparisonStatus},
    models::{
        StepCommon,
        uses::RepositoryUsesExt as _,
        version::Version,
        workflow::{ReusableWorkflowCallJob, Workflow},
    },
    registry::input::InputKey,
    state::AuditState,
};

use yamlpatch::{Op, Patch};

pub const IMPOSTOR_ANNOTATION: &str = "uses a commit that doesn't belong to the specified org/repo";

pub(crate) struct ImpostorCommit {
    pub(crate) client: github::Client,
}

audit_meta!(
    ImpostorCommit,
    "impostor-commit",
    "commit with no history in referenced repository"
);

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

    /// Returns a boolean indicating whether or not this commit is an "impostor",
    /// i.e. resolves due to presence in GitHub's fork network but is not actually
    /// present in any of the specified `owner/repo`'s tags or branches.
    async fn impostor(&self, uses: &RepositoryUses) -> Result<bool, AuditError> {
        // If there's no ref or the ref is not a commit, there's nothing to impersonate.
        let Some(head_ref) = uses.commit_ref() else {
            return Ok(false);
        };

        // Fastest path: almost all commit refs will be at the tip of
        // the branch or tag's history, so check those first.
        // Check tags before branches, since in practice version tags
        // are more commonly pinned.
        let tags = self
            .client
            .list_tags(uses.owner(), uses.repo())
            .await
            .map_err(Self::err)?;

        for tag in &tags {
            if tag.commit.sha == head_ref {
                return Ok(false);
            }
        }

        let branches = self
            .client
            .list_branches(uses.owner(), uses.repo())
            .await
            .map_err(Self::err)?;

        for branch in &branches {
            if branch.commit.sha == head_ref {
                return Ok(false);
            }
        }

        // Fast path: attempt to use GitHub's undocumented `branch_commits`
        // API to see if the commit is present in any branch/tag.
        // There are no stabilitiy guarantees for this API, so we fall back
        // to the slow(er) paths if it fails.
        match self
            .client
            .branch_commits(uses.owner(), uses.repo(), head_ref)
            .await
        {
            Ok(branch_commits) => return Ok(branch_commits.is_empty()),
            Err(e) => tracing::warn!("fast path impostor check failed for {uses}: {e}"),
        }

        // Slow path: use GitHub's comparison API to check each branch and tag's
        // history for presence of the commit.
        for branch in &branches {
            if self
                .named_ref_contains_commit(uses, &format!("refs/heads/{}", &branch.name), head_ref)
                .await?
            {
                return Ok(false);
            }
        }

        for tag in &tags {
            if self
                .named_ref_contains_commit(uses, &format!("refs/tags/{}", &tag.name), head_ref)
                .await?
            {
                return Ok(false);
            }
        }

        // If we've made it here, the commit isn't present in any commit or tag's history,
        // strongly suggesting that it's an impostor.
        Ok(true)
    }

    /// Return the highest semantically versioned tag in the repository.
    async fn get_highest_tag(&self, uses: &RepositoryUses) -> Result<Option<String>, AuditError> {
        let tags = self
            .client
            .list_tags(uses.owner(), uses.repo())
            .await
            .map_err(Self::err)?;

        // Filter tags down to those that can be parsed as semantic versions,
        // get the highest one, and return its original string representation.
        let highest_tag = tags
            .iter()
            .filter_map(|tag| Version::parse(&tag.name).ok())
            .max()
            .map(|vers| vers.raw().to_string());

        Ok(highest_tag)
    }

    /// Create a fix for an impostor commit by replacing it with the latest tag
    async fn create_impostor_fix<'doc, T>(
        &self,
        uses: &RepositoryUses,
        step: &T,
    ) -> Option<Fix<'doc>>
    where
        T: StepCommon<'doc> + for<'a> Routable<'a, 'doc>,
    {
        self.create_fix_for_location(uses, step.location().key, step.route().with_key("uses"))
            .await
    }

    /// Create a fix for a reusable workflow job
    async fn create_reusable_fix<'doc>(
        &self,
        uses: &RepositoryUses,
        job: &ReusableWorkflowCallJob<'doc>,
    ) -> Option<Fix<'doc>> {
        self.create_fix_for_location(
            uses,
            job.location().key,
            job.location().route.with_key("uses"),
        )
        .await
    }

    /// Create a fix for the given location parameters
    async fn create_fix_for_location<'doc>(
        &self,
        uses: &RepositoryUses,
        key: &'doc InputKey,
        route: yamlpath::Route<'doc>,
    ) -> Option<Fix<'doc>> {
        // Get the latest tag for this repository
        let latest_tag = match self.get_highest_tag(uses).await {
            Ok(Some(tag)) => tag,
            Ok(None) => {
                tracing::warn!(
                    "No tags found for {}/{}, cannot create fix",
                    uses.owner(),
                    uses.repo()
                );
                return None;
            }
            Err(e) => {
                tracing::error!(
                    "Failed to get latest tag for {}/{}: {}",
                    uses.owner(),
                    uses.repo(),
                    e
                );
                return None;
            }
        };

        // Build the new uses string with the latest tag
        let mut uses_slug = format!("{}/{}", uses.owner(), uses.repo());
        if let Some(subpath) = &uses.subpath() {
            uses_slug.push_str(&format!("/{subpath}"));
        }
        let fixed_uses = format!("{uses_slug}@{latest_tag}");

        Some(Fix {
            title: format!("pin to latest tag {latest_tag}"),
            key,
            disposition: FixDisposition::Unsafe,
            patches: vec![Patch {
                route,
                operation: Op::Replace(fixed_uses.into()),
            }],
        })
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
                            let mut finding_builder = Self::finding()
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

                            if let Some(fix) = self.create_impostor_fix(uses, &step).await {
                                finding_builder = finding_builder.fix(fix);
                            }

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
                        let mut finding_builder = Self::finding()
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

                        if let Some(fix) = self.create_reusable_fix(uses, &reusable).await {
                            finding_builder = finding_builder.fix(fix);
                        }

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
            let mut finding_builder = Self::finding()
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

            if let Some(fix) = self.create_impostor_fix(uses, step).await {
                finding_builder = finding_builder.fix(fix);
            }

            findings.push(finding_builder.build(step).map_err(Self::err)?);
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {

    #[cfg(feature = "gh-token-tests")]
    #[tokio::test]
    async fn test_impostor_commit_fix_snapshot() {
        use insta::assert_snapshot;

        use crate::models::AsDocument as _;

        use super::*;
        use crate::{models::workflow::Workflow, registry::input::InputKey};

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

        let key = InputKey::local("dummy".into(), "test.yml", None::<&str>);
        let workflow = Workflow::from_string(workflow_content.to_string(), key).unwrap();

        let state = crate::state::AuditState {
            no_online_audits: false,
            gh_client: Some(
                crate::github::Client::new(
                    &crate::github::GitHubHost::Standard("github.com".to_string()),
                    &crate::github::GitHubToken::new(&std::env::var("GH_TOKEN").unwrap()).unwrap(),
                    "/tmp".into(),
                )
                .unwrap(),
            ),
        };

        let audit = ImpostorCommit::new(&state).unwrap();
        let input = workflow.into();
        let findings = audit
            .audit("impostor-commit", &input, &Config::default())
            .await
            .unwrap();

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
    #[tokio::test]
    async fn test_no_impostor_with_valid_tag() {
        use super::*;
        use crate::{models::workflow::Workflow, registry::input::InputKey};

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

        let key = InputKey::local("dummy".into(), "test.yml", None::<&str>);
        let workflow = Workflow::from_string(workflow_content.to_string(), key).unwrap();

        let state = crate::state::AuditState {
            no_online_audits: false,
            gh_client: Some(
                crate::github::Client::new(
                    &crate::github::GitHubHost::Standard("github.com".to_string()),
                    &crate::github::GitHubToken::new(&std::env::var("GH_TOKEN").unwrap()).unwrap(),
                    "/tmp".into(),
                )
                .unwrap(),
            ),
        };

        let audit = ImpostorCommit::new(&state).unwrap();
        let input = workflow.into();
        let findings = audit
            .audit("impostor-commit", &input, &Config::default())
            .await
            .unwrap();

        // With a valid tag, we should not find any impostor commits
        assert!(
            findings.is_empty(),
            "Valid tags should not be flagged as impostor commits"
        );
    }
}
