//! Detects actions pinned by commit hash, which doesn't point to a Git tag.

use anyhow::{Result, anyhow};
use github_actions_models::common::{RepositoryUses, Uses};

use super::{Audit, AuditLoadError, audit_meta};
use crate::{
    Persona,
    finding::{Confidence, Finding, Fix, Severity},
    github_api,
    models::{CompositeStep, Step, StepCommon, uses::RepositoryUsesExt as _},
    state::AuditState,
};

pub(crate) struct StaleActionRefs {
    client: github_api::Client,
}

audit_meta!(
    StaleActionRefs,
    "stale-action-refs",
    "commit hash does not point to a Git tag"
);

impl StaleActionRefs {
    fn is_stale_action_ref(&self, uses: &RepositoryUses) -> Result<bool> {
        let tag = match &uses.commit_ref() {
            Some(commit_ref) => {
                self.client
                    .longest_tag_for_commit(&uses.owner, &uses.repo, commit_ref)?
            }
            None => return Ok(false),
        };
        Ok(tag.is_none())
    }

    /// Create a fix for manual review and investigation
    fn create_manual_review_fix(&self, uses: &RepositoryUses) -> Fix {
        let commit_ref = uses.commit_ref().unwrap(); // We know this exists

        Fix {
            title: "Manually review commit selection".to_string(),
            description: format!(
                "The commit {} doesn't correspond to a Git tag, which means it's an intermediate commit. \
                Review why this specific commit was chosen:\n\
                1. Check if it fixes a critical bug that wasn't in the previous tag\n\
                2. Verify if a newer tag is available that includes this fix\n\
                3. Consider the security implications of using untagged commits\n\
                4. Document the reason for using this specific commit\n\n\
                Repository: {}/{}\nCommit: {}",
                &commit_ref[..8],
                uses.owner,
                uses.repo,
                commit_ref
            ),
            apply: Box::new(|content| Ok(Some(content.to_string()))), // No automatic change
        }
    }

    /// Create a fix that suggests updating to a tagged version
    fn create_tagged_version_fix(&self, uses: &RepositoryUses) -> Fix {
        let commit_ref = uses.commit_ref().unwrap(); // We know this exists

        Fix {
            title: "Update to tagged version".to_string(),
            description: format!(
                "The commit {} doesn't correspond to a Git tag. Consider updating to a tagged version:\n\
                1. Check the repository's releases/tags page for available versions\n\
                2. Update to the latest stable tag for better reliability\n\
                3. Use the commit SHA of a tagged release instead\n\n\
                Repository: {}/{}\nCurrent commit: {}",
                &commit_ref[..8],
                uses.owner,
                uses.repo,
                commit_ref
            ),
            apply: Box::new(|content| Ok(Some(content.to_string()))), // Guidance-only
        }
    }

    fn process_step<'w>(&self, step: &impl StepCommon<'w>) -> Result<Vec<Finding<'w>>> {
        let mut findings = vec![];

        let Some(Uses::Repository(uses)) = step.uses() else {
            return Ok(findings);
        };

        if self.is_stale_action_ref(uses)? {
            let mut finding_builder = Self::finding()
                .confidence(Confidence::High)
                .severity(Severity::Low)
                .persona(Persona::Pedantic)
                .add_location(
                    step.location()
                        .primary()
                        .with_keys(&["uses".into()])
                        .annotated("commit hash does not correspond to a Git tag"),
                );

            // Add fixes
            finding_builder = finding_builder.fix(self.create_tagged_version_fix(uses));
            finding_builder = finding_builder.fix(self.create_manual_review_fix(uses));

            findings.push(finding_builder.build(step)?);
        }

        Ok(findings)
    }
}

impl Audit for StaleActionRefs {
    fn new(state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
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

        Ok(Self { client })
    }

    fn audit_step<'w>(&self, step: &Step<'w>) -> Result<Vec<Finding<'w>>> {
        self.process_step(step)
    }

    fn audit_composite_step<'a>(&self, step: &CompositeStep<'a>) -> Result<Vec<Finding<'a>>> {
        self.process_step(step)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn create_test_uses(
        owner: &str,
        repo: &str,
        git_ref: &str,
    ) -> github_actions_models::common::RepositoryUses {
        github_actions_models::common::RepositoryUses {
            owner: owner.to_string(),
            repo: repo.to_string(),
            git_ref: Some(git_ref.to_string()),
            subpath: None,
        }
    }

    fn create_test_audit() -> StaleActionRefs {
        let hostname = crate::github_api::GitHubHost::Standard("github.com".to_string());
        let cache_dir = Path::new("/tmp");
        let client = crate::github_api::Client::new(&hostname, "fake-token", cache_dir);
        StaleActionRefs { client }
    }

    #[test]
    fn test_tagged_version_fix() {
        let uses = create_test_uses(
            "actions",
            "checkout",
            "1f0bdec2ad9bfad9e84b5e11ad5b9de3bc22e04e",
        );
        let audit = create_test_audit();
        let fix = audit.create_tagged_version_fix(&uses);

        assert_eq!(fix.title, "Update to tagged version");
        assert!(fix.description.contains("1f0bdec"));
        assert!(fix.description.contains("actions/checkout"));
        assert!(
            fix.description
                .contains("Check the repository's releases/tags page")
        );
    }

    #[test]
    fn test_manual_review_fix() {
        let uses = create_test_uses(
            "actions",
            "setup-node",
            "abcdef1234567890abcdef1234567890abcdef12",
        );
        let audit = create_test_audit();
        let fix = audit.create_manual_review_fix(&uses);

        assert_eq!(fix.title, "Manually review commit selection");
        assert!(fix.description.contains("abcdef12"));
        assert!(fix.description.contains("actions/setup-node"));
        assert!(fix.description.contains("intermediate commit"));
        assert!(fix.description.contains("security implications"));
    }

    #[test]
    fn test_fix_guidance_content() {
        let uses = create_test_uses(
            "example",
            "action",
            "1234567890abcdef1234567890abcdef12345678",
        );
        let audit = create_test_audit();

        // Test tagged version fix
        let tagged_fix = audit.create_tagged_version_fix(&uses);
        assert!(tagged_fix.description.contains("releases/tags page"));
        assert!(tagged_fix.description.contains("latest stable tag"));
        assert!(
            tagged_fix
                .description
                .contains("commit SHA of a tagged release")
        );

        // Test manual review fix
        let manual_fix = audit.create_manual_review_fix(&uses);
        assert!(
            manual_fix
                .description
                .contains("Check if it fixes a critical bug")
        );
        assert!(manual_fix.description.contains("newer tag is available"));
        assert!(manual_fix.description.contains("Document the reason"));
    }

    #[test]
    fn test_fix_apply_functions_are_safe() {
        let uses = create_test_uses("test", "action", "abcd1234567890abcdef1234567890abcdef1234");
        let audit = create_test_audit();

        // Test that apply functions return the content unchanged (guidance-only)
        let test_content = "test workflow content";

        let tagged_fix = audit.create_tagged_version_fix(&uses);
        let result = tagged_fix.apply_to_content(test_content).unwrap().unwrap();
        assert_eq!(result, test_content);

        let manual_fix = audit.create_manual_review_fix(&uses);
        let result = manual_fix.apply_to_content(test_content).unwrap().unwrap();
        assert_eq!(result, test_content);
    }
}
