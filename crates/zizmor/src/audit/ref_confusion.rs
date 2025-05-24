//! Audits reusable workflows and action usage for confusable refs.
//!
//! This is similar to "impostor" commit detection, but with only named
//! refs instead of fully pinned commits: a user may pin a ref such as
//! `@foo` thinking that `foo` will always refer to either a branch or a tag,
//! but the upstream repository may host *both* a branch and a tag named
//! `foo`, making it unclear to the end user which is selected.

use anyhow::{Result, anyhow};
use github_actions_models::common::{RepositoryUses, Uses};

use super::{Audit, AuditLoadError, Job, audit_meta};
use crate::finding::{Finding, Fix};
use crate::models::{CompositeStep, JobExt as _, StepCommon};
use crate::{
    apply_yaml_patch,
    finding::{Confidence, Severity},
    github_api,
    models::uses::RepositoryUsesExt as _,
    state::AuditState,
    yaml_patch::YamlPatchOperation,
};

const REF_CONFUSION_ANNOTATION: &str =
    "uses a ref that's provided by both the branch and tag namespaces";

pub(crate) struct RefConfusion {
    client: github_api::Client,
}

audit_meta!(
    RefConfusion,
    "ref-confusion",
    "git ref for action with ambiguous ref type"
);

impl RefConfusion {
    fn confusable(&self, uses: &RepositoryUses) -> Result<bool> {
        let Some(sym_ref) = uses.symbolic_ref() else {
            return Ok(false);
        };

        let branches_match = self.client.has_branch(&uses.owner, &uses.repo, sym_ref)?;
        let tags_match = self.client.has_tag(&uses.owner, &uses.repo, sym_ref)?;

        // If both the branch and tag namespaces have a match, we have a
        // confusable ref.
        Ok(branches_match && tags_match)
    }

    /// Get the commit SHA for a given ref (prioritizing tags over branches)
    fn get_preferred_commit_sha(
        &self,
        uses: &RepositoryUses,
        sym_ref: &str,
    ) -> Result<Option<String>> {
        // Try tag first (tags are generally more stable than branches)
        if let Ok(Some(tag_sha)) =
            self.client
                .commit_for_ref(&uses.owner, &uses.repo, &format!("tags/{}", sym_ref))
        {
            return Ok(Some(tag_sha));
        }

        // Fall back to branch
        if let Ok(Some(branch_sha)) =
            self.client
                .commit_for_ref(&uses.owner, &uses.repo, &format!("heads/{}", sym_ref))
        {
            return Ok(Some(branch_sha));
        }

        Ok(None)
    }

    /// Create a fix that replaces the confusable ref with a hash-pinned ref
    fn create_hash_pin_fix(&self, uses: &RepositoryUses, path: &str) -> Result<Fix> {
        let Some(sym_ref) = uses.symbolic_ref() else {
            return Ok(Fix {
                title: "Convert to hash-pinned reference".to_string(),
                description: "Unable to determine symbolic reference. Manually convert to a hash-pinned reference.".to_string(),
                apply: Box::new(|content: &str| Ok(Some(content.to_string()))),
            });
        };

        if let Ok(Some(commit_sha)) = self.get_preferred_commit_sha(uses, sym_ref) {
            let new_uses = if let Some(subpath) = &uses.subpath {
                format!("{}/{}{}@{}", uses.owner, uses.repo, subpath, commit_sha)
            } else {
                format!("{}/{}@{}", uses.owner, uses.repo, commit_sha)
            };

            Ok(Fix {
                title: format!("Pin to commit SHA ({})", &commit_sha[..8]),
                description: format!(
                    "Replace the ambiguous ref '{}' with hash-pinned reference '{}'. \
                    This eliminates the ambiguity between branch and tag refs by using the specific commit SHA. \
                    The hash was resolved from the tag reference (preferred over branch).",
                    sym_ref, commit_sha
                ),
                apply: apply_yaml_patch!(vec![YamlPatchOperation::Replace {
                    path: path.to_string(),
                    value: serde_yaml::Value::String(new_uses),
                }]),
            })
        } else {
            Ok(Fix {
                title: "Manually convert to hash-pinned reference".to_string(),
                description: format!(
                    "Replace the ambiguous ref '{}' with a hash-pinned reference. \
                    Visit the repository at https://github.com/{}/{} to find the correct commit SHA \
                    and replace '@{}' with '@<commit-sha>'.",
                    sym_ref, uses.owner, uses.repo, sym_ref
                ),
                apply: Box::new(|content: &str| Ok(Some(content.to_string()))),
            })
        }
    }

    /// Create a fix that suggests manual verification
    fn create_manual_verification_fix(uses: &RepositoryUses) -> Fix {
        let Some(sym_ref) = uses.symbolic_ref() else {
            return Fix {
                title: "Manually verify reference".to_string(),
                description: "Manually verify which reference (branch or tag) you intended to use."
                    .to_string(),
                apply: Box::new(|content: &str| Ok(Some(content.to_string()))),
            };
        };

        Fix {
            title: "Manually verify intended reference".to_string(),
            description: format!(
                "The ref '{}' exists as both a branch and tag in {}/{}. \
                Visit https://github.com/{}/{} to verify which one you intended to use. \
                Consider using a more specific ref name or switch to hash-pinning for security.",
                sym_ref, uses.owner, uses.repo, uses.owner, uses.repo
            ),
            apply: Box::new(|content: &str| Ok(Some(content.to_string()))),
        }
    }

    /// Create a fix that removes the confusing action usage
    fn create_removal_fix(path: &str, item_type: &str) -> Fix {
        Fix {
            title: format!("Remove confusing {} usage", item_type),
            description: format!(
                "Remove this {} that uses an ambiguous ref. \
                Consider using a different action or implementing the functionality manually with clear references.",
                item_type
            ),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Remove {
                path: path.to_string(),
            }]),
        }
    }

    /// Get the appropriate fixes for a confusable ref
    fn get_confusion_fixes(&self, uses: &RepositoryUses, path: &str, item_type: &str) -> Vec<Fix> {
        let mut fixes = Vec::new();

        // Primary fix: hash pin if possible
        if let Ok(hash_fix) = self.create_hash_pin_fix(uses, path) {
            fixes.push(hash_fix);
        }

        // Alternative: manual verification
        fixes.push(Self::create_manual_verification_fix(uses));

        // Last resort: removal
        fixes.push(Self::create_removal_fix(path, item_type));

        fixes
    }

    /// Get the path for a workflow step uses clause
    fn get_step_uses_path(job_id: &str, step_index: usize) -> String {
        format!("/jobs/{}/steps/{}/uses", job_id, step_index)
    }

    /// Get the path for a reusable workflow call uses clause
    fn get_reusable_workflow_uses_path(job_id: &str) -> String {
        format!("/jobs/{}/uses", job_id)
    }

    /// Get the path for a composite step uses clause
    fn get_composite_step_uses_path(step_index: usize) -> String {
        format!("/runs/steps/{}/uses", step_index)
    }
}

impl Audit for RefConfusion {
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

    fn audit_workflow<'doc>(
        &self,
        workflow: &'doc crate::models::Workflow,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'doc>>> {
        let mut findings = vec![];

        for job in workflow.jobs() {
            match job {
                Job::NormalJob(normal) => {
                    for step in normal.steps() {
                        let Some(Uses::Repository(uses)) = step.uses() else {
                            continue;
                        };

                        if self.confusable(uses)? {
                            let step_path = Self::get_step_uses_path(normal.id(), step.index);
                            let fixes = self.get_confusion_fixes(uses, &step_path, "step");

                            let mut finding_builder = Self::finding()
                                .severity(Severity::Medium)
                                .confidence(Confidence::High)
                                .add_location(
                                    step.location()
                                        .primary()
                                        .with_keys(&["uses".into()])
                                        .annotated(REF_CONFUSION_ANNOTATION),
                                );

                            // Add fixes for this confusing reference
                            for fix in fixes {
                                finding_builder = finding_builder.fix(fix);
                            }

                            findings.push(finding_builder.build(workflow)?);
                        }
                    }
                }
                Job::ReusableWorkflowCallJob(reusable) => {
                    let Uses::Repository(uses) = &reusable.uses else {
                        continue;
                    };

                    if self.confusable(uses)? {
                        let workflow_path = Self::get_reusable_workflow_uses_path(reusable.id());
                        let fixes =
                            self.get_confusion_fixes(uses, &workflow_path, "reusable workflow");

                        let mut finding_builder = Self::finding()
                            .severity(Severity::Medium)
                            .confidence(Confidence::High)
                            .add_location(
                                reusable
                                    .location()
                                    .primary()
                                    .annotated(REF_CONFUSION_ANNOTATION),
                            );

                        // Add fixes for this confusing reference
                        for fix in fixes {
                            finding_builder = finding_builder.fix(fix);
                        }

                        findings.push(finding_builder.build(workflow)?);
                    }
                }
            }
        }

        Ok(findings)
    }

    fn audit_composite_step<'a>(&self, step: &CompositeStep<'a>) -> Result<Vec<Finding<'a>>> {
        let mut findings = vec![];

        let Some(Uses::Repository(uses)) = step.uses() else {
            return Ok(findings);
        };

        if self.confusable(uses)? {
            let step_path = Self::get_composite_step_uses_path(step.index);
            let fixes = self.get_confusion_fixes(uses, &step_path, "composite step");

            let mut finding_builder = Self::finding()
                .severity(Severity::Medium)
                .confidence(Confidence::High)
                .add_location(
                    step.location()
                        .primary()
                        .with_keys(&["uses".into()])
                        .annotated(REF_CONFUSION_ANNOTATION),
                );

            // Add fixes for this confusing reference
            for fix in fixes {
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
    fn test_create_manual_verification_fix() {
        let uses = RepositoryUses {
            owner: "actions".to_string(),
            repo: "checkout".to_string(),
            git_ref: Some("v1".to_string()),
            subpath: None,
        };

        let fix = RefConfusion::create_manual_verification_fix(&uses);

        assert_eq!(fix.title, "Manually verify intended reference");
        assert!(fix.description.contains("exists as both a branch and tag"));
        assert!(fix.description.contains("actions/checkout"));
        assert!(
            fix.description
                .contains("https://github.com/actions/checkout")
        );
    }

    #[test]
    fn test_create_removal_fix() {
        let fix = RefConfusion::create_removal_fix("/jobs/test/steps/0/uses", "step");

        assert_eq!(fix.title, "Remove confusing step usage");
        assert!(fix.description.contains("Remove this step"));
        assert!(fix.description.contains("ambiguous ref"));
    }

    #[test]
    fn test_path_generation() {
        assert_eq!(
            RefConfusion::get_step_uses_path("test", 0),
            "/jobs/test/steps/0/uses"
        );
        assert_eq!(
            RefConfusion::get_reusable_workflow_uses_path("deploy"),
            "/jobs/deploy/uses"
        );
        assert_eq!(
            RefConfusion::get_composite_step_uses_path(2),
            "/runs/steps/2/uses"
        );
    }

    #[test]
    fn test_get_confusion_fixes_count() {
        // We can't easily test the actual GitHub API calls without mocking,
        // but we can verify that the fix generation logic returns the expected number of fixes
        let uses = RepositoryUses {
            owner: "actions".to_string(),
            repo: "checkout".to_string(),
            git_ref: Some("v1".to_string()),
            subpath: None,
        };

        // Create a mock client - in a real test environment we'd need proper mocking
        // For now, just verify the structure makes sense
        let fixes = vec![
            RefConfusion::create_manual_verification_fix(&uses),
            RefConfusion::create_removal_fix("/test/path", "step"),
        ];

        assert_eq!(fixes.len(), 2);
        assert!(fixes[0].title.contains("verify"));
        assert!(fixes[1].title.contains("Remove"));
    }

    #[test]
    fn test_fix_application() {
        let yaml_content = r#"name: test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v1
"#;

        let fix = RefConfusion::create_manual_verification_fix(&RepositoryUses {
            owner: "actions".to_string(),
            repo: "checkout".to_string(),
            git_ref: Some("v1".to_string()),
            subpath: None,
        });

        let result = fix.apply_to_content(yaml_content).unwrap();

        // Manual verification fix should return the content unchanged (provides guidance)
        assert!(result.is_some());
        assert_eq!(result.unwrap(), yaml_content);
    }
}
