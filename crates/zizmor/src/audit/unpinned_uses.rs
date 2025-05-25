use std::collections::HashMap;

use anyhow::Context;
use github_actions_models::common::{RepositoryUses, Uses};
use serde::Deserialize;

use super::{Audit, AuditLoadError, AuditState, audit_meta};
use crate::{
    apply_yaml_patch,
    finding::{Confidence, Finding, Fix, Persona, Severity},
    models::uses::RepositoryUsesPattern,
    models::{CompositeStep, JobExt as _, Step, StepCommon, uses::UsesExt as _},
    oci_registry_client_with_fallback,
    yaml_patch::YamlPatchOperation,
};

pub(crate) struct UnpinnedUses {
    policies: UnpinnedUsesPolicies,
}

audit_meta!(UnpinnedUses, "unpinned-uses", "unpinned action reference");

impl UnpinnedUses {
    pub fn evaluate_pinning(&self, uses: &Uses) -> Option<(String, Severity, Persona)> {
        match uses {
            // Don't evaluate pinning for local `uses:`, since unpinned references
            // are fully controlled by the repository anyways.
            // TODO: auditor-level findings instead, perhaps?
            Uses::Local(_) => None,
            // We don't have detailed policies for `uses: docker://` yet,
            // in part because evaluating the risk of a tagged versus hash-pinned
            // Docker image depends on the image and its registry).
            //
            // Instead, we produce a blanket finding for unpinned images,
            // and a pedantic-only finding for unhashed images.
            Uses::Docker(_) => {
                if uses.unpinned() {
                    Some((
                        "action is not pinned to a tag, branch, or hash ref".into(),
                        Severity::Medium,
                        Persona::default(),
                    ))
                } else if uses.unhashed() {
                    Some((
                        "action is not pinned to a hash".into(),
                        Severity::Low,
                        Persona::Pedantic,
                    ))
                } else {
                    None
                }
            }
            Uses::Repository(repo_uses) => {
                let (pattern, policy) = self.policies.get_policy(repo_uses);

                let pat_desc = match pattern {
                    Some(RepositoryUsesPattern::Any) | None => "blanket".into(),
                    Some(RepositoryUsesPattern::InOwner(owner)) => format!("{owner}/*"),
                    Some(RepositoryUsesPattern::InRepo { owner, repo }) => {
                        format!("{owner}/{repo}/*")
                    }
                    Some(RepositoryUsesPattern::ExactRepo { owner, repo }) => {
                        format!("{owner}/{repo}")
                    }
                    Some(RepositoryUsesPattern::ExactPath {
                        owner,
                        repo,
                        subpath,
                    }) => {
                        format!("{owner}/{repo}/{subpath}")
                    }
                    // Not allowed in this audit.
                    Some(RepositoryUsesPattern::ExactWithRef { .. }) => unreachable!(),
                };

                match policy {
                    UsesPolicy::Any => None,
                    UsesPolicy::RefPin => uses.unpinned().then_some((
                        format!(
                            "action is not pinned to a ref or hash (required by {pat_desc} policy)"
                        ),
                        Severity::High,
                        Persona::default(),
                    )),
                    UsesPolicy::HashPin => uses.unhashed().then_some((
                        format!("action is not pinned to a hash (required by {pat_desc} policy)"),
                        Severity::High,
                        Persona::default(),
                    )),
                }
            }
        }
    }

    /// Create a fix that adds a tag to completely unpinned repository actions
    fn create_add_tag_fix(uses: &RepositoryUses, path: &str) -> Fix {
        let suggested_ref = if uses.owner == "actions" || uses.owner == "github" {
            // For official GitHub actions, suggest a common tag
            match uses.repo.as_str() {
                "checkout" => "v4",
                "setup-node" => "v4",
                "setup-python" => "v5",
                "setup-java" => "v4",
                "setup-go" => "v5",
                "upload-artifact" => "v4",
                "download-artifact" => "v4",
                "cache" => "v4",
                _ => "v1", // Generic fallback
            }
        } else {
            "v1.0.0" // Generic version for third-party actions
        };

        let new_uses = if let Some(subpath) = &uses.subpath {
            format!("{}/{}{}@{}", uses.owner, uses.repo, subpath, suggested_ref)
        } else {
            format!("{}/{}@{}", uses.owner, uses.repo, suggested_ref)
        };

        Fix {
            title: format!("Add {} tag to action", suggested_ref),
            description: format!(
                "Add a tag reference '{}' to the unpinned action '{}/{}'. \
                This provides better reproducibility than using the default branch. \
                Check the action's repository for available tags and choose an appropriate version.",
                suggested_ref, uses.owner, uses.repo
            ),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Replace {
                path: path.to_string(),
                value: serde_yaml::Value::String(new_uses),
            }]),
        }
    }

    /// Create a fix that converts a tag/branch to hash-pinned reference
    fn create_hash_pin_fix(uses: &RepositoryUses, _path: &str) -> Fix {
        let current_ref = uses.git_ref.as_deref().unwrap_or("main");

        Fix {
            title: "Convert to hash-pinned reference".to_string(),
            description: format!(
                "Replace the symbolic reference '{}' with a hash-pinned reference for '{}/{}'. \
                Visit https://github.com/{}/{}/commits/{} to find the latest commit SHA \
                and replace '@{}' with '@<commit-sha>'. Hash-pinning provides the highest security \
                by ensuring the exact code version is used.",
                current_ref, uses.owner, uses.repo, uses.owner, uses.repo, current_ref, current_ref
            ),
            apply: Box::new(|content: &str| Ok(Some(content.to_string()))), // Manual fix
        }
    }

    /// Create a fix that adds a Docker tag to unpinned Docker actions
    fn create_docker_tag_fix(docker_image: &str, path: &str) -> Fix {
        // Get actual tags from registry or fall back to static suggestions
        let suggested_tags = Self::get_docker_tags_sync(docker_image);

        let (title, description, apply_fn): (
            String,
            String,
            Box<dyn Fn(&str) -> anyhow::Result<Option<String>> + Send + Sync>,
        ) = if suggested_tags.is_empty() {
            (
                "Add version tag to Docker action".to_string(),
                format!(
                    "Add an appropriate version tag to the unpinned Docker action '{}'. \
                        Check the Docker registry for available tags and choose a specific version. \
                        This provides better reproducibility than using the implicit 'latest' tag.",
                    docker_image
                ),
                Box::new(|content: &str| Ok(Some(content.to_string()))), // Manual fix - guidance only
            )
        } else {
            let best_tag = &suggested_tags[0]; // Use the first (best) suggested tag
            let new_uses = format!("docker://{}:{}", docker_image, best_tag);

            (
                format!("Add '{}' tag to Docker action", best_tag),
                format!(
                    "Add the '{}' tag to the unpinned Docker action '{}'. \
                        This tag was fetched from the registry and provides better reproducibility than using the implicit 'latest' tag. \
                        Other available tags include: {}.",
                    best_tag,
                    docker_image,
                    suggested_tags
                        .iter()
                        .skip(1)
                        .take(3) // Show up to 3 additional tags
                        .map(|t| format!("'{}'", t))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                apply_yaml_patch!(vec![YamlPatchOperation::Replace {
                    path: path.to_string(),
                    value: serde_yaml::Value::String(new_uses),
                }]),
            )
        };

        Fix {
            title,
            description,
            apply: apply_fn,
        }
    }

    /// Create a fix that suggests using hash-pinned Docker images
    fn create_docker_hash_fix(docker_image: &str) -> Fix {
        Fix {
            title: "Convert to hash-pinned Docker image".to_string(),
            description: format!(
                "Replace the tag reference with a hash-pinned reference for the Docker image '{}'. \
                Use 'docker inspect {}:<tag>' to find the SHA256 digest and replace the tag with '@sha256:<digest>'. \
                Hash-pinning provides the highest security by ensuring the exact image version is used.",
                docker_image, docker_image
            ),
            apply: Box::new(|content: &str| Ok(Some(content.to_string()))), // Manual fix
        }
    }

    /// Create a fix that provides general pinning guidance
    fn create_pinning_guidance_fix(uses: &Uses, policy: UsesPolicy) -> Fix {
        let policy_desc = match policy {
            UsesPolicy::Any => "no specific pinning requirements",
            UsesPolicy::RefPin => "requires pinning to a tag, branch, or hash",
            UsesPolicy::HashPin => "requires hash-pinning for maximum security",
        };

        let guidance = match uses {
            Uses::Repository(repo_uses) => {
                format!(
                    "For repository action '{}/{}': {}. \
                    Visit the action's repository to find appropriate tags or commit SHAs.",
                    repo_uses.owner, repo_uses.repo, policy_desc
                )
            }
            Uses::Docker(docker_uses) => {
                format!(
                    "For Docker action '{}': {}. \
                    Check the Docker registry for available tags or use 'docker inspect' to find SHA256 digests.",
                    docker_uses.image, policy_desc
                )
            }
            Uses::Local(local_uses) => {
                format!(
                    "For local action '{}': {}. \
                    Local actions are controlled by your repository, so pinning is less critical.",
                    local_uses.path, policy_desc
                )
            }
        };

        Fix {
            title: "Pinning guidance".to_string(),
            description: guidance,
            apply: Box::new(|content: &str| Ok(Some(content.to_string()))), // Guidance only
        }
    }

    /// Get Docker tags from registry with fallback to static suggestions
    fn get_docker_tags_sync(image_name: &str) -> Vec<String> {
        // Try to get tags from registry using the macro
        let get_tags = oci_registry_client_with_fallback!(3);

        // Since we can't use async in this context, we'll use tokio::runtime::Handle
        // to run the async operation if we're in a tokio context, otherwise fall back
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let tags = handle.block_on(get_tags(image_name));
            if !tags.is_empty() {
                return tags;
            }
        }

        // Fall back to static suggestions if registry fetch fails or we're not in async context
        Self::get_common_docker_tags(image_name)
    }

    /// Get common Docker tags for well-known images (fallback)
    fn get_common_docker_tags(image_name: &str) -> Vec<String> {
        match image_name {
            "ubuntu" => vec![
                "24.04".to_string(),
                "22.04".to_string(),
                "20.04".to_string(),
            ],
            "node" => vec!["20".to_string(), "18".to_string(), "16".to_string()],
            "python" => vec!["3.12".to_string(), "3.11".to_string(), "3.10".to_string()],
            "alpine" => vec!["3.19".to_string(), "3.18".to_string(), "latest".to_string()],
            "nginx" => vec!["1.25".to_string(), "1.24".to_string(), "alpine".to_string()],
            "redis" => vec!["7".to_string(), "6".to_string(), "alpine".to_string()],
            "postgres" => vec!["16".to_string(), "15".to_string(), "14".to_string()],
            "mysql" => vec!["8.0".to_string(), "5.7".to_string()],
            _ => vec![], // No suggestions for unknown images
        }
    }

    fn get_fixes_for_uses(
        &self,
        uses: &Uses,
        policy: UsesPolicy,
        path: &str,
        _item_type: &str,
    ) -> Vec<Fix> {
        let mut fixes = Vec::new();

        match uses {
            Uses::Repository(repo_uses) => {
                match policy {
                    UsesPolicy::RefPin => {
                        if uses.unpinned() {
                            // Completely unpinned - suggest adding a tag
                            fixes.push(Self::create_add_tag_fix(repo_uses, path));
                            fixes.push(Self::create_pinning_guidance_fix(uses, policy));
                        }
                    }
                    UsesPolicy::HashPin => {
                        if uses.unpinned() {
                            // Completely unpinned - suggest adding a tag first, then hash-pinning
                            fixes.push(Self::create_add_tag_fix(repo_uses, path));
                            fixes.push(Self::create_hash_pin_fix(repo_uses, path));
                            fixes.push(Self::create_pinning_guidance_fix(uses, policy));
                        } else if uses.unhashed() {
                            // Has tag/branch but not hash-pinned
                            fixes.push(Self::create_hash_pin_fix(repo_uses, path));
                            fixes.push(Self::create_pinning_guidance_fix(uses, policy));
                        }
                    }
                    UsesPolicy::Any => {
                        // No restrictions, but still provide guidance
                        if uses.unpinned() {
                            fixes.push(Self::create_pinning_guidance_fix(uses, policy));
                        }
                    }
                }
            }
            Uses::Docker(docker_uses) => {
                if uses.unpinned() {
                    // Unpinned Docker action - suggest adding a tag
                    fixes.push(Self::create_docker_tag_fix(&docker_uses.image, path));
                    fixes.push(Self::create_docker_hash_fix(&docker_uses.image));
                } else if uses.unhashed() {
                    // Has tag but not hash-pinned
                    fixes.push(Self::create_docker_hash_fix(&docker_uses.image));
                }
                fixes.push(Self::create_pinning_guidance_fix(uses, policy));
            }
            Uses::Local(_) => {
                // Local actions don't need pinning fixes, just provide guidance
                fixes.push(Self::create_pinning_guidance_fix(uses, policy));
            }
        }

        fixes
    }

    /// Get the path for a workflow step uses clause
    fn get_step_uses_path(job_id: &str, step_index: usize) -> String {
        format!("/jobs/{}/steps/{}/uses", job_id, step_index)
    }

    /// Get the path for a composite step uses clause
    fn get_composite_step_uses_path(step_index: usize) -> String {
        format!("/runs/steps/{}/uses", step_index)
    }
}

impl Audit for UnpinnedUses {
    fn new(state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        let config = state
            .config
            .rule_config::<UnpinnedUsesConfig>(Self::ident())
            .context("invalid configuration")
            .map_err(AuditLoadError::Fail)?
            .unwrap_or_default();

        let policies = UnpinnedUsesPolicies::try_from(config)
            .context("invalid configuration")
            .map_err(AuditLoadError::Fail)?;

        Ok(Self { policies })
    }

    fn audit_step<'doc>(&self, step: &Step<'doc>) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        let Some(uses) = step.uses() else {
            return Ok(findings);
        };

        if let Some((annotation, severity, persona)) = self.evaluate_pinning(uses) {
            // Determine the policy that triggered this finding
            let policy = match uses {
                Uses::Repository(repo_uses) => {
                    let (_, policy) = self.policies.get_policy(repo_uses);
                    policy
                }
                Uses::Docker(_) => {
                    if uses.unpinned() {
                        UsesPolicy::RefPin
                    } else {
                        UsesPolicy::HashPin
                    }
                }
                Uses::Local(_) => UsesPolicy::Any,
            };

            // Construct the proper YAML path for this step
            let step_path = Self::get_step_uses_path(step.job().id(), step.index);
            let fixes = self.get_fixes_for_uses(uses, policy, &step_path, "step");

            let mut finding_builder = Self::finding()
                .severity(severity)
                .confidence(Confidence::High)
                .persona(persona)
                .add_location(
                    step.location()
                        .with_keys(&["uses".into()])
                        .primary()
                        .annotated(annotation),
                );

            for fix in fixes {
                finding_builder = finding_builder.fix(fix);
            }

            findings.push(finding_builder.build(step.workflow())?);
        }

        Ok(findings)
    }

    fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
    ) -> anyhow::Result<Vec<Finding<'a>>> {
        let mut findings = vec![];

        let Some(uses) = step.uses() else {
            return Ok(findings);
        };

        if let Some((annotation, severity, persona)) = self.evaluate_pinning(uses) {
            // Determine the policy that triggered this finding
            let policy = match uses {
                Uses::Repository(repo_uses) => {
                    let (_, policy) = self.policies.get_policy(repo_uses);
                    policy
                }
                Uses::Docker(_) => {
                    if uses.unpinned() {
                        UsesPolicy::RefPin
                    } else {
                        UsesPolicy::HashPin
                    }
                }
                Uses::Local(_) => UsesPolicy::Any,
            };

            // Construct the proper YAML path for this composite step
            let step_path = Self::get_composite_step_uses_path(step.index);
            let fixes = self.get_fixes_for_uses(uses, policy, &step_path, "composite step");

            let mut finding_builder = Self::finding()
                .severity(severity)
                .confidence(Confidence::High)
                .persona(persona)
                .add_location(
                    step.location()
                        .with_keys(&["uses".into()])
                        .primary()
                        .annotated(annotation),
                );

            for fix in fixes {
                finding_builder = finding_builder.fix(fix);
            }

            findings.push(finding_builder.build(step.action())?);
        }

        Ok(findings)
    }
}

/// Config for the `unpinned-uses` rule.
///
/// This configuration is reified into an `UnpinnedUsesPolicies`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct UnpinnedUsesConfig {
    /// A mapping of `uses:` patterns to policies.
    policies: HashMap<RepositoryUsesPattern, UsesPolicy>,
}

impl Default for UnpinnedUsesConfig {
    fn default() -> Self {
        Self {
            policies: [
                (
                    RepositoryUsesPattern::InOwner("actions".into()),
                    UsesPolicy::RefPin,
                ),
                (
                    RepositoryUsesPattern::InOwner("github".into()),
                    UsesPolicy::RefPin,
                ),
                (
                    RepositoryUsesPattern::InOwner("dependabot".into()),
                    UsesPolicy::RefPin,
                ),
                (RepositoryUsesPattern::Any, UsesPolicy::HashPin),
            ]
            .into(),
        }
    }
}

/// A singular policy for a `uses:` reference.
#[derive(Copy, Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum UsesPolicy {
    /// No policy; all `uses:` references are allowed, even unpinned ones.
    Any,
    /// `uses:` references must be pinned to a tag, branch, or hash ref.
    RefPin,
    /// `uses:` references must be pinned to a hash ref.
    HashPin,
}

/// Represents the set of policies used to evaluate `uses:` references.
struct UnpinnedUsesPolicies {
    /// The policy tree is a mapping of `owner` slugs to a list of
    /// `(pattern, policy)` pairs under that owner, ordered by specificity.
    ///
    /// For example, a config containing both `foo/*: hash-pin` and
    /// `foo/bar: ref-pin` would produce a policy tree like this:
    ///
    /// ```text
    /// foo:
    ///   - foo/bar: ref-pin
    ///   - foo/*: hash-pin
    /// ```
    ///
    /// This is done for performance reasons: a two-level structure here
    /// means that checking a `uses:` is a linear scan of the policies
    /// for that owner, rather than a full scan of all policies.
    policy_tree: HashMap<String, Vec<(RepositoryUsesPattern, UsesPolicy)>>,

    /// This is the policy that's applied if nothing in the policy tree matches.
    ///
    /// Normally is this configured by an `*` entry in the config or by
    /// `UnpinnedUsesConfig::default()`. However, if the user explicitly
    /// omits a `*` rule, this will be `UsesPolicy::HashPin`.
    default_policy: UsesPolicy,
}

impl UnpinnedUsesPolicies {
    /// Returns the most specific policy for the given repository `uses` reference,
    /// or the default policy if none match.
    fn get_policy(&self, uses: &RepositoryUses) -> (Option<&RepositoryUsesPattern>, UsesPolicy) {
        match self.policy_tree.get(&uses.owner) {
            Some(policies) => {
                // Policies are ordered by specificity, so we can
                // iterate and return eagerly.
                for (uses_pattern, policy) in policies {
                    if uses_pattern.matches(uses) {
                        return (Some(uses_pattern), *policy);
                    }
                }
                // The policies under `owner/` might be fully divergent
                // if there isn't an `owner/*` rule, so we fall back
                // to the default policy.
                (None, self.default_policy)
            }
            None => (None, self.default_policy),
        }
    }
}

impl TryFrom<UnpinnedUsesConfig> for UnpinnedUsesPolicies {
    type Error = anyhow::Error;

    fn try_from(config: UnpinnedUsesConfig) -> Result<Self, Self::Error> {
        let mut policy_tree: HashMap<String, Vec<(RepositoryUsesPattern, UsesPolicy)>> =
            HashMap::new();
        let mut default_policy = UsesPolicy::HashPin;

        for (pattern, policy) in config.policies {
            match pattern {
                // Patterns with refs don't make sense in this context, since
                // we're establishing policies for the refs themselves.
                RepositoryUsesPattern::ExactWithRef { .. } => {
                    return Err(anyhow::anyhow!("can't use exact ref patterns here"));
                }
                RepositoryUsesPattern::ExactPath { ref owner, .. } => {
                    policy_tree
                        .entry(owner.clone())
                        .or_default()
                        .push((pattern, policy));
                }
                RepositoryUsesPattern::ExactRepo { ref owner, .. } => {
                    policy_tree
                        .entry(owner.clone())
                        .or_default()
                        .push((pattern, policy));
                }
                RepositoryUsesPattern::InRepo { ref owner, .. } => {
                    policy_tree
                        .entry(owner.clone())
                        .or_default()
                        .push((pattern, policy));
                }
                RepositoryUsesPattern::InOwner(ref owner) => {
                    policy_tree
                        .entry(owner.clone())
                        .or_default()
                        .push((pattern, policy));
                }
                RepositoryUsesPattern::Any => {
                    default_policy = policy;
                }
            }
        }

        // Sort the policies for each owner by specificity.
        for policies in policy_tree.values_mut() {
            policies.sort_by(|a, b| a.0.cmp(&b.0));
        }

        Ok(Self {
            policy_tree,
            default_policy,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use github_actions_models::common::{DockerUses, RepositoryUses};

    #[test]
    fn test_add_tag_fix() {
        let uses = RepositoryUses {
            owner: "actions".to_string(),
            repo: "checkout".to_string(),
            git_ref: None,
            subpath: None,
        };

        let fix = UnpinnedUses::create_add_tag_fix(&uses, "/jobs/test/steps/0/uses");
        assert_eq!(fix.title, "Add v4 tag to action");
        assert!(fix.description.contains("actions/checkout"));
        assert!(fix.description.contains("v4"));

        // Test the fix application
        let yaml_content = r#"jobs:
  test:
    steps:
      - uses: actions/checkout"#;

        let result = fix.apply_to_content(yaml_content).unwrap().unwrap();
        assert!(result.contains("actions/checkout@v4"));
    }

    #[test]
    fn test_add_tag_fix_third_party() {
        let uses = RepositoryUses {
            owner: "codecov".to_string(),
            repo: "codecov-action".to_string(),
            git_ref: None,
            subpath: None,
        };

        let fix = UnpinnedUses::create_add_tag_fix(&uses, "/jobs/test/steps/0/uses");
        assert_eq!(fix.title, "Add v1.0.0 tag to action");
        assert!(fix.description.contains("codecov/codecov-action"));
        assert!(fix.description.contains("v1.0.0"));
    }

    #[test]
    fn test_hash_pin_fix() {
        let uses = RepositoryUses {
            owner: "actions".to_string(),
            repo: "checkout".to_string(),
            git_ref: Some("v4".to_string()),
            subpath: None,
        };

        let fix = UnpinnedUses::create_hash_pin_fix(&uses, "/jobs/test/steps/0/uses");
        assert_eq!(fix.title, "Convert to hash-pinned reference");
        assert!(fix.description.contains("actions/checkout"));
        assert!(fix.description.contains("v4"));
        assert!(
            fix.description
                .contains("https://github.com/actions/checkout/commits/v4")
        );
    }

    #[test]
    fn test_docker_tag_fix() {
        let fix = UnpinnedUses::create_docker_tag_fix("ubuntu", "/jobs/test/steps/0/uses");
        // Now we expect the actual tag from registry (or fallback)
        assert_eq!(fix.title, "Add '24.04' tag to Docker action");
        assert!(fix.description.contains("ubuntu"));
        assert!(fix.description.contains("24.04"));

        // Test the fix application - should now actually apply the tag
        let yaml_content = r#"jobs:
  test:
    steps:
      - uses: docker://ubuntu"#;

        let result = fix.apply_to_content(yaml_content).unwrap().unwrap();
        assert!(result.contains("docker://ubuntu:24.04")); // Should be modified with the tag
    }

    #[test]
    fn test_docker_hash_fix() {
        let fix = UnpinnedUses::create_docker_hash_fix("ubuntu");
        assert_eq!(fix.title, "Convert to hash-pinned Docker image");
        assert!(fix.description.contains("ubuntu"));
        assert!(fix.description.contains("docker inspect ubuntu"));
    }

    #[test]
    fn test_pinning_guidance_fix() {
        let uses = Uses::Repository(RepositoryUses {
            owner: "actions".to_string(),
            repo: "checkout".to_string(),
            git_ref: None,
            subpath: None,
        });

        let fix = UnpinnedUses::create_pinning_guidance_fix(&uses, UsesPolicy::HashPin);
        assert_eq!(fix.title, "Pinning guidance");
        assert!(fix.description.contains("actions/checkout"));
        assert!(fix.description.contains("hash-pinning"));
        assert!(fix.description.contains("repository"));
    }

    #[test]
    fn test_get_fixes_for_uses_unpinned_repo() {
        let uses = Uses::Repository(RepositoryUses {
            owner: "actions".to_string(),
            repo: "checkout".to_string(),
            git_ref: None,
            subpath: None,
        });

        let audit = create_test_audit();
        let fixes = audit.get_fixes_for_uses(&uses, UsesPolicy::RefPin, "/test", "step");
        assert_eq!(fixes.len(), 2); // add tag + guidance
        assert_eq!(fixes[0].title, "Add v4 tag to action");
        assert_eq!(fixes[1].title, "Pinning guidance");
    }

    #[test]
    fn test_get_fixes_for_uses_hash_pin_policy() {
        let uses = Uses::Repository(RepositoryUses {
            owner: "third-party".to_string(),
            repo: "action".to_string(),
            git_ref: None,
            subpath: None,
        });

        let audit = create_test_audit();
        let fixes = audit.get_fixes_for_uses(&uses, UsesPolicy::HashPin, "/test", "step");
        assert_eq!(fixes.len(), 3); // add tag + hash pin + guidance
        assert_eq!(fixes[0].title, "Add v1.0.0 tag to action");
        assert_eq!(fixes[1].title, "Convert to hash-pinned reference");
        assert_eq!(fixes[2].title, "Pinning guidance");
    }

    #[test]
    fn test_get_fixes_for_uses_tagged_but_unhashed() {
        let uses = Uses::Repository(RepositoryUses {
            owner: "third-party".to_string(),
            repo: "action".to_string(),
            git_ref: Some("v1.0.0".to_string()),
            subpath: None,
        });

        let audit = create_test_audit();
        let fixes = audit.get_fixes_for_uses(&uses, UsesPolicy::HashPin, "/test", "step");
        assert_eq!(fixes.len(), 2); // hash pin + guidance
        assert_eq!(fixes[0].title, "Convert to hash-pinned reference");
        assert_eq!(fixes[1].title, "Pinning guidance");
    }

    #[test]
    fn test_get_fixes_for_uses_docker_unpinned() {
        let uses = Uses::Docker(DockerUses {
            image: "ubuntu".to_string(),
            tag: None,
            hash: None,
            registry: None,
        });

        let audit = create_test_audit();
        let fixes = audit.get_fixes_for_uses(&uses, UsesPolicy::RefPin, "/test", "step");
        assert_eq!(fixes.len(), 3); // docker tag + docker hash + guidance
        assert_eq!(fixes[0].title, "Add '24.04' tag to Docker action"); // Now expects actual tag
        assert_eq!(fixes[1].title, "Convert to hash-pinned Docker image");
        assert_eq!(fixes[2].title, "Pinning guidance");
    }

    fn create_test_audit() -> UnpinnedUses {
        UnpinnedUses {
            policies: UnpinnedUsesPolicies::try_from(UnpinnedUsesConfig::default()).unwrap(),
        }
    }
}
