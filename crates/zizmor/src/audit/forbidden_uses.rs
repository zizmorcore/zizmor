use anyhow::{Context, anyhow};
use github_actions_models::common::Uses;

use super::{Audit, AuditLoadError, AuditState, audit_meta};
use crate::{
    apply_yaml_patch,
    finding::{Confidence, Finding, Fix, Persona, Severity},
    models::{CompositeStep, Step, StepCommon},
    models::{JobExt, uses::RepositoryUsesPattern},
    yaml_patch::YamlPatchOperation,
};
use serde::Deserialize;

pub(crate) struct ForbiddenUses {
    config: ForbiddenUsesConfig,
}

audit_meta!(ForbiddenUses, "forbidden-uses", "forbidden action used");

impl ForbiddenUses {
    fn use_denied(&self, uses: &Uses) -> bool {
        match uses {
            // Local uses are never denied.
            Uses::Local(_) => false,
            // TODO: Support Docker uses here?
            // We'd need some equivalent to RepositoryUsesPattern
            // but for Docker uses, which will be slightly annoying.
            Uses::Docker(_) => {
                tracing::warn!("can't evaluate direct Docker uses");
                false
            }
            Uses::Repository(uses) => match &self.config {
                ForbiddenUsesConfig::Allow { allow } => {
                    !allow.iter().any(|pattern| pattern.matches(uses))
                }
                ForbiddenUsesConfig::Deny { deny } => {
                    deny.iter().any(|pattern| pattern.matches(uses))
                }
            },
        }
    }

    /// Create a fix for removing a forbidden step entirely
    fn create_remove_step_fix(job_id: &str, step_index: usize) -> Fix {
        let step_path = format!("/jobs/{}/steps/{}", job_id, step_index);

        Fix {
            title: "Remove forbidden action step".to_string(),
            description: "Remove this step that uses a forbidden action. You may need to replace it with an alternative action or implement the functionality differently.".to_string(),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Remove {
                path: step_path,
            }]),
        }
    }

    /// Create a fix suggesting an alternative action
    fn create_replace_action_fix(job_id: &str, step_index: usize, suggested_action: &str) -> Fix {
        let uses_path = format!("/jobs/{}/steps/{}/uses", job_id, step_index);

        Fix {
            title: format!("Replace with {}", suggested_action),
            description: format!(
                "Replace the forbidden action with the suggested alternative: {}. Note that you may need to adjust the 'with' inputs and other step configuration to match the new action's interface.",
                suggested_action
            ),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Replace {
                path: uses_path,
                value: serde_yaml::Value::String(suggested_action.to_string()),
            }]),
        }
    }

    /// Try to suggest an alternative action for common forbidden actions
    fn suggest_alternative(&self, uses: &Uses) -> Option<String> {
        if let Uses::Repository(repo_uses) = uses {
            // Create the full action string including version if present
            let action_string = if let Some(ref git_ref) = repo_uses.git_ref {
                format!("{}/{}@{}", repo_uses.owner, repo_uses.repo, git_ref)
            } else {
                format!("{}/{}", repo_uses.owner, repo_uses.repo)
            };

            // Common alternatives for frequently forbidden actions
            match action_string.as_str() {
                // Old checkout versions
                "actions/checkout@v1" | "actions/checkout@v2" => {
                    Some("actions/checkout@v4".to_string())
                }
                // Old setup-node versions
                "actions/setup-node@v1" | "actions/setup-node@v2" => {
                    Some("actions/setup-node@v4".to_string())
                }
                // Old setup-python versions
                "actions/setup-python@v1" | "actions/setup-python@v2" => {
                    Some("actions/setup-python@v5".to_string())
                }
                // Security-problematic actions with safer alternatives
                "actions/upload-artifact@v1" | "actions/upload-artifact@v2" => {
                    Some("actions/upload-artifact@v4".to_string())
                }
                "actions/download-artifact@v1" | "actions/download-artifact@v2" => {
                    Some("actions/download-artifact@v4".to_string())
                }
                // Common third-party actions that might be replaced
                "codecov/codecov-action@v1" => Some("codecov/codecov-action@v4".to_string()),
                _ => None,
            }
        } else {
            None
        }
    }

    /// Get the appropriate fix for a forbidden use in a workflow step
    fn get_fix_for_step(&self, step: &Step, uses: &Uses) -> Option<Fix> {
        let job_id = step.job().id();
        let step_index = step.index;

        // Try to suggest an alternative first
        if let Some(alternative) = self.suggest_alternative(uses) {
            Some(Self::create_replace_action_fix(
                job_id,
                step_index,
                &alternative,
            ))
        } else {
            // Fall back to removal if no alternative is available
            Some(Self::create_remove_step_fix(job_id, step_index))
        }
    }

    /// Get the appropriate fix for a forbidden use in a composite step
    fn get_fix_for_composite_step(&self, step: &CompositeStep, uses: &Uses) -> Option<Fix> {
        let step_index = step.index;

        // For composite steps, the path is different: /runs/steps/{index}
        let step_path = format!("/runs/steps/{}", step_index);
        let uses_path = format!("/runs/steps/{}/uses", step_index);

        // Try to suggest an alternative first
        if let Some(alternative) = self.suggest_alternative(uses) {
            Some(Fix {
                title: format!("Replace with {}", alternative),
                description: format!(
                    "Replace the forbidden action with the suggested alternative: {}. Note that you may need to adjust the 'with' inputs and other step configuration to match the new action's interface.",
                    alternative
                ),
                apply: apply_yaml_patch!(vec![YamlPatchOperation::Replace {
                    path: uses_path,
                    value: serde_yaml::Value::String(alternative),
                }]),
            })
        } else {
            // Fall back to removal if no alternative is available
            Some(Fix {
                title: "Remove forbidden action step".to_string(),
                description: "Remove this step that uses a forbidden action. You may need to replace it with an alternative action or implement the functionality differently.".to_string(),
                apply: apply_yaml_patch!(vec![YamlPatchOperation::Remove {
                    path: step_path,
                }]),
            })
        }
    }
}

impl Audit for ForbiddenUses {
    fn new(state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        let Some(config) = state
            .config
            .rule_config(Self::ident())
            .context("invalid configuration")
            .map_err(AuditLoadError::Fail)?
        else {
            return Err(AuditLoadError::Skip(anyhow!("audit not configured")));
        };

        Ok(Self { config })
    }

    fn audit_step<'doc>(&self, step: &Step<'doc>) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        let Some(uses) = step.uses() else {
            return Ok(findings);
        };

        if self.use_denied(uses) {
            let finding_builder = Self::finding()
                .confidence(Confidence::High)
                .severity(Severity::High)
                .persona(Persona::Regular)
                .add_location(
                    step.location()
                        .primary()
                        .with_keys(&["uses".into()])
                        .annotated("use of this action is forbidden"),
                );

            // Add fix if we can determine one
            let finding_builder = if let Some(fix) = self.get_fix_for_step(step, uses) {
                finding_builder.fix(fix)
            } else {
                finding_builder
            };

            findings.push(finding_builder.build(step)?);
        };

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

        if self.use_denied(uses) {
            let finding_builder = Self::finding()
                .confidence(Confidence::High)
                .severity(Severity::High)
                .persona(Persona::Regular)
                .add_location(
                    step.location()
                        .primary()
                        .with_keys(&["uses".into()])
                        .annotated("use of this action is forbidden"),
                );

            // Add fix if we can determine one
            let finding_builder = if let Some(fix) = self.get_fix_for_composite_step(step, uses) {
                finding_builder.fix(fix)
            } else {
                finding_builder
            };

            findings.push(finding_builder.build(step)?);
        };

        Ok(findings)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", untagged)]
enum ForbiddenUsesConfig {
    Allow { allow: Vec<RepositoryUsesPattern> },
    Deny { deny: Vec<RepositoryUsesPattern> },
}
