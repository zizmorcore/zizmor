use github_actions_models::workflow::job::Secrets;

use super::{Audit, AuditLoadError, AuditState, audit_meta};
use crate::{
    apply_yaml_patch,
    finding::{Confidence, Fix},
    models::JobExt as _,
    yaml_patch::YamlPatchOperation,
};

pub(crate) struct SecretsInherit;

audit_meta!(
    SecretsInherit,
    "secrets-inherit",
    "secrets unconditionally inherited by called workflow"
);

impl SecretsInherit {
    /// Generate a safe secret name from a base name
    fn generate_safe_secret_name(base_name: &str) -> String {
        // Convert names to kebab-case and ensure they only contain allowed characters
        // Secret names should be lowercase with hyphens, alphanumeric characters only
        base_name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .collect::<String>()
            // Remove leading/trailing hyphens and collapse multiple hyphens
            .trim_matches('-')
            .split('-')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Create a fix that replaces secrets: inherit with explicit secret declarations
    fn create_explicit_secrets_fix(job_id: &str) -> Fix {
        let secrets_path = format!("/jobs/{}/secrets", job_id);
        let job_id = job_id.to_string(); // Convert to owned string

        Fix {
            title: "Replace secrets: inherit with explicit secret declarations".to_string(),
            description: "Replace 'secrets: inherit' with explicit secret declarations. \
                List only the specific secrets that the reusable workflow actually needs. \
                For example:\n\
                Before: secrets: inherit\n\
                After:\n  secrets:\n    my-secret: ${{ secrets.MY_SECRET }}\n    deploy-token: ${{ secrets.DEPLOY_TOKEN }}\n\n\
                This follows the principle of least authority and makes secret usage explicit and auditable.".to_string(),
            apply: Box::new(move |old_content: &str| -> anyhow::Result<Option<String>> {
                // First remove the existing secrets: inherit
                let content_without_inherit = crate::yaml_patch::apply_yaml_patch(
                    old_content,
                    vec![YamlPatchOperation::Remove {
                        path: secrets_path.clone(),
                    }]
                )?;

                // Create a proper YAML mapping for explicit secrets with safe names
                let mut example_secrets = serde_yaml::Mapping::new();

                // Generate safe secret names - keep it simple for the example
                let secret_key = Self::generate_safe_secret_name("example-secret");
                let secret_ref = "EXAMPLE_SECRET"; // Keep the secret reference simple and valid

                example_secrets.insert(
                    serde_yaml::Value::String(secret_key),
                    serde_yaml::Value::String(format!("${{{{ secrets.{} }}}}", secret_ref)),
                );

                // Use MergeInto to add the new secrets mapping (similar to template_injection)
                let final_content = crate::yaml_patch::apply_yaml_patch(
                    &content_without_inherit,
                    vec![YamlPatchOperation::MergeInto {
                        path: format!("/jobs/{}", job_id),
                        key: "secrets".to_string(),
                        value: serde_yaml::Value::Mapping(example_secrets),
                    }]
                )?;
                Ok(Some(final_content))
            }),
        }
    }

    /// Create a fix that removes the secrets clause entirely
    fn create_remove_secrets_fix(job_id: &str) -> Fix {
        let secrets_path = format!("/jobs/{}/secrets", job_id);

        Fix {
            title: "Remove secrets clause if no secrets are needed".to_string(),
            description: "Remove the 'secrets:' clause entirely if the reusable workflow doesn't need any secrets. \
                This is the most secure option when no secrets are required. \
                Review the called workflow to confirm it doesn't require any secrets before applying this fix.".to_string(),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Remove {
                path: secrets_path,
            }]),
        }
    }

    /// Create a fix that provides manual review guidance
    fn create_manual_review_fix() -> Fix {
        Fix {
            title: "Manually review and specify required secrets".to_string(),
            description: "Review the reusable workflow being called to determine which secrets it actually requires. \
                Then replace 'secrets: inherit' with explicit secret declarations for only those secrets. \
                Check the workflow file and its documentation to understand its secret requirements. \
                Example: 'secrets: { forward-me: ${{ secrets.forward-me }}, deploy-token: ${{ secrets.DEPLOY_TOKEN }} }'".to_string(),
            apply: Box::new(|content: &str| -> anyhow::Result<Option<String>> {
                // Provide guidance but don't automatically change content
                Ok(Some(content.to_string()))
            }),
        }
    }

    /// Get the appropriate fixes for a secrets inherit issue
    fn get_secrets_inherit_fixes(job_id: &str) -> Vec<Fix> {
        vec![
            // Primary fix: replace with explicit secrets (matches documentation exactly)
            Self::create_explicit_secrets_fix(job_id),
            // Alternative: remove if no secrets needed
            Self::create_remove_secrets_fix(job_id),
            // Manual review guidance
            Self::create_manual_review_fix(),
        ]
    }
}

impl Audit for SecretsInherit {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_reusable_job<'doc>(
        &self,
        job: &super::ReusableWorkflowCallJob<'doc>,
    ) -> anyhow::Result<Vec<super::Finding<'doc>>> {
        let mut findings = vec![];

        if matches!(job.secrets, Some(Secrets::Inherit)) {
            let fixes = Self::get_secrets_inherit_fixes(job.id());

            let mut finding_builder = Self::finding()
                .add_location(
                    job.location()
                        .primary()
                        .with_keys(&["uses".into()])
                        .annotated("this reusable workflow"),
                )
                .add_location(
                    job.location()
                        .with_keys(&["secrets".into()])
                        .annotated("inherits all parent secrets"),
                )
                .confidence(Confidence::High)
                .severity(crate::finding::Severity::Medium);

            // Add fixes for this excessive secret inheritance
            for fix in fixes {
                finding_builder = finding_builder.fix(fix);
            }

            findings.push(finding_builder.build(job.parent())?);
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_safe_secret_name() {
        // Test basic alphanumeric names
        assert_eq!(
            SecretsInherit::generate_safe_secret_name("example-secret"),
            "example-secret"
        );

        // Test names with special characters
        assert_eq!(
            SecretsInherit::generate_safe_secret_name("MY_SECRET_TOKEN"),
            "my-secret-token"
        );

        // Test names with multiple special characters
        assert_eq!(
            SecretsInherit::generate_safe_secret_name("api.token@service"),
            "api-token-service"
        );

        // Test names with leading/trailing special characters
        assert_eq!(
            SecretsInherit::generate_safe_secret_name("_secret_"),
            "secret"
        );

        // Test names with consecutive special characters
        assert_eq!(
            SecretsInherit::generate_safe_secret_name("my___secret"),
            "my-secret"
        );

        // Test empty and edge cases
        assert_eq!(SecretsInherit::generate_safe_secret_name("___"), "");

        assert_eq!(SecretsInherit::generate_safe_secret_name("a"), "a");
    }

    #[test]
    fn test_explicit_secrets_fix() {
        let fix = SecretsInherit::create_explicit_secrets_fix("test-job");

        assert_eq!(
            fix.title,
            "Replace secrets: inherit with explicit secret declarations"
        );
        assert!(fix.description.contains("principle of least authority"));
        assert!(fix.description.contains("Before: secrets: inherit"));
        assert!(fix.description.contains("After:"));
        assert!(
            fix.description
                .contains("my-secret: ${{ secrets.MY_SECRET }}")
        );
        assert!(
            fix.description
                .contains("deploy-token: ${{ secrets.DEPLOY_TOKEN }}")
        );
    }

    #[test]
    fn test_remove_secrets_fix() {
        let fix = SecretsInherit::create_remove_secrets_fix("test-job");

        assert_eq!(fix.title, "Remove secrets clause if no secrets are needed");
        assert!(fix.description.contains("most secure option"));
        assert!(fix.description.contains("no secrets are required"));
    }

    #[test]
    fn test_manual_review_fix() {
        let fix = SecretsInherit::create_manual_review_fix();

        assert_eq!(fix.title, "Manually review and specify required secrets");
        assert!(fix.description.contains("Review the reusable workflow"));
        assert!(fix.description.contains(
            "{ forward-me: ${{ secrets.forward-me }}, deploy-token: ${{ secrets.DEPLOY_TOKEN }} }"
        ));
    }

    #[test]
    fn test_get_secrets_inherit_fixes_count() {
        let fixes = SecretsInherit::get_secrets_inherit_fixes("test-job");

        // Should return 3 fixes: explicit, remove, manual review
        assert_eq!(fixes.len(), 3);

        let titles: Vec<&str> = fixes.iter().map(|f| f.title.as_str()).collect();
        assert!(titles.contains(&"Replace secrets: inherit with explicit secret declarations"));
        assert!(titles.contains(&"Remove secrets clause if no secrets are needed"));
        assert!(titles.contains(&"Manually review and specify required secrets"));
    }

    #[test]
    fn test_explicit_secrets_fix_application() {
        let fix = SecretsInherit::create_explicit_secrets_fix("test-job");

        let yaml_content = r#"
jobs:
  test-job:
    uses: ./.github/workflows/reusable.yml
    secrets: inherit
"#;

        let result = fix.apply_to_content(yaml_content).unwrap().unwrap();

        // Should replace secrets: inherit with properly formatted secrets
        assert!(result.contains("secrets:"));
        assert!(result.contains("example-secret"));
        assert!(!result.contains("secrets: inherit"));

        // Try to parse the YAML to see if it's valid
        match serde_yaml::from_str::<serde_yaml::Value>(&result) {
            Ok(parsed) => {
                let secrets = &parsed["jobs"]["test-job"]["secrets"];
                assert!(secrets.is_mapping());
            }
            Err(e) => {
                panic!(
                    "Generated YAML is invalid: {}\nGenerated content:\n{}",
                    e, result
                );
            }
        }
    }

    #[test]
    fn test_remove_secrets_fix_application() {
        let fix = SecretsInherit::create_remove_secrets_fix("test-job");

        let yaml_content = r#"
jobs:
  test-job:
    uses: ./.github/workflows/reusable.yml
    secrets: inherit
"#;

        let result = fix.apply_to_content(yaml_content).unwrap().unwrap();

        // Should remove the secrets clause entirely
        assert!(!result.contains("secrets:"));
        assert!(!result.contains("inherit"));
    }
}
