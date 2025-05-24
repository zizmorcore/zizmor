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
    /// Create a fix that replaces secrets: inherit with explicit secret declarations
    fn create_explicit_secrets_fix(job_id: &str) -> Fix {
        let secrets_path = format!("/jobs/{}/secrets", job_id);

        Fix {
            title: "Replace secrets: inherit with explicit secret declarations".to_string(),
            description: "Replace 'secrets: inherit' with explicit secret declarations. \
                List only the specific secrets that the reusable workflow actually needs. \
                For example: 'secrets: { my-secret: ${{ secrets.MY_SECRET }}, deploy-token: ${{ secrets.DEPLOY_TOKEN }} }'. \
                This follows the principle of least authority and makes secret usage explicit and auditable.".to_string(),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Replace {
                path: secrets_path,
                value: {
                    let mut example_secrets = serde_yaml::Mapping::new();
                    example_secrets.insert(
                        serde_yaml::Value::String("example-secret".to_string()),
                        serde_yaml::Value::String("${{ secrets.EXAMPLE_SECRET }}".to_string()),
                    );
                    serde_yaml::Value::Mapping(example_secrets)
                },
            }]),
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
    fn test_explicit_secrets_fix() {
        let fix = SecretsInherit::create_explicit_secrets_fix("test-job");

        assert_eq!(
            fix.title,
            "Replace secrets: inherit with explicit secret declarations"
        );
        assert!(fix.description.contains("principle of least authority"));
        assert!(
            fix.description
                .contains("secrets: { my-secret: ${{ secrets.MY_SECRET }}, deploy-token: ${{ secrets.DEPLOY_TOKEN }} }")
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

        // Should replace secrets: inherit with an example secret
        assert!(result.contains("secrets: example-secret: ${{ secrets.EXAMPLE_SECRET }}"));
        assert!(!result.contains("secrets: inherit"));
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
