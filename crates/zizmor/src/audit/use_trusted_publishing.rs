use std::ops::Deref;

use github_actions_models::{
    common::{EnvValue, Uses},
    workflow::job::StepBody,
};
use indexmap::IndexMap;

use super::{Audit, AuditLoadError, audit_meta};
use crate::{
    apply_yaml_patch,
    finding::{Confidence, Fix, Severity},
    models::{JobExt, StepCommon, uses::RepositoryUsesExt as _},
    state::AuditState,
    yaml_patch::YamlPatchOperation,
};

const USES_MANUAL_CREDENTIAL: &str =
    "uses a manually-configured credential instead of Trusted Publishing";

const KNOWN_PYTHON_TP_INDICES: &[&str] = &[
    "https://upload.pypi.org/legacy/",
    "https://test.pypi.org/legacy/",
];

pub(crate) struct UseTrustedPublishing;

audit_meta!(
    UseTrustedPublishing,
    "use-trusted-publishing",
    "prefer trusted publishing for authentication"
);

impl UseTrustedPublishing {
    fn pypi_publish_uses_manual_credentials(&self, with: &IndexMap<String, EnvValue>) -> bool {
        // `password` implies the step isn't using Trusted Publishing,
        // but we also need to check `repository-url` to prevent false-positives
        // on third-party indices.
        let has_manual_credential = with.contains_key("password");

        match with
            .get("repository-url")
            .or_else(|| with.get("repository_url"))
        {
            Some(repo_url) => {
                has_manual_credential
                    && KNOWN_PYTHON_TP_INDICES.contains(&repo_url.to_string().as_str())
            }
            None => has_manual_credential,
        }
    }

    fn release_gem_uses_manual_credentials(&self, with: &IndexMap<String, EnvValue>) -> bool {
        match with.get("setup-trusted-publisher") {
            Some(v) if v.to_string() == "true" => false,
            // Anything besides `true` means to *not* use trusted publishing.
            Some(_) => true,
            // Not set means the default, which is trusted publishing.
            None => false,
        }
    }

    fn rubygems_credential_uses_manual_credentials(
        &self,
        with: &IndexMap<String, EnvValue>,
    ) -> bool {
        with.contains_key("api-token")
    }

    /// Create a fix that removes the password field and adds id-token permission for PyPI
    fn create_pypi_trusted_publishing_fix(job_id: String, step_index: usize) -> Fix {
        let step_path = format!("/jobs/{}/steps/{}", job_id, step_index);
        let password_path = format!("{}/with/password", step_path);
        let job_path = format!("/jobs/{}", job_id);

        Fix {
            title: "Enable Trusted Publishing for PyPI".to_string(),
            description: "Remove the 'password' field and ensure 'id-token: write' permission is set. \
                Trusted Publishing uses OIDC tokens instead of manual API tokens, providing better security. \
                You'll need to configure the trusted publisher in your PyPI project settings first.".to_string(),
            apply: Box::new(move |old_content: &str| -> anyhow::Result<Option<String>> {
                // First, remove the password field
                let content_without_password = crate::yaml_patch::apply_yaml_patch(
                    old_content,
                    vec![YamlPatchOperation::Remove {
                        path: password_path.clone(),
                    }]
                )?;

                // Then, use MergeInto to add id-token permission to the job
                // This will create the permissions section if it doesn't exist, or add to it if it does
                let final_content = crate::yaml_patch::apply_yaml_patch(
                    &content_without_password,
                    vec![YamlPatchOperation::MergeInto {
                        path: job_path.clone(),
                        key: "permissions".to_string(),
                        value: {
                            let mut permissions_map = serde_yaml::Mapping::new();
                            permissions_map.insert(
                                serde_yaml::Value::String("id-token".to_string()),
                                serde_yaml::Value::String("write".to_string()),
                            );
                            serde_yaml::Value::Mapping(permissions_map)
                        },
                    }]
                )?;

                Ok(Some(final_content))
            }),
        }
    }

    /// Create a fix that provides guidance on setting up PyPI trusted publishing
    fn create_pypi_setup_guidance_fix() -> Fix {
        Fix {
            title: "Set up PyPI Trusted Publishing".to_string(),
            description: "To use Trusted Publishing with PyPI:\n\
                1. Go to your PyPI project settings\n\
                2. Navigate to the 'Publishing' section\n\
                3. Add a new trusted publisher for GitHub Actions\n\
                4. Specify your repository owner, name, and workflow filename\n\
                5. Optionally specify the environment name if using deployment environments\n\
                6. Remove the 'password' field from your workflow and ensure 'id-token: write' permission is set\n\n\
                This eliminates the need for long-lived API tokens and provides better security through OIDC.".to_string(),
            apply: Box::new(|content: &str| -> anyhow::Result<Option<String>> {
                // Guidance-only fix
                Ok(Some(content.to_string()))
            }),
        }
    }

    /// Create a fix that enables trusted publishing for RubyGems release-gem action
    fn create_rubygems_release_gem_fix(job_id: String, step_index: usize) -> Fix {
        let setup_trusted_publisher_path = format!(
            "/jobs/{}/steps/{}/with/setup-trusted-publisher",
            job_id, step_index
        );

        Fix {
            title: "Enable Trusted Publishing for RubyGems".to_string(),
            description:
                "Set 'setup-trusted-publisher: true' to enable Trusted Publishing for RubyGems. \
                This uses OIDC tokens instead of manual API tokens for better security."
                    .to_string(),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Replace {
                path: setup_trusted_publisher_path,
                value: serde_yaml::Value::String("true".to_string()),
            }]),
        }
    }

    /// Create a fix that removes api-token and provides guidance for RubyGems credential action
    fn create_rubygems_credential_fix(job_id: String, step_index: usize) -> Fix {
        let api_token_path = format!("/jobs/{}/steps/{}/with/api-token", job_id, step_index);

        Fix {
            title: "Remove manual API token for RubyGems".to_string(),
            description: "Remove the 'api-token' field and use Trusted Publishing instead. \
                Configure the trusted publisher in your RubyGems.org account settings first."
                .to_string(),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Remove {
                path: api_token_path,
            }]),
        }
    }

    /// Create a fix that provides guidance on setting up RubyGems trusted publishing
    fn create_rubygems_setup_guidance_fix() -> Fix {
        Fix {
            title: "Set up RubyGems Trusted Publishing".to_string(),
            description: "To use Trusted Publishing with RubyGems:\n\
                1. Go to your RubyGems.org account settings\n\
                2. Navigate to the 'Trusted Publishing' section\n\
                3. Add a new trusted publisher for GitHub Actions\n\
                4. Specify your repository owner, name, and workflow filename\n\
                5. Optionally specify the environment name if using deployment environments\n\
                6. Update your workflow to use trusted publishing instead of API tokens\n\n\
                This provides better security through OIDC tokens instead of long-lived API keys."
                .to_string(),
            apply: Box::new(|content: &str| -> anyhow::Result<Option<String>> {
                // Guidance-only fix
                Ok(Some(content.to_string()))
            }),
        }
    }

    /// Create fixes for PyPI trusted publishing
    fn create_pypi_fixes(job_id: String, step_index: usize) -> Vec<Fix> {
        vec![
            Self::create_pypi_trusted_publishing_fix(job_id, step_index),
            Self::create_pypi_setup_guidance_fix(),
        ]
    }

    /// Create fixes for RubyGems release-gem trusted publishing
    fn create_rubygems_release_gem_fixes(job_id: String, step_index: usize) -> Vec<Fix> {
        vec![
            Self::create_rubygems_release_gem_fix(job_id, step_index),
            Self::create_rubygems_setup_guidance_fix(),
        ]
    }

    /// Create fixes for RubyGems credential trusted publishing
    fn create_rubygems_credential_fixes(job_id: String, step_index: usize) -> Vec<Fix> {
        vec![
            Self::create_rubygems_credential_fix(job_id, step_index),
            Self::create_rubygems_setup_guidance_fix(),
        ]
    }
}

impl Audit for UseTrustedPublishing {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError> {
        Ok(Self)
    }

    fn audit_step<'doc>(
        &self,
        step: &super::Step<'doc>,
    ) -> anyhow::Result<Vec<super::Finding<'doc>>> {
        let mut findings = vec![];

        let StepBody::Uses {
            uses: Uses::Repository(uses),
            with,
        } = &step.deref().body
        else {
            return Ok(findings);
        };

        let mut candidate = Self::finding()
            .severity(Severity::Informational)
            .confidence(Confidence::High)
            .add_location(
                step.location()
                    .primary()
                    .with_keys(&["uses".into()])
                    .annotated("this step"),
            );

        if uses.matches("pypa/gh-action-pypi-publish")
            && self.pypi_publish_uses_manual_credentials(with)
        {
            let job_id = step.job().id().to_string();
            let step_index = step.index;
            let fixes = Self::create_pypi_fixes(job_id, step_index);

            for fix in fixes {
                candidate = candidate.fix(fix);
            }

            findings.push(
                candidate
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(&["with".into(), "password".into()])
                            .annotated(USES_MANUAL_CREDENTIAL),
                    )
                    .build(step.workflow())?,
            );
        } else if uses.matches("rubygems/release-gem")
            && self.release_gem_uses_manual_credentials(with)
        {
            let job_id = step.job().id().to_string();
            let step_index = step.index;
            let fixes = Self::create_rubygems_release_gem_fixes(job_id, step_index);

            for fix in fixes {
                candidate = candidate.fix(fix);
            }

            findings.push(
                candidate
                    .add_location(step.location().primary().annotated(USES_MANUAL_CREDENTIAL))
                    .build(step.workflow())?,
            );
        } else if uses.matches("rubygems/configure-rubygems-credential")
            && self.rubygems_credential_uses_manual_credentials(with)
        {
            let job_id = step.job().id().to_string();
            let step_index = step.index;
            let fixes = Self::create_rubygems_credential_fixes(job_id, step_index);

            for fix in fixes {
                candidate = candidate.fix(fix);
            }

            findings.push(
                candidate
                    .add_location(step.location().primary().annotated(USES_MANUAL_CREDENTIAL))
                    .build(step.workflow())?,
            );
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pypi_trusted_publishing_fix() {
        let fix =
            UseTrustedPublishing::create_pypi_trusted_publishing_fix("publish".to_string(), 1);

        assert_eq!(fix.title, "Enable Trusted Publishing for PyPI");
        assert!(fix.description.contains("Remove the 'password' field"));
        assert!(fix.description.contains("id-token: write"));
        assert!(fix.description.contains("OIDC tokens"));

        // Test the fix application on a simple workflow
        let yaml_content = r#"jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pypa/gh-action-pypi-publish@release/v1
        with:
          password: ${{ secrets.PYPI_TOKEN }}
          repository-url: https://upload.pypi.org/legacy/"#;

        let result = fix.apply_to_content(yaml_content).unwrap().unwrap();

        // Should remove password and add id-token permission
        assert!(!result.contains("password: ${{ secrets.PYPI_TOKEN }}"));
        assert!(result.contains("id-token: write"));
    }

    #[test]
    fn test_pypi_setup_guidance_fix() {
        let fix = UseTrustedPublishing::create_pypi_setup_guidance_fix();

        assert_eq!(fix.title, "Set up PyPI Trusted Publishing");
        assert!(fix.description.contains("PyPI project settings"));
        assert!(fix.description.contains("Publishing"));
        assert!(fix.description.contains("trusted publisher"));
        assert!(fix.description.contains("OIDC"));

        // Test that the fix doesn't modify content (guidance only)
        let result = fix.apply_to_content("test content").unwrap();
        assert_eq!(result, Some("test content".to_string()));
    }

    #[test]
    fn test_rubygems_release_gem_fix() {
        let fix = UseTrustedPublishing::create_rubygems_release_gem_fix("publish".to_string(), 0);

        assert_eq!(fix.title, "Enable Trusted Publishing for RubyGems");
        assert!(fix.description.contains("setup-trusted-publisher: true"));
        assert!(fix.description.contains("OIDC tokens"));

        // Test the fix application
        let yaml_content = r#"jobs:
  publish:
    steps:
      - uses: rubygems/release-gem@v1
        with:
          setup-trusted-publisher: false"#;

        let result = fix.apply_to_content(yaml_content).unwrap().unwrap();
        // The YAML patch will quote the value, so check for both possibilities
        assert!(
            result.contains("setup-trusted-publisher: true")
                || result.contains("setup-trusted-publisher: 'true'")
        );
        // Make sure the old value is gone
        assert!(!result.contains("setup-trusted-publisher: false"));
    }

    #[test]
    fn test_rubygems_credential_fix() {
        let fix = UseTrustedPublishing::create_rubygems_credential_fix("publish".to_string(), 0);

        assert_eq!(fix.title, "Remove manual API token for RubyGems");
        assert!(fix.description.contains("Remove the 'api-token' field"));
        assert!(fix.description.contains("Trusted Publishing"));

        // Test the fix application
        let yaml_content = r#"jobs:
  publish:
    steps:
      - uses: rubygems/configure-rubygems-credential@v1
        with:
          api-token: ${{ secrets.RUBYGEMS_TOKEN }}"#;

        let result = fix.apply_to_content(yaml_content).unwrap().unwrap();
        assert!(!result.contains("api-token: ${{ secrets.RUBYGEMS_TOKEN }}"));
    }

    #[test]
    fn test_rubygems_setup_guidance_fix() {
        let fix = UseTrustedPublishing::create_rubygems_setup_guidance_fix();

        assert_eq!(fix.title, "Set up RubyGems Trusted Publishing");
        assert!(fix.description.contains("RubyGems.org account settings"));
        assert!(fix.description.contains("Trusted Publishing"));
        assert!(fix.description.contains("OIDC tokens"));

        // Test that the fix doesn't modify content (guidance only)
        let result = fix.apply_to_content("test content").unwrap();
        assert_eq!(result, Some("test content".to_string()));
    }

    #[test]
    fn test_create_pypi_fixes() {
        let fixes = UseTrustedPublishing::create_pypi_fixes("test-job".to_string(), 1);

        assert_eq!(fixes.len(), 2);
        assert_eq!(fixes[0].title, "Enable Trusted Publishing for PyPI");
        assert_eq!(fixes[1].title, "Set up PyPI Trusted Publishing");
    }

    #[test]
    fn test_create_rubygems_release_gem_fixes() {
        let fixes =
            UseTrustedPublishing::create_rubygems_release_gem_fixes("test-job".to_string(), 0);

        assert_eq!(fixes.len(), 2);
        assert_eq!(fixes[0].title, "Enable Trusted Publishing for RubyGems");
        assert_eq!(fixes[1].title, "Set up RubyGems Trusted Publishing");
    }

    #[test]
    fn test_create_rubygems_credential_fixes() {
        let fixes =
            UseTrustedPublishing::create_rubygems_credential_fixes("test-job".to_string(), 0);

        assert_eq!(fixes.len(), 2);
        assert_eq!(fixes[0].title, "Remove manual API token for RubyGems");
        assert_eq!(fixes[1].title, "Set up RubyGems Trusted Publishing");
    }

    #[test]
    fn test_fix_descriptions_are_informative() {
        let fixes = [
            UseTrustedPublishing::create_pypi_trusted_publishing_fix("job".to_string(), 0),
            UseTrustedPublishing::create_pypi_setup_guidance_fix(),
            UseTrustedPublishing::create_rubygems_release_gem_fix("job".to_string(), 0),
            UseTrustedPublishing::create_rubygems_credential_fix("job".to_string(), 0),
            UseTrustedPublishing::create_rubygems_setup_guidance_fix(),
        ];

        for fix in &fixes {
            // Each fix should have a meaningful title and description
            assert!(!fix.title.is_empty());
            assert!(!fix.description.is_empty());
            assert!(fix.description.len() > 50); // Should be reasonably detailed
        }
    }
}
