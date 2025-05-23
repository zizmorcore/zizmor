use github_actions_models::{
    common::expr::ExplicitExpr,
    workflow::job::{Container, DockerCredentials},
};

use super::{Audit, AuditLoadError, Job, audit_meta};
use crate::{
    apply_yaml_patch,
    finding::{Confidence, Fix, Severity},
    models::JobExt as _,
    state::AuditState,
    yaml_patch::YamlPatchOperation,
};

pub(crate) struct HardcodedContainerCredentials;

audit_meta!(
    HardcodedContainerCredentials,
    "hardcoded-container-credentials",
    "hardcoded credential in GitHub Actions container configurations"
);

/// Represents the different types of credential fields that can be hardcoded
#[derive(Debug, Clone, Copy)]
enum CredentialField {
    Username,
    Password,
}

impl CredentialField {
    fn field_name(&self) -> &'static str {
        match self {
            CredentialField::Username => "username",
            CredentialField::Password => "password",
        }
    }

    fn secret_suffix(&self) -> &'static str {
        match self {
            CredentialField::Username => "USERNAME",
            CredentialField::Password => "PASSWORD",
        }
    }

    fn display_name(&self) -> &'static str {
        match self {
            CredentialField::Username => "username",
            CredentialField::Password => "password",
        }
    }
}

impl HardcodedContainerCredentials {
    /// Generate a secret name for a given credential field and context
    fn get_secret_name(credential_field: CredentialField, credential_type: &str) -> String {
        match credential_type {
            "container" => format!("REGISTRY_{}", credential_field.secret_suffix()),
            service => format!(
                "{}_REGISTRY_{}",
                service.to_uppercase().replace('-', "_"),
                credential_field.secret_suffix()
            ),
        }
    }

    /// Create a fix that replaces hardcoded credential with a secret reference
    fn create_secret_replacement_fix(
        path: &str,
        credential_field: CredentialField,
        credential_type: &str,
    ) -> Fix {
        let secret_name = Self::get_secret_name(credential_field, credential_type);
        let field_name = credential_field.field_name();
        let display_name = credential_field.display_name();

        Fix {
            title: format!(
                "Replace hardcoded {} {} with secret",
                credential_type, display_name
            ),
            description: format!(
                "Replace the hardcoded {} with a reference to a GitHub secret. \
                Create a secret named '{}' in your repository settings (Settings → Secrets and variables → Actions) \
                and reference it using '${{{{ secrets.{} }}}}'. This prevents the {} from being exposed in your workflow file.",
                display_name, secret_name, secret_name, display_name
            ),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Replace {
                path: format!("{}/{}", path, field_name),
                value: serde_yaml::Value::String(format!("${{{{ secrets.{} }}}}", secret_name)),
            }]),
        }
    }

    /// Get the appropriate fix for a hardcoded credential field
    fn get_fix_for_credential(
        job_id: &str,
        credential_field: CredentialField,
        credential_type: &str,
        is_service: bool,
        service_name: Option<&str>,
    ) -> Fix {
        let path = if is_service {
            format!(
                "/jobs/{}/services/{}/credentials",
                job_id,
                service_name.unwrap()
            )
        } else {
            format!("/jobs/{}/container/credentials", job_id)
        };

        Self::create_secret_replacement_fix(&path, credential_field, credential_type)
    }

    /// Check if a credential field is hardcoded and create a finding if so
    fn check_and_create_finding<'doc>(
        &self,
        workflow: &'doc crate::models::Workflow,
        job: &super::NormalJob<'doc>,
        credential_field: CredentialField,
        _credential_value: &str,
        credential_type: &str,
        is_service: bool,
        service_name: Option<&'doc str>,
        findings: &mut Vec<crate::finding::Finding<'doc>>,
    ) -> anyhow::Result<()> {
        let display_name = credential_field.display_name();
        let annotation = if is_service {
            format!(
                "service {}: container registry {} is hard-coded",
                service_name.unwrap(),
                display_name
            )
        } else {
            format!("container registry {} is hard-coded", display_name)
        };

        let location_keys = if is_service {
            vec![
                "services".into(),
                service_name.unwrap().into(),
                "credentials".into(),
            ]
        } else {
            vec!["container".into(), "credentials".into()]
        };

        let fix = Self::get_fix_for_credential(
            job.id(),
            credential_field,
            credential_type,
            is_service,
            service_name,
        );

        let finding = Self::finding()
            .severity(Severity::High)
            .confidence(Confidence::High)
            .add_location(
                job.location()
                    .primary()
                    .with_keys(&location_keys)
                    .annotated(annotation),
            )
            .fix(fix)
            .build(workflow)?;

        findings.push(finding);
        Ok(())
    }
}

impl Audit for HardcodedContainerCredentials {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_workflow<'doc>(
        &self,
        workflow: &'doc crate::models::Workflow,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'doc>>> {
        let mut findings = vec![];

        for job in workflow.jobs() {
            let Job::NormalJob(job) = &job else {
                continue;
            };

            // Check container credentials
            if let Some(Container::Container {
                image: _,
                credentials: Some(DockerCredentials { username, password }),
                ..
            }) = &job.container
            {
                // Check username if present
                if let Some(username) = username {
                    if ExplicitExpr::from_curly(username).is_none() {
                        self.check_and_create_finding(
                            workflow,
                            job,
                            CredentialField::Username,
                            username,
                            "container",
                            false,
                            None,
                            &mut findings,
                        )?;
                    }
                }

                // Check password if present
                if let Some(password) = password {
                    if ExplicitExpr::from_curly(password).is_none() {
                        self.check_and_create_finding(
                            workflow,
                            job,
                            CredentialField::Password,
                            password,
                            "container",
                            false,
                            None,
                            &mut findings,
                        )?;
                    }
                }
            }

            // Check service credentials
            for (service, config) in job.services.iter() {
                if let Container::Container {
                    image: _,
                    credentials: Some(DockerCredentials { username, password }),
                    ..
                } = &config
                {
                    // Check username if present
                    if let Some(username) = username {
                        if ExplicitExpr::from_curly(username).is_none() {
                            self.check_and_create_finding(
                                workflow,
                                job,
                                CredentialField::Username,
                                username,
                                service.as_str(),
                                true,
                                Some(service.as_str()),
                                &mut findings,
                            )?;
                        }
                    }

                    // Check password if present
                    if let Some(password) = password {
                        if ExplicitExpr::from_curly(password).is_none() {
                            self.check_and_create_finding(
                                workflow,
                                job,
                                CredentialField::Password,
                                password,
                                service.as_str(),
                                true,
                                Some(service.as_str()),
                                &mut findings,
                            )?;
                        }
                    }
                }
            }
        }

        Ok(findings)
    }
}
