use std::ops::Deref as _;

use anyhow::Result;
use github_actions_models::{
    common::{EnvValue, Uses, expr::ExplicitExpr},
    workflow::job::StepBody,
};
use itertools::Itertools as _;

use super::{Audit, AuditLoadError, audit_meta};
use crate::{
    finding::{Confidence, Finding, Fix, Persona, Severity},
    models::{JobExt, StepCommon, uses::RepositoryUsesExt as _},
    state::AuditState,
    utils::split_patterns,
    yaml_patch::YamlPatchOperation,
};

pub(crate) struct Artipacked;

audit_meta!(
    Artipacked,
    "artipacked",
    "credential persistence through GitHub Actions artifacts"
);

impl Artipacked {
    fn dangerous_artifact_patterns<'b>(&self, path: &'b str) -> Vec<&'b str> {
        let mut patterns = vec![];
        for path in split_patterns(path) {
            match path {
                // TODO: this could be even more generic.
                "." | "./" | ".." | "../" => patterns.push(path),
                path => match ExplicitExpr::from_curly(path) {
                    Some(expr) if expr.as_bare().contains("github.workspace") => {
                        patterns.push(path)
                    }
                    // TODO: Other expressions worth flagging here?
                    Some(_) => continue,
                    _ => continue,
                },
            }
        }

        patterns
    }

    /// Create a Fix for setting persist-credentials: false
    fn create_persist_credentials_fix(job_id: String, checkout_index: usize) -> Fix {
        // Create the path to the with section
        let with_path = format!("/jobs/{}/steps/{}/with", job_id, checkout_index);

        Fix {
            title: "Set persist-credentials: false".to_string(),
            description: "To prevent credential persistence, set 'persist-credentials: false' in this checkout step.".to_string(),
            apply: Box::new(move |old_content: &str| -> anyhow::Result<Option<String>> {
                // This is a two-step approach:
                // 1. First, try to add persist-credentials to existing "with" section
                // 2. If that fails, add the whole "with" section

                let add_to_existing = crate::yaml_patch::apply_yaml_patch(
                    old_content,
                    vec![YamlPatchOperation::Add {
                        path: with_path.clone(),
                        key: "persist-credentials".to_string(),
                        value: serde_yaml::Value::Bool(false),
                    }]
                );

                if add_to_existing.is_ok() {
                    return add_to_existing.map(Some).map_err(Into::into);
                }

                // If adding to existing "with" section failed, create the whole "with" section
                let mut with_map = serde_yaml::Mapping::new();
                with_map.insert(
                    serde_yaml::Value::String("persist-credentials".to_string()),
                    serde_yaml::Value::Bool(false),
                );

                let step_path = format!("/jobs/{}/steps/{}", job_id, checkout_index);
                crate::yaml_patch::apply_yaml_patch(
                    old_content,
                    vec![YamlPatchOperation::Add {
                        path: step_path,
                        key: "with".to_string(),
                        value: serde_yaml::Value::Mapping(with_map),
                    }]
                ).map(Some).map_err(Into::into)
            }),
        }
    }
}

impl Audit for Artipacked {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError> {
        Ok(Self)
    }

    fn audit_normal_job<'doc>(&self, job: &super::NormalJob<'doc>) -> Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        // First, collect all vulnerable checkouts and upload steps independently.
        let mut vulnerable_checkouts = vec![];
        let mut vulnerable_uploads = vec![];
        for step in job.steps() {
            let StepBody::Uses {
                uses: Uses::Repository(uses),
                with,
            } = &step.deref().body
            else {
                continue;
            };

            if uses.matches("actions/checkout") {
                match with
                    .get("persist-credentials")
                    .map(|v| v.to_string())
                    .as_deref()
                {
                    Some("false") => continue,
                    Some("true") => {
                        // If a user explicitly sets `persist-credentials: true`,
                        // they probably mean it. Only report if in auditor mode.
                        vulnerable_checkouts.push((step, Persona::Auditor))
                    }
                    // TODO: handle expressions here.
                    // persist-credentials is true by default.
                    _ => vulnerable_checkouts.push((step, Persona::default())),
                }
            } else if uses.matches("actions/upload-artifact") {
                let Some(EnvValue::String(path)) = with.get("path") else {
                    continue;
                };

                let dangerous_paths = self.dangerous_artifact_patterns(path);
                if !dangerous_paths.is_empty() {
                    // TODO: plumb dangerous_paths into the annotation here.
                    vulnerable_uploads.push(step)
                }
            }
        }

        if vulnerable_uploads.is_empty() {
            // If we have no vulnerable uploads, then emit lower-confidence
            // findings for just the checkout steps.
            for (checkout, persona) in vulnerable_checkouts {
                let job_id = job.id().to_string();
                let checkout_index = checkout.index;
                findings.push(
                    Self::finding()
                        .severity(Severity::Medium)
                        .confidence(Confidence::Low)
                        .persona(persona)
                        .add_location(
                            checkout
                                .location()
                                .primary()
                                .annotated("does not set persist-credentials: false"),
                        )
                        .fix(Self::create_persist_credentials_fix(job_id, checkout_index))
                        .build(job.parent())?,
                );
            }
        } else {
            // Select only pairs where the vulnerable checkout precedes the
            // vulnerable upload. There are more efficient ways to do this than
            // a cartesian product, but this way is simple.
            for ((checkout, persona), upload) in vulnerable_checkouts
                .into_iter()
                .cartesian_product(vulnerable_uploads.into_iter())
            {
                if checkout.index < upload.index {
                    let job_id = job.id().to_string();
                    let checkout_index = checkout.index;
                    findings.push(
                        Self::finding()
                            .severity(Severity::High)
                            .confidence(Confidence::High)
                            .persona(persona)
                            .add_location(
                                checkout
                                    .location()
                                    .primary()
                                    .annotated("does not set persist-credentials: false"),
                            )
                            .add_location(
                                upload
                                    .location()
                                    .annotated("may leak the credentials persisted above"),
                            )
                            .fix(Self::create_persist_credentials_fix(job_id, checkout_index))
                            .build(job.parent())?,
                    );
                }
            }
        }

        Ok(findings)
    }
}
