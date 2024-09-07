use std::ops::Deref;

use anyhow::Result;
use github_actions_models::{
    common::{EnvValue, Expression},
    workflow::{job::StepBody, Job},
};
use itertools::Itertools;

use super::WorkflowAudit;
use crate::{
    finding::{Confidence, Finding, Severity},
    models::AuditConfig,
};
use crate::{models::Workflow, utils::split_patterns};

pub(crate) struct Artipacked<'a> {
    pub(crate) config: AuditConfig<'a>,
}

impl<'a> Artipacked<'a> {
    fn dangerous_artifact_patterns<'b>(&self, path: &'b str) -> Vec<&'b str> {
        let mut patterns = vec![];
        for path in split_patterns(path) {
            match path {
                // TODO: this could be even more generic.
                "." | "./" | ".." | "../" => patterns.push(path),
                path => match Expression::from_curly(path.into()) {
                    Some(expr) if expr.as_bare() == "github.workspace" => patterns.push(path),
                    // TODO: Other expressions worth flagging here?
                    Some(_) => continue,
                    _ => continue,
                },
            }
        }

        patterns
    }
}

impl<'a> WorkflowAudit<'a> for Artipacked<'a> {
    fn ident() -> &'static str {
        "artipacked"
    }

    fn new(config: AuditConfig<'a>) -> Result<Self> {
        Ok(Self { config })
    }

    fn audit<'w>(&mut self, workflow: &'w Workflow) -> Result<Vec<Finding<'w>>> {
        log::debug!("audit: {} evaluating {}", Self::ident(), &workflow.filename);

        let mut findings = vec![];

        for job in workflow.jobs() {
            // Reusable workflows aren't checked, for now,
            // since we'd need to resolve their contents to determine
            // whether their interior steps are vulnerable.
            if !matches!(job.inner, Job::NormalJob(_)) {
                continue;
            }

            // First, collect all vulnerable checkouts and upload steps independently.
            let mut vulnerable_checkouts = vec![];
            let mut vulnerable_uploads = vec![];
            for step in job.steps() {
                let StepBody::Uses { ref uses, ref with } = &step.deref().body else {
                    continue;
                };

                if uses.starts_with("actions/checkout") {
                    match with.get("persist-credentials") {
                        Some(EnvValue::Boolean(false)) => continue,
                        Some(EnvValue::Boolean(true)) => {
                            // If a user explicitly sets `persist-credentials: true`,
                            // they probably mean it. Only report if being pedantic.
                            if self.config.pedantic {
                                vulnerable_checkouts.push(step)
                            } else {
                                continue;
                            }
                        }
                        // TODO: handle expressions and literal strings here.
                        // persist-credentials is true by default.
                        _ => vulnerable_checkouts.push(step),
                    }
                } else if uses.starts_with("actions/upload-artifact") {
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
                for checkout in vulnerable_checkouts {
                    findings.push(
                        Self::finding()
                            .severity(Severity::Medium)
                            .confidence(Confidence::Low)
                            .add_location(
                                checkout
                                    .location()
                                    .annotated("does not set persist-credentials: false"),
                            )
                            .build(workflow)?,
                    );
                }
            } else {
                // Select only pairs where the vulnerable checkout precedes the
                // vulnerable upload. There are more efficient ways to do this than
                // a cartesian product, but this way is simple.
                for (checkout, upload) in vulnerable_checkouts
                    .into_iter()
                    .cartesian_product(vulnerable_uploads.into_iter())
                {
                    if checkout.index < upload.index {
                        findings.push(
                            Self::finding()
                                .severity(Severity::High)
                                .confidence(Confidence::High)
                                .add_location(
                                    checkout
                                        .location()
                                        .annotated("does not set persist-credentials: false"),
                                )
                                .add_location(
                                    upload
                                        .location()
                                        .annotated("may leak the credentials persisted above"),
                                )
                                .build(workflow)?,
                        );
                    }
                }
            }
        }

        log::debug!("audit: {} completed {}", Self::ident(), &workflow.filename);

        Ok(findings)
    }
}
