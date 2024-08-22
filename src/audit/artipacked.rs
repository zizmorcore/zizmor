use anyhow::Result;
use github_actions_models::{
    common::EnvValue,
    workflow::{job::StepBody, Job},
};
use itertools::Itertools;

use crate::{finding::Determinations, models::Workflow};
use crate::{
    finding::{Confidence, Finding, Severity},
    models::AuditConfig,
};

use super::WorkflowAudit;

pub(crate) struct Artipacked<'a> {
    pub(crate) config: AuditConfig<'a>,
}

impl<'a> WorkflowAudit<'a> for Artipacked<'a> {
    const AUDIT_IDENT: &'static str = "artipacked";

    fn new(config: AuditConfig<'a>) -> Result<Self> {
        Ok(Self { config })
    }

    fn audit<'w>(&self, workflow: &'w Workflow) -> Result<Vec<Finding<'w>>> {
        log::debug!(
            "audit: {} evaluating {}",
            Self::AUDIT_IDENT,
            &workflow.filename
        );

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
                let StepBody::Uses { ref uses, ref with } = &step.inner.body else {
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
                    match with.get("path") {
                        // TODO: This is pretty naive -- we should also flag on
                        // `${{ expressions }}` and absolute paths, etc.
                        Some(EnvValue::String(s)) if s == "." || s == ".." => {
                            vulnerable_uploads.push(step)
                        }
                        _ => continue,
                    }
                }
            }

            if vulnerable_uploads.is_empty() {
                // If we have no vulnerable uploads, then emit lower-confidence
                // findings for just the checkout steps.
                for checkout in vulnerable_checkouts {
                    findings.push(Finding {
                        ident: Artipacked::AUDIT_IDENT,
                        determinations: Determinations {
                            severity: Severity::Medium,
                            confidence: Confidence::Low,
                        },
                        locations: vec![checkout.location().clone()],
                    })
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
                        findings.push(Finding {
                            ident: Artipacked::AUDIT_IDENT,
                            determinations: Determinations {
                                severity: Severity::High,
                                confidence: Confidence::High,
                            },
                            locations: vec![checkout.location().clone(), upload.location().clone()],
                        });
                    }
                }
            }
        }

        log::debug!(
            "audit: {} completed {}",
            Self::AUDIT_IDENT,
            &workflow.filename
        );

        Ok(findings)
    }
}
