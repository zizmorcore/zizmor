use anyhow::Result;
use github_actions_models::{
    common::EnvValue,
    workflow::{job::StepBody, Job},
};
use itertools::Itertools;

use crate::models::Workflow;
use crate::{
    finding::{Confidence, Finding, JobIdentity, Severity, StepIdentity},
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

    async fn audit(&self, workflow: &Workflow) -> Result<Vec<Finding>> {
        log::debug!(
            "audit: {} evaluating {}",
            Self::AUDIT_IDENT,
            &workflow.filename
        );

        let mut findings = vec![];

        for (jobid, job) in workflow.jobs.iter() {
            // Reusable workflows aren't checked, for now,
            // since we'd need to resolve their contents to determine
            // whether their interior steps are vulnerable.
            let Job::NormalJob(job) = job else {
                continue;
            };

            // First, collect all vulnerable checkouts and upload steps independently.
            let mut vulnerable_checkouts = vec![];
            let mut vulnerable_uploads = vec![];
            for (stepno, step) in job.steps.iter().enumerate() {
                let StepBody::Uses { uses, with } = &step.body else {
                    continue;
                };

                if uses.starts_with("actions/checkout") {
                    match with.get("persist-credentials") {
                        Some(EnvValue::Boolean(false)) => continue,
                        Some(EnvValue::Boolean(true)) => {
                            // If a user explicitly sets `persist-credentials: true`,
                            // they probably mean it. Only report if being pedantic.
                            if self.config.pedantic {
                                vulnerable_checkouts.push(StepIdentity::new(stepno, step))
                            } else {
                                continue;
                            }
                        }
                        // TODO: handle expressions and literal strings here.
                        // persist-credentials is true by default.
                        _ => vulnerable_checkouts.push(StepIdentity::new(stepno, step)),
                    }
                }

                if uses.starts_with("actions/upload-artifact") {
                    match with.get("path") {
                        // TODO: This is pretty naive -- we should also flag on
                        // `${{ expressions }}` and absolute paths, etc.
                        Some(EnvValue::String(s)) if s == "." || s == ".." => {
                            vulnerable_uploads.push(StepIdentity::new(stepno, step))
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
                        workflow: workflow.filename.clone(),
                        severity: Severity::Medium,
                        confidence: Confidence::Low,
                        job: Some(JobIdentity::new(jobid, job.name.as_deref())),
                        steps: vec![checkout],
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
                    if checkout.number < upload.number {
                        findings.push(Finding {
                            ident: Artipacked::AUDIT_IDENT,
                            workflow: workflow.filename.clone(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            job: Some(JobIdentity::new(jobid, job.name.as_deref())),
                            steps: vec![checkout, upload],
                        })
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
