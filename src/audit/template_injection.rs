//! (Very) primitive template injection detection.
//!
//! This looks for job steps where the step is a `run:` whose body
//! contains indicators of template expansion, i.e. anything matching `${{ }}`.
//! A small amount of additional processing is done to remove template
//! expressions that an attacker can't control.

use std::ops::Deref;

use github_actions_models::workflow::{job::StepBody, Job};
use regex::Regex;

use crate::{
    finding::{Confidence, Severity},
    models::AuditConfig,
};

use super::WorkflowAudit;

pub(crate) struct TemplateInjection<'a> {
    pub(crate) _config: AuditConfig<'a>,
    expr_pattern: Regex,
}

impl<'a> TemplateInjection<'a> {
    fn injectable_template_expressions(&self, run: &str) -> Vec<(&str, Confidence)> {
        for (_, [expr]) in self.expr_pattern.captures_iter(run).map(|c| c.extract()) {
            log::debug!("found expression candidate: {expr}")
        }

        vec![]
    }
}

impl<'a> WorkflowAudit<'a> for TemplateInjection<'a> {
    fn ident() -> &'static str
    where
        Self: Sized,
    {
        "template-injection"
    }

    fn new(config: AuditConfig<'a>) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            _config: config,
            expr_pattern: Regex::new("${{(.+)}}").unwrap(),
        })
    }

    fn audit<'w>(
        &self,
        workflow: &'w crate::models::Workflow,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'w>>> {
        let mut findings = vec![];

        for job in workflow.jobs() {
            if !matches!(job.deref(), Job::NormalJob(_)) {
                continue;
            }

            for step in job.steps() {
                let StepBody::Run { run, .. } = &step.deref().body else {
                    continue;
                };

                for (expr, confidence) in self.injectable_template_expressions(run) {
                    findings.push(
                        Self::finding()
                            .severity(Severity::High)
                            .confidence(confidence)
                            .add_location(step.location().annotated(format!(
                                "template may expand into attacker-controllable code: {expr}"
                            )))
                            .build(workflow)?,
                    )
                }
            }
        }

        Ok(findings)
    }
}
