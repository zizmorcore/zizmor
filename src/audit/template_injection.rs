//! (Very) primitive template injection detection.
//!
//! This looks for job steps where the step is a `run:` whose body
//! contains indicators of template expansion, i.e. anything matching `${{ }}`.
//! A small amount of additional processing is done to remove template
//! expressions that an attacker can't control.

use std::ops::Deref;

use github_actions_models::workflow::{job::StepBody, Job};

use crate::{
    finding::{Confidence, Severity},
    models::AuditConfig,
    utils::iter_expressions,
};

use super::WorkflowAudit;

pub(crate) struct TemplateInjection<'a> {
    pub(crate) _config: AuditConfig<'a>,
}

impl<'a> TemplateInjection<'a> {
    fn injectable_template_expressions(&self, run: &str) -> Vec<(String, Severity, Confidence)> {
        let mut bad_expressions = vec![];
        for expr in iter_expressions(run) {
            let bare = expr.as_bare();

            if bare.starts_with("secrets.") || bare == "github.token" {
                // While not ideal, secret expansion is typically not exploitable.
                continue;
            } else if bare.starts_with("inputs.") {
                // TODO: Currently low confidence because we don't check the
                // input's type. In the future, we should index back into
                // the workflow's triggers and exclude input expansions
                // from innocuous types, e.g. booleans.
                bad_expressions.push((bare.into(), Severity::High, Confidence::Low));
            } else if bare.starts_with("env.") {
                // Almost never exploitable.
                bad_expressions.push((bare.into(), Severity::Low, Confidence::High));
            } else if bare.starts_with("github.event.") {
                // TODO: Filter these more finely; not everything in the event
                // context is actually attacker-controllable.
                bad_expressions.push((bare.into(), Severity::High, Confidence::High));
            } else {
                // All other contexts are typically not attacker controllable,
                // but may be in obscure cases.
                bad_expressions.push((bare.into(), Severity::Informational, Confidence::Low));
            }
        }

        bad_expressions
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
        Ok(Self { _config: config })
    }

    fn audit<'w>(
        &mut self,
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

                for (expr, severity, confidence) in self.injectable_template_expressions(run) {
                    findings.push(
                        Self::finding()
                            .severity(severity)
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
