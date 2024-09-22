//! (Very) primitive template injection detection.
//!
//! This looks for job steps where the step is a `run:` whose body
//! contains indicators of template expansion, i.e. anything matching `${{ }}`.
//! A small amount of additional processing is done to remove template
//! expressions that an attacker can't control.

use std::ops::Deref;

use github_actions_models::{
    common::LoE,
    workflow::{
        job::{Matrix, NormalJob, StepBody, Strategy},
        Job,
    },
};

use super::WorkflowAudit;
use crate::{
    finding::{Confidence, Severity},
    utils::extract_expressions,
    AuditConfig,
};

pub(crate) struct TemplateInjection<'a> {
    pub(crate) _config: AuditConfig<'a>,
}

/// Context members that are believed to be always safe.
const SAFE_CONTEXTS: &[&str] = &[
    // Like `secrets.*`: not safe to expose, but safe to interpolate.
    "github.token",
    // GitHub Actions-controlled local directory.
    "github.workspace",
    // GitHub Actions-controller runner architecture.
    "runner.arch",
];

impl<'a> TemplateInjection<'a> {
    /// Checks whether the given `expr` into `matrix` is static.
    fn matrix_is_static(&self, expr: &str, matrix: &Matrix) -> bool {
        // If the matrix's dimensions are an expression, then it's not static.
        let LoE::Literal(dimensions) = &matrix.dimensions else {
            return false;
        };

        // Our `expr` should be a literal path of `matrix.foo.bar.baz.etc`,
        // so we descend through the matrix based on it.
        let mut keys = expr.split('.').skip(1);

        let Some(key) = keys.next() else {
            // No path means that we're effectively expanding the entire matrix,
            // meaning *any* non-static component makes the entire expansion
            // non-static.

            // HACK: The correct way to do this is to walk `matrix.dimensions`,
            // but it could be arbitrarily deep. Instead, we YOLO the dimensions
            // back into YAML and see if the serialized equivalent has
            // any indicators of expansion (`${{ ... }}`) in it.
            // NOTE: Safe unwrap since `dimensions` was loaded directly from YAML
            let dimensions_yaml = serde_yaml::to_string(&dimensions).unwrap();
            return !(dimensions_yaml.contains("${{") && dimensions_yaml.contains("}}"));
        };

        match dimensions.get(key) {
            // This indicates a malformed matrix or matrix ref, which is
            // static for our purposes.
            None => true,
            // If our key is an expression, it's definitely not static.
            Some(LoE::Expr(_)) => false,
            Some(LoE::Literal(dim)) => {
                // TODO: This is imprecise: technically we should walk the
                // entire set of keys to determine if a specific index is
                // accessed + whether that index is an expression.
                // But doing that is hard, so we do the same YOLO reserialize
                // trick as above and consider this non-static
                // if it has any hint of a template expansion in it.
                let dim_yaml = serde_yaml::to_string(&dim).unwrap();
                !(dim_yaml.contains("${{") && dim_yaml.contains("}}"))
            }
        }
    }

    fn injectable_template_expressions(
        &self,
        run: &str,
        job: &NormalJob,
    ) -> Vec<(String, Severity, Confidence)> {
        let mut bad_expressions = vec![];
        for expr in extract_expressions(run) {
            let bare = expr.as_bare();

            if bare.starts_with("secrets.") {
                // While not ideal, secret expansion is typically not exploitable.
                continue;
            } else if SAFE_CONTEXTS.contains(&bare) {
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
            } else if bare.starts_with("matrix.") || bare == "matrix" {
                if let Some(Strategy { matrix, .. }) = &job.strategy {
                    let matrix_is_static = match matrix {
                        // The matrix is statically defined, but one
                        // or more keys might contain expressions.
                        LoE::Literal(matrix) => self.matrix_is_static(bare, matrix),
                        // The matrix is generated by an expression, meaning
                        // that it's trivially not static.
                        LoE::Expr(_) => false,
                    };

                    if !matrix_is_static {
                        bad_expressions.push((bare.into(), Severity::Medium, Confidence::Medium));
                    }
                }
                continue;
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

    fn desc() -> &'static str
    where
        Self: Sized,
    {
        "code injection via template expansion"
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
            let Job::NormalJob(normal) = job.deref() else {
                continue;
            };

            for step in job.steps() {
                let StepBody::Run { run, .. } = &step.deref().body else {
                    continue;
                };

                for (expr, severity, confidence) in
                    self.injectable_template_expressions(run, normal)
                {
                    findings.push(
                        Self::finding()
                            .severity(severity)
                            .confidence(confidence)
                            .add_location(
                                step.location()
                                    .with_keys(&["uses".into()])
                                    .annotated("this step"),
                            )
                            .add_location(step.location().with_keys(&["run".into()]).annotated(
                                format!("{expr} may expand into attacker-controllable code"),
                            ))
                            .build(workflow)?,
                    )
                }
            }
        }

        Ok(findings)
    }
}
