//! (Very) primitive template injection detection.
//!
//! This looks for job steps where the step contains indicators of template
//! expansion, i.e. anything matching `${{ }}`.
//!
//! The following steps are currently supported:
//! * `run:`, indicating template expansion into a shell script or similar
//! * `actions/github-script`, indicating template expansion into a JavaScript function
//!
//! A small amount of additional processing is done to remove template
//! expressions that an attacker can't control.

use std::ops::Deref;

use github_actions_models::{
    common::expr::LoE,
    workflow::{
        job::{Matrix, NormalJob, StepBody, Strategy},
        Job,
    },
};

use super::WorkflowAudit;
use crate::{
    expr::{BinOp, Expr, UnOp},
    finding::{Confidence, Severity},
    state::AuditState,
    utils::extract_expressions,
};

pub(crate) struct TemplateInjection {
    pub(crate) state: AuditState,
}

/// Context members that are believed to be always safe.
const SAFE_CONTEXTS: &[&str] = &[
    // The GitHub event name (i.e. trigger) is itself safe.
    "github.event_name",
    // Safe keys within the otherwise generally unsafe github.event context.
    "github.event.number",
    "github.event.merge_group.base_sha",
    "github.event.workflow_run.id",
    // Unique numbers assigned by GitHub for workflow runs
    "github.run_attempt",
    "github.run_id",
    "github.run_number",
    // Always a 40-char SHA-1 reference.
    "github.sha",
    // Like `secrets.*`: not safe to expose, but safe to interpolate.
    "github.token",
    // GitHub Actions-controlled local directory.
    "github.workspace",
    // GitHub Actions-controller runner architecture.
    "runner.arch",
    // Debug logging is (1) or is not (0) enabled on GitHub Actions runner.
    "runner.debug",
    // GitHub Actions runner operating system.
    "runner.os",
];

impl TemplateInjection {
    /// Checks whether an expression is "safe" for the purposes of template
    /// injection.
    ///
    /// In the context of template injection, a "safe" expression is one that
    /// can only ever return a literal node (i.e. bool, number, string, etc.).
    /// All branches/flows of the expression must uphold that invariant;
    /// no taint tracking is currently done.
    fn expr_is_safe(expr: &Expr) -> bool {
        match expr {
            Expr::Number(_) => true,
            Expr::String(_) => true,
            Expr::Boolean(_) => true,
            Expr::Null => true,
            // NOTE: Currently unreachable, since we churlishly consider
            // indexing expressions unsafe and `Expr::Star` only occurs
            // within indices at the moment.
            Expr::Star => unreachable!(),
            // NOTE: Some index operations may be safe, but for now
            // we consider them all unsafe.
            Expr::Index { .. } => false,
            // NOTE: Some function calls may be safe, but for now
            // we consider them all unsafe.
            Expr::Call { .. } => false,
            // We consider all context accesses unsafe. This isn't true,
            // but our audit filters the safe ones later on.
            Expr::Context(_) => false,
            Expr::BinOp { lhs, op, rhs } => {
                match op {
                    // `==` and `!=` are always safe, since they evaluate to
                    // boolean rather than to the truthy value.
                    BinOp::Eq | BinOp::Neq => true,
                    // `&&` is safe if its RHS is safe, since && cannot
                    // short-circuit.
                    BinOp::And => Self::expr_is_safe(rhs),
                    // We consider all other binops safe if both sides are safe,
                    // regardless of the actual operation type. This could be
                    // refined to check only one side with taint information.
                    // TODO: Relax this for >/>=/</<=?
                    _ => Self::expr_is_safe(lhs) && Self::expr_is_safe(rhs),
                }
            }
            Expr::UnOp { op, .. } => match op {
                // !expr always produces a boolean.
                UnOp::Not => true,
            },
        }
    }

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
            let Ok(expr) = Expr::parse(expr.as_bare()) else {
                log::warn!("couldn't parse expression: {expr}", expr = expr.as_bare());
                continue;
            };

            // Filter "safe" expressions (ones that might expand to code,
            // but not arbitrary code) by default, unless we're operating
            // in pedantic mode.
            if Self::expr_is_safe(&expr) && !self.state.pedantic {
                continue;
            }

            for context in expr.contexts() {
                if context.starts_with("secrets.") {
                    // While not ideal, secret expansion is typically not exploitable.
                    continue;
                } else if SAFE_CONTEXTS.contains(&context) {
                    continue;
                } else if context.starts_with("inputs.") {
                    // TODO: Currently low confidence because we don't check the
                    // input's type. In the future, we should index back into
                    // the workflow's triggers and exclude input expansions
                    // from innocuous types, e.g. booleans.
                    bad_expressions.push((context.into(), Severity::High, Confidence::Low));
                } else if context.starts_with("env.") {
                    // Almost never exploitable.
                    bad_expressions.push((context.into(), Severity::Low, Confidence::High));
                } else if context.starts_with("github.event.") || context == "github.ref_name" {
                    // TODO: Filter these more finely; not everything in the event
                    // context is actually attacker-controllable.
                    bad_expressions.push((context.into(), Severity::High, Confidence::High));
                } else if context.starts_with("matrix.") || context == "matrix" {
                    if let Some(Strategy { matrix, .. }) = &job.strategy {
                        let matrix_is_static = match matrix {
                            // The matrix is statically defined, but one
                            // or more keys might contain expressions.
                            Some(LoE::Literal(matrix)) => self.matrix_is_static(context, matrix),
                            // The matrix is generated by an expression, meaning
                            // that it's trivially not static.
                            Some(LoE::Expr(_)) => false,
                            // Context specifies a matrix, but there is no matrix defined.
                            // This is an invalid workflow so there's no point in flagging it.
                            None => continue,
                        };

                        if !matrix_is_static {
                            bad_expressions.push((
                                context.into(),
                                Severity::Medium,
                                Confidence::Medium,
                            ));
                        }
                    }
                    continue;
                } else {
                    // All other contexts are typically not attacker controllable,
                    // but may be in obscure cases.
                    bad_expressions.push((
                        context.into(),
                        Severity::Informational,
                        Confidence::Low,
                    ));
                }
            }
        }

        bad_expressions
    }
}

impl WorkflowAudit for TemplateInjection {
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

    fn new(state: AuditState) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self { state })
    }

    fn audit<'w>(
        &self,
        workflow: &'w crate::models::Workflow,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'w>>> {
        let mut findings = vec![];

        for job in workflow.jobs() {
            let Job::NormalJob(normal) = job.deref() else {
                continue;
            };

            for step in job.steps() {
                let (script, script_loc) = match &step.deref().body {
                    StepBody::Uses { uses, with } => {
                        if uses.starts_with("actions/github-script") {
                            match with.get("script") {
                                Some(script) => (
                                    &script.to_string(),
                                    step.location().with_keys(&["with".into(), "script".into()]),
                                ),
                                None => continue,
                            }
                        } else {
                            continue;
                        }
                    }
                    StepBody::Run { run, .. } => (run, step.location().with_keys(&["run".into()])),
                };

                for (expr, severity, confidence) in
                    self.injectable_template_expressions(script, normal)
                {
                    findings.push(
                        Self::finding()
                            .severity(severity)
                            .confidence(confidence)
                            .add_location(step.location_with_name())
                            .add_location(script_loc.clone().annotated(format!(
                                "{expr} may expand into attacker-controllable code"
                            )))
                            .build(workflow)?,
                    )
                }
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::template_injection::TemplateInjection;

    use super::Expr;

    #[test]
    fn test_expr_is_safe() {
        let cases = &[
            // Literals are always safe.
            ("true", true),
            ("false", true),
            ("1.0", true),
            ("null", true),
            ("'some string'", true),
            // negation is always safe.
            ("!true", true),
            ("!some.context", true),
            // == / != are always safe, even if their hands are not.
            ("true == true", true),
            ("'true' == true", true),
            ("some.context == true", true),
            ("contains(some.context, 'foo') != true", true),
            // || is safe if both hands are safe.
            ("true || true", true),
            ("some.context || true", false),
            ("true || some.context", false),
            // && is true if the RHS is safe.
            ("true && true", true),
            ("some.context && true", true),
            ("true && other.context", false),
            ("some.context && other.context", false),
            // Index ops and function calls are unsafe.
            ("some.context[0]", false),
            ("some.context[*]", false),
            ("someFunction()", false),
            ("fromJSON(some.context)", false),
            ("toJSON(fromJSON(some.context))", false),
            // Context accesses are unsafe.
            ("some.context", false),
            ("some.context.*.something", false),
            // More complicated cases:
            ("some.condition && '--some-arg' || ''", true),
            ("some.condition && some.context || ''", false),
            ("some.condition && '--some-arg' || some.context", false),
            (
                "(github.actor != 'github-actions[bot]' && github.actor) || 'BrewTestBot'",
                false,
            ),
        ];

        for (case, safe) in cases {
            let expr = Expr::parse(case).unwrap();
            assert_eq!(TemplateInjection::expr_is_safe(&expr), *safe, "{expr:#?}");
        }
    }
}
