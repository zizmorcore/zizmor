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

use std::sync::LazyLock;

use fst::Map;
use github_actions_expressions::{BinOp, Expr, UnOp};
use github_actions_models::{
    common::{Uses, expr::LoE},
    workflow::job::Strategy,
};

use super::{Audit, AuditLoadError, audit_meta};
use crate::{
    finding::{Confidence, Finding, Persona, Severity, SymbolicLocation},
    models::{self, CompositeStep, Step, StepCommon, uses::RepositoryUsesExt as _},
    state::AuditState,
    utils::extract_expressions,
};

pub(crate) struct TemplateInjection;

audit_meta!(
    TemplateInjection,
    "template-injection",
    "code injection via template expansion"
);

static CONTEXT_CAPABILITIES_FST: LazyLock<Map<&[u8]>> = LazyLock::new(|| {
    fst::Map::new(include_bytes!(concat!(env!("OUT_DIR"), "/context-capabilities.fst")).as_slice())
        .expect("couldn't initialize context capabilities FST")
});

enum Capability {
    Arbitrary,
    Structured,
    Fixed,
}

impl Capability {
    fn from_context(context: &str) -> Option<Self> {
        match CONTEXT_CAPABILITIES_FST.get(context) {
            Some(0) => Some(Capability::Arbitrary),
            Some(1) => Some(Capability::Structured),
            Some(2) => Some(Capability::Fixed),
            Some(_) => unreachable!("unexpected context capability"),
            _ => None,
        }
    }
}

impl TemplateInjection {
    fn script_with_location<'s>(
        step: &impl StepCommon<'s>,
    ) -> Option<(String, SymbolicLocation<'s>)> {
        match step.body() {
            models::StepBodyCommon::Uses {
                uses: Uses::Repository(uses),
                with,
            } => {
                if uses.matches("actions/github-script") {
                    with.get("script").map(|script| {
                        (
                            script.to_string(),
                            step.location().with_keys(&["with".into(), "script".into()]),
                        )
                    })
                } else if uses.matches("azure/powershell") || uses.matches("azure/cli") {
                    // Both `azure/powershell` and `azure/cli` uses the same `inlineScript`
                    // option to feed arbitrary code.

                    with.get("inlineScript").map(|script| {
                        (
                            script.to_string(),
                            step.location()
                                .with_keys(&["with".into(), "inlineScript".into()]),
                        )
                    })
                } else {
                    None
                }
            }
            models::StepBodyCommon::Run { run, .. } => {
                Some((run.to_string(), step.location().with_keys(&["run".into()])))
            }
            _ => None,
        }
    }

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
            // NOTE: Currently unreachable, since these only occur
            // within Expr::Context and we handle that at the top-level.
            Expr::Star | Expr::Identifier(_) | Expr::Index(_) => unreachable!(),
            // NOTE: Some function calls may be safe, but for now
            // we consider them all unsafe.
            Expr::Call { .. } => false,
            // We consider all context accesses unsafe. This isn't true,
            // but our audit filters the safe ones later on.
            Expr::Context { .. } => false,
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

    fn injectable_template_expressions<'s>(
        &self,
        run: &str,
        step: &impl StepCommon<'s>,
    ) -> Vec<(String, Severity, Confidence, Persona)> {
        let mut bad_expressions = vec![];
        for (expr, _) in extract_expressions(run) {
            let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                tracing::warn!("couldn't parse expression: {expr}", expr = expr.as_bare());
                continue;
            };

            if Self::expr_is_safe(&parsed) {
                // Emit a pedantic finding for all expressions, since
                // all template injections are code smells, even if unexploitable.
                bad_expressions.push((
                    expr.as_raw().into(),
                    Severity::Unknown,
                    Confidence::Unknown,
                    Persona::Pedantic,
                ));
                continue;
            }

            for context in parsed.dataflow_contexts() {
                // Try and turn our context into a pattern for
                // matching against the FST.
                match context.as_pattern().as_deref() {
                    Some(context_pattern) => {
                        // Try and get the pattern's capability from our FST.
                        match Capability::from_context(context_pattern) {
                            // Fixed means no meaningful injectable structure.
                            Some(Capability::Fixed) => continue,
                            // Structured means some attacker-controllable
                            // structure, but not fully arbitrary.
                            Some(Capability::Structured) => {
                                bad_expressions.push((
                                    context.as_str().into(),
                                    Severity::Medium,
                                    Confidence::High,
                                    Persona::default(),
                                ));
                            }
                            // Arbitrary means the context's expansion is
                            // fully attacker-controllable.
                            Some(Capability::Arbitrary) => {
                                bad_expressions.push((
                                    context.as_str().into(),
                                    Severity::High,
                                    Confidence::High,
                                    Persona::default(),
                                ));
                            }
                            None => {
                                // Without a FST match, we fall back on heuristics.
                                if context.child_of("secrets") {
                                    // While not ideal, secret expansion is typically not exploitable.
                                    continue;
                                } else if context.child_of("inputs") {
                                    // TODO: Currently low confidence because we don't check the
                                    // input's type. In the future, we should index back into
                                    // the workflow's triggers and exclude input expansions
                                    // from innocuous types, e.g. booleans.
                                    bad_expressions.push((
                                        context.as_str().into(),
                                        Severity::High,
                                        Confidence::Low,
                                        Persona::default(),
                                    ));
                                } else if let Some(env) = context.pop_if("env") {
                                    let env_is_static = step.env_is_static(env);

                                    if !env_is_static {
                                        bad_expressions.push((
                                            context.as_str().into(),
                                            Severity::Low,
                                            Confidence::High,
                                            Persona::default(),
                                        ));
                                    }
                                } else if context.child_of("github") {
                                    // TODO: Filter these more finely; not everything in the event
                                    // context is actually attacker-controllable.
                                    bad_expressions.push((
                                        context.as_str().into(),
                                        Severity::High,
                                        Confidence::High,
                                        Persona::default(),
                                    ));
                                } else if context.child_of("matrix") || context == "matrix" {
                                    if let Some(Strategy { matrix, .. }) = step.strategy() {
                                        let matrix_is_static = match matrix {
                                            // The matrix is generated by an expression, meaning
                                            // that it's trivially not static.
                                            Some(LoE::Expr(_)) => false,
                                            // The matrix may expand to static values according to the context
                                            Some(inner) => models::Matrix::new(inner)
                                                .expands_to_static_values(context.as_str()),
                                            // Context specifies a matrix, but there is no matrix defined.
                                            // This is an invalid workflow so there's no point in flagging it.
                                            None => continue,
                                        };

                                        if !matrix_is_static {
                                            bad_expressions.push((
                                                context.as_str().into(),
                                                Severity::Medium,
                                                Confidence::Medium,
                                                Persona::default(),
                                            ));
                                        }
                                    }
                                    continue;
                                } else {
                                    // All other contexts are typically not attacker controllable,
                                    // but may be in obscure cases.
                                    bad_expressions.push((
                                        context.as_str().into(),
                                        Severity::Informational,
                                        Confidence::Low,
                                        Persona::default(),
                                    ));
                                }
                            }
                        }
                    }
                    None => {
                        // If we couldn't turn the context into a pattern,
                        // we almost certainly have something like
                        // `call(...).foo.bar`.
                        bad_expressions.push((
                            context.as_str().into(),
                            Severity::Informational,
                            Confidence::Low,
                            Persona::default(),
                        ));
                    }
                }
            }
        }

        bad_expressions
    }

    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        let Some((script, script_loc)) = Self::script_with_location(step) else {
            return Ok(findings);
        };

        for (expr, severity, confidence, persona) in
            self.injectable_template_expressions(&script, step)
        {
            findings.push(
                Self::finding()
                    .severity(severity)
                    .confidence(confidence)
                    .persona(persona)
                    .add_location(step.location().hidden())
                    .add_location(step.location_with_name())
                    .add_location(
                        script_loc.clone().primary().annotated(format!(
                            "{expr} may expand into attacker-controllable code"
                        )),
                    )
                    .build(step)?,
            )
        }

        Ok(findings)
    }
}

impl Audit for TemplateInjection {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_step<'doc>(&self, step: &Step<'doc>) -> anyhow::Result<Vec<Finding<'doc>>> {
        self.process_step(step)
    }

    fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
    ) -> anyhow::Result<Vec<Finding<'a>>> {
        self.process_step(step)
    }
}

#[cfg(test)]
mod tests {
    use super::{CONTEXT_CAPABILITIES_FST, Expr, TemplateInjection};

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

    #[test]
    fn test_fst_basic() {
        assert_eq!(
            CONTEXT_CAPABILITIES_FST.get("github.event.workflow_run.triggering_actor.login"),
            Some(0) // arbitrary
        );
        assert_eq!(
            CONTEXT_CAPABILITIES_FST
                .get("github.event.workflow_run.triggering_actor.organizations_url"),
            Some(1) // structured
        );
        assert_eq!(
            CONTEXT_CAPABILITIES_FST.get("github.event.type.is_enabled"),
            Some(2) // fixed
        );
    }
}
