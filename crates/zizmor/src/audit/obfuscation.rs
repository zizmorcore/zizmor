use github_actions_expressions::{Expr, Origin, SpannedExpr};
use github_actions_models::common::{RepositoryUses, Uses};

use crate::{
    Confidence, Severity,
    finding::{
        Finding, Persona,
        location::{Feature, Location, Subfeature},
    },
    models::{StepCommon, action::CompositeStep, workflow::Step},
    utils::parse_expressions_from_input,
};

use super::{Audit, AuditInput, AuditLoadError, AuditState, audit_meta};

pub(crate) struct Obfuscation;

audit_meta!(
    Obfuscation,
    "obfuscation",
    "obfuscated usage of GitHub Actions features"
);

impl Obfuscation {
    fn obfuscated_repo_uses(&self, uses: &RepositoryUses) -> Vec<&str> {
        let mut annotations = vec![];

        // Users can put all kinds of nonsense in `uses:` clauses, which
        // GitHub happily interprets but otherwise gums up pattern matching
        // in audits like unpinned-uses, forbidden-uses, and cache-poisoning.
        // We check for some of these forms of nonsense here and report them.
        if let Some(subpath) = uses.subpath.as_deref() {
            for component in subpath.split('/') {
                match component {
                    // . and .. are valid in uses subpaths, but are impossible to
                    // analyze or match with full generality.
                    "." => {
                        annotations.push("actions reference contains '.'");
                    }
                    ".." => {
                        annotations.push("actions reference contains '..'");
                    }
                    // `uses: foo/bar////baz` and similar is valid, but
                    // only serves to mess up pattern matching.
                    // This also catches `uses: foo/bar/@v1`.
                    _ if component.is_empty() => {
                        annotations.push("actions reference contains empty component");
                    }
                    _ => {}
                }
            }
        }

        annotations
    }

    fn obfuscated_exprs<'src>(
        &self,
        expr: &SpannedExpr<'src>,
    ) -> Vec<(&str, Origin<'src>, Persona)> {
        let mut annotations = vec![];

        // Check for some common expression obfuscation patterns.

        // Expressions that can be constant reduced should be simplified to
        // their evaluated form.
        if expr.constant_reducible() {
            annotations.push((
                "can be replaced by its static evaluation",
                expr.origin,
                Persona::Regular,
            ));
        } else {
            // Even if an expression is not itself constant reducible,
            // it might contains reducible sub-expressions.
            for subexpr in expr.constant_reducible_subexprs() {
                annotations.push((
                    "can be reduced to a constant",
                    subexpr.origin,
                    Persona::Regular,
                ));
            }
        }

        for index_expr in expr.computed_indices() {
            annotations.push((
                "index expression is computed",
                index_expr.origin,
                Persona::Pedantic,
            ));
        }

        // TODO: calculate call breadth/depth and flag above thresholds.

        annotations
    }

    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        if let Some(Uses::Repository(uses)) = step.uses() {
            for annotation in self.obfuscated_repo_uses(uses) {
                findings.push(
                    Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::Low)
                        .add_location(
                            step.location()
                                .primary()
                                .with_keys(&["uses".into()])
                                .annotated(annotation),
                        )
                        .build(step)?,
                );
            }
        }

        Ok(findings)
    }
}

impl Audit for Obfuscation {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_raw<'doc>(&self, input: &'doc AuditInput) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        for (expr, expr_span) in parse_expressions_from_input(input) {
            let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                tracing::warn!("couldn't parse expression: {expr}", expr = expr.as_bare());
                continue;
            };

            for (annotation, origin, persona) in self.obfuscated_exprs(&parsed) {
                let after = expr_span.start + origin.span.start;
                let subfeature = Subfeature::new(after, origin.raw);

                findings.push(
                    Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::Low)
                        .persona(persona)
                        .add_raw_location(Location::new(
                            input.location().annotated(annotation).primary(),
                            Feature::from_subfeature(&subfeature, input),
                        ))
                        .build(input)?,
                );
            }
        }

        Ok(findings)
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
