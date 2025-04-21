use github_actions_models::common::{RepositoryUses, Uses};

use crate::{
    Confidence, Severity,
    expr::Expr,
    finding::{self, Feature, Location},
    utils::parse_expressions_from_input,
};

use super::{Audit, audit_meta};

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

    fn obfuscated_exprs(&self, expr: &Expr) -> Vec<&str> {
        let mut annotations = vec![];

        // Check for some common expression obfuscation patterns.

        // Expressions that can be constant folded should be simplified to
        // their evaluated form.
        if expr.constant_foldable() {
            annotations.push("expression can be simplified via constant folding");
        }

        annotations
    }
}

impl Audit for Obfuscation {
    fn new(_state: &crate::AuditState<'_>) -> Result<Self, super::AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_raw<'w>(
        &self,
        input: &'w super::AuditInput,
    ) -> anyhow::Result<Vec<finding::Finding<'w>>> {
        let mut findings = vec![];

        for (expr, span) in parse_expressions_from_input(input) {
            let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                tracing::warn!("couldn't parse expression: {expr}", expr = expr.as_bare());
                continue;
            };

            for annotation in self.obfuscated_exprs(&parsed) {
                findings.push(
                    Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::High)
                        .add_raw_location(Location::new(
                            input.location().annotated(annotation).primary(),
                            Feature::from_span(&span, input),
                        ))
                        .build(input)?,
                );
            }
        }

        Ok(findings)
    }

    fn audit_step<'w>(
        &self,
        step: &crate::models::Step<'w>,
    ) -> anyhow::Result<Vec<finding::Finding<'w>>> {
        let mut findings = vec![];

        if let Some(Uses::Repository(uses)) = step.uses() {
            for annotation in self.obfuscated_repo_uses(uses) {
                findings.push(
                    Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::High)
                        .add_location(
                            step.location()
                                .primary()
                                .with_keys(&["uses".into()])
                                .annotated(annotation),
                        )
                        .build(step.workflow())?,
                );
            }
        }

        Ok(findings)
    }

    fn audit_composite_step<'a>(
        &self,
        step: &crate::models::CompositeStep<'a>,
    ) -> anyhow::Result<Vec<finding::Finding<'a>>> {
        let mut findings = vec![];

        if let Some(Uses::Repository(uses)) = step.uses() {
            for annotation in self.obfuscated_repo_uses(uses) {
                findings.push(
                    Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::High)
                        .add_location(
                            step.location()
                                .primary()
                                .with_keys(&["uses".into()])
                                .annotated(annotation),
                        )
                        .build(step.action())?,
                );
            }
        }

        Ok(findings)
    }

    // TODO: Implement obfuscation checks for expressions via audit_raw.
    // See: https://github.com/woodruffw/zizmor/issues/458
}
