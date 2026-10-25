use github_actions_expressions::{Evaluation, Expr, Origin, SpannedExpr};
use github_actions_models::common::{RepositoryUses, Uses, expr::LoE};
use yamlpatch::{Op, Patch};

use crate::{
    Confidence, Severity,
    audit::AuditError,
    finding::{
        Finding, Fix, FixDisposition, Persona,
        location::{Feature, Location, Routable as _},
    },
    models::{StepCommon, action::CompositeStep, workflow::Step},
    utils::parse_fenced_expressions_from_routable,
};
use subfeature::Subfeature;

use super::{Audit, AuditInput, AuditLoadError, AuditState, audit_meta};

pub(crate) struct Obfuscation;

audit_meta!(
    Obfuscation,
    "obfuscation",
    "obfuscated usage of GitHub Actions features"
);

impl Obfuscation {
    fn obfuscated_repo_uses(&self, uses: &RepositoryUses) -> Vec<&'static str> {
        let mut annotations = vec![];

        // Users can put all kinds of nonsense in `uses:` clauses, which
        // GitHub happily interprets but otherwise gums up pattern matching
        // in audits like unpinned-uses, forbidden-uses, and cache-poisoning.
        // We check for some of these forms of nonsense here and report them.
        if let Some(subpath) = uses.subpath() {
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

    /// Normalizes a uses path by removing unnecessary components like empty slashes, `.`, and `..`.
    fn normalize_uses_path(&self, uses: &RepositoryUses) -> Option<String> {
        let subpath = uses.subpath()?;

        let mut components = Vec::new();
        for component in subpath.split('/') {
            match component {
                // Skip empty components and current directory references
                "" | "." => continue,
                // Handle parent directory references
                ".." => {
                    // There's no meaningful normalization if we have no concrete
                    // component to go back from.
                    if components.is_empty() {
                        return None;
                    }
                    components.pop();
                }
                // Keep regular components
                other => components.push(other),
            }
        }

        // If all components were removed, the subpath should be empty
        if components.is_empty() {
            Some(format!(
                "{}/{}@{}",
                uses.owner(),
                uses.repo(),
                uses.git_ref()
            ))
        } else {
            Some(format!(
                "{}/{}/{}@{}",
                uses.owner(),
                uses.repo(),
                components.join("/"),
                uses.git_ref()
            ))
        }
    }

    /// Creates a fix for obfuscated uses paths.
    fn create_uses_fix<'doc>(
        &self,
        uses: &RepositoryUses,
        step: &impl StepCommon<'doc>,
    ) -> Option<Fix<'doc>> {
        let normalized_uses = self.normalize_uses_path(uses)?;

        Some(Fix {
            title: "normalize uses path".into(),
            key: step.location().key,
            disposition: FixDisposition::Safe,
            patches: vec![Patch {
                route: step.route().with_key("uses"),
                operation: Op::Replace(normalized_uses.into()),
            }],
        })
    }

    /// Renders template text when replacing an expression (or subexpression).
    /// Returns `None` if there isn't a sound replacement.
    fn expression_replacement(evaluation: &Evaluation, is_subexpr: bool) -> Option<String> {
        match (evaluation, is_subexpr) {
            // Aggregates have no expression literal syntax. Stringifying them
            // as `Array` or `Object` would change their meaning (see #1177).
            (Evaluation::Array(_) | Evaluation::Object(_), _) => None,
            // Bug #2464: expanding these strings could introduce an unpaired
            // expression fence or turn verbatim text into an active expression.
            (Evaluation::String(value), _) if value.contains("${{") => None,
            // When we're in a subexpression, we can't use EvaluationSema's form
            // since it assumes expansion *outside* of an expression.
            (Evaluation::String(value), true) => Some(format!("'{}'", value.replace('\'', "''"))),
            (Evaluation::Null, true) => Some("null".into()),
            (Evaluation::Number(value), true) if value.is_finite() => Some(value.to_string()),
            _ => Some(evaluation.sema().to_string()),
        }
    }

    /// Creates a fix from a rendered replacement.
    fn create_expression_fix<'doc>(
        &self,
        replacement: String,
        input: &'doc crate::audit::AuditInput,
        after: usize,
        raw: &'doc str,
    ) -> Fix<'doc> {
        Fix {
            title: "replace with evaluated constant".into(),
            key: input.location().key,
            disposition: FixDisposition::Safe,
            patches: vec![Patch {
                route: input.location().route,
                operation: Op::RewriteFragment {
                    from: Subfeature::new(after, raw),
                    to: replacement.into(),
                },
            }],
        }
    }

    fn obfuscated_exprs<'doc>(
        &self,
        expr: &SpannedExpr<'doc>,
        input: &'doc AuditInput,
        after: usize,
        raw: &'doc str,
    ) -> (Vec<(&'static str, Origin<'doc>, Persona)>, Vec<Fix<'doc>>) {
        let mut annotations = vec![];
        let mut fixes = vec![];

        // Check for some common expression obfuscation patterns.

        // Expressions that can be constant reduced should be simplified to
        // their evaluated form.
        if let Some(replacement) = expr
            .consteval()
            .and_then(|evaluation| Self::expression_replacement(&evaluation, false))
        {
            annotations.push((
                "can be replaced by its static evaluation",
                expr.origin,
                Persona::Regular,
            ));
            // Replace the fencing too: `${{ 'foo' }}` simplifies to `foo`.
            fixes.push(self.create_expression_fix(replacement, input, after, raw));
        } else {
            // Check for subexpressions that can be simplified.
            for (subexpr, evaluation) in expr.consteval_subexprs() {
                let Some(replacement) = Self::expression_replacement(&evaluation, true) else {
                    continue;
                };
                annotations.push((
                    "can be reduced to a constant",
                    subexpr.origin,
                    Persona::Regular,
                ));
                fixes.push(self.create_expression_fix(
                    replacement,
                    input,
                    after + subexpr.origin.span.start,
                    subexpr.origin.raw,
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

        // Subexpressions are collected in source order. Apply fixes from the
        // end so that replacements preserve the offsets of earlier fixes.
        fixes.reverse();

        (annotations, fixes)
    }

    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        if let Some(crate::models::StepBodyCommon::Uses {
            uses: Uses::Repository(uses),
            with,
        }) = step.body()
        {
            let obfuscated_annotations = self.obfuscated_repo_uses(uses);
            if !obfuscated_annotations.is_empty() {
                let mut finding_builder = Self::finding()
                    .confidence(Confidence::High)
                    .severity(Severity::Low);

                // Add all annotations as locations
                for annotation in &obfuscated_annotations {
                    finding_builder = finding_builder.add_location(
                        step.location()
                            .primary()
                            .with_keys(["uses".into()])
                            .annotated(*annotation),
                    );
                }

                // Try to create a fix for the obfuscated uses path
                if let Some(fix) = self.create_uses_fix(uses, step) {
                    finding_builder = finding_builder.fix(fix);
                }

                findings.push(finding_builder.build(step).map_err(Self::err)?);
            }

            if let LoE::Expr(_) = with {
                findings.push(
                    Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::Informational)
                        .persona(Persona::Regular)
                        .add_location(
                            step.location()
                                .with_keys(["uses".into()])
                                .annotated("this action"),
                        )
                        .add_location(
                            step.location()
                                .primary()
                                .with_keys(["with".into()])
                                .annotated("use of an expression for `with:` prevents analysis"),
                        )
                        .build(step)
                        .map_err(Self::err)?,
                );
            }
        }

        Ok(findings)
    }
}

#[async_trait::async_trait]
impl Audit for Obfuscation {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_raw<'doc>(
        &self,
        input: &'doc AuditInput,
        _group: &crate::registry::input::InputGroup,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        if !input.supports_gha_template_syntax() {
            return Ok(findings);
        }

        for (expr, expr_span) in parse_fenced_expressions_from_routable(input) {
            let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                tracing::warn!("couldn't parse expression: {expr}", expr = expr.as_bare());
                continue;
            };

            let (obfuscated_annotations, fixes) =
                self.obfuscated_exprs(&parsed, input, expr_span.start, expr.as_raw());

            if !obfuscated_annotations.is_empty() {
                let mut finding_builder = Self::finding()
                    .confidence(Confidence::High)
                    .severity(Severity::Low);

                // Add all annotations as locations
                for (annotation, origin, persona) in &obfuscated_annotations {
                    let after = expr_span.start + origin.span.start;
                    let subfeature = Subfeature::new(after, origin.raw);

                    finding_builder =
                        finding_builder
                            .persona(*persona)
                            .add_raw_location(Location::new(
                                input.location().annotated(*annotation).primary(),
                                Feature::from_subfeature(&subfeature, input),
                            ));
                }

                for fix in fixes {
                    finding_builder = finding_builder.fix(fix);
                }

                findings.push(finding_builder.build(input).map_err(Self::err)?);
            }
        }

        Ok(findings)
    }

    async fn audit_step<'doc>(
        &self,
        step: &Step<'doc>,
        _group: &crate::registry::input::InputGroup,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step)
    }

    async fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
        _group: &crate::registry::input::InputGroup,
    ) -> Result<Vec<Finding<'a>>, AuditError> {
        self.process_step(step)
    }
}
