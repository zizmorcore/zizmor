use github_actions_expressions::{Expr, Origin, SpannedExpr};
use github_actions_models::common::{RepositoryUses, Uses};
use yamlpatch::{Op, Patch};

use crate::{
    Confidence, Severity,
    audit::AuditError,
    config::Config,
    finding::{
        Finding, Fix, FixDisposition, Persona,
        location::{Feature, Location, Routable},
    },
    models::{StepCommon, action::CompositeStep, workflow::Step},
    utils::{self, parse_fenced_expressions_from_input},
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
    fn obfuscated_repo_uses(&self, uses: &RepositoryUses) -> Vec<&str> {
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

    /// Creates a fix for constant-reducible expressions.
    fn create_expression_fix<'doc>(
        &self,
        expr: &SpannedExpr<'doc>,
        input: &'doc crate::audit::AuditInput,
        expr_span: std::ops::Range<usize>,
        origin: Origin<'doc>,
    ) -> Option<Fix<'doc>> {
        let evaluated = expr
            .consteval()
            .map(|evaluation| evaluation.sema().to_string())?;

        // Calculate the absolute position in the input
        let after = expr_span.start + origin.span.start;

        Some(Fix {
            title: "replace with evaluated constant".into(),
            key: input.location().key,
            disposition: FixDisposition::Safe,
            patches: vec![Patch {
                route: input.location().route,
                operation: Op::RewriteFragment {
                    from: Subfeature::new(after, origin.raw),
                    to: evaluated.into(),
                },
            }],
        })
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
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        match step.body() {
            crate::models::StepBodyCommon::Uses {
                uses: Uses::Repository(uses),
                ..
            } => {
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
            }
            crate::models::StepBodyCommon::Run { .. } => {
                if let Some(("cmd" | "cmd.exe", shell_loc)) = step
                    .shell()
                    .map(|(shell, loc)| (utils::normalize_shell(shell), loc))
                {
                    // `shell: cmd` is basically impossible to analyze: it has no formal
                    // grammar and has several line continuation mechanisms that stymie
                    // naive matching. It also hasn't been the default shell on Windows
                    // runners since 2019.
                    findings.push(
                        Self::finding()
                            .confidence(Confidence::High)
                            .severity(Severity::Low)
                            .add_location(
                                step.location_with_grip()
                                    .annotated("Windows CMD shell limits analysis"),
                            )
                            .add_location(shell_loc.primary())
                            .tip("use 'shell: pwsh' or 'shell: bash' for improved analysis")
                            .build(step)
                            .map_err(Self::err)?,
                    );
                }
            }
            _ => {}
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
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let mut findings = vec![];

        for (expr, expr_span) in parse_fenced_expressions_from_input(input) {
            let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                tracing::warn!("couldn't parse expression: {expr}", expr = expr.as_bare());
                continue;
            };

            let obfuscated_annotations = self.obfuscated_exprs(&parsed);

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

                // Check if we can create a fix for constant-reducible expressions
                if parsed.constant_reducible() {
                    // Get the main expression's origin from the first annotation
                    if let Some((_, main_origin, _)) = obfuscated_annotations.first()
                        && let Some(fix) = self.create_expression_fix(
                            &parsed,
                            input,
                            expr_span.clone(),
                            *main_origin,
                        )
                    {
                        finding_builder = finding_builder.fix(fix);
                    }
                } else {
                    // Check for constant-reducible subexpressions
                    for subexpr in parsed.constant_reducible_subexprs() {
                        if let Some(fix) = self.create_expression_fix(
                            subexpr,
                            input,
                            expr_span.clone(),
                            subexpr.origin,
                        ) {
                            finding_builder = finding_builder.fix(fix);
                            break; // Only apply one fix at a time to avoid conflicts
                        }
                    }
                }

                findings.push(finding_builder.build(input).map_err(Self::err)?);
            }
        }

        Ok(findings)
    }

    async fn audit_step<'doc>(
        &self,
        step: &Step<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step)
    }

    async fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
        _config: &Config,
    ) -> Result<Vec<Finding<'a>>, AuditError> {
        self.process_step(step)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::Audit;
    use crate::models::{AsDocument, workflow::Workflow};
    use crate::registry::input::InputKey;
    use crate::state::AuditState;

    /// Helper function to apply a fix and return the result for snapshot testing
    async fn apply_fix_for_snapshot(workflow_content: &str, _audit_name: &str) -> String {
        let key = InputKey::local("dummy".into(), "test.yml", None::<&str>);
        let workflow = Workflow::from_string(workflow_content.to_string(), key).unwrap();
        let audit_state = AuditState {
            no_online_audits: false,
            gh_client: None,
        };
        let audit = Obfuscation::new(&audit_state).unwrap();
        let findings = audit
            .audit_workflow(&workflow, &Default::default())
            .await
            .unwrap();

        assert!(!findings.is_empty(), "Expected findings but got none");

        // Find the first finding that has fixes
        let finding_with_fix = findings
            .iter()
            .find(|f| !f.fixes.is_empty())
            .expect("Expected at least one finding with a fix");

        assert!(
            !finding_with_fix.fixes.is_empty(),
            "Expected fixes but got none"
        );

        // Apply the first fix
        let fix = &finding_with_fix.fixes[0];
        let document = workflow.as_document();
        let fixed_document = fix.apply(document).unwrap();

        fixed_document.source().to_string()
    }

    #[tokio::test]
    async fn test_obfuscation_fix_uses_path_empty_components() {
        let workflow_content = r#"
name: Test Workflow
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout////@v4
"#;

        let result = apply_fix_for_snapshot(workflow_content, "obfuscation").await;
        insta::assert_snapshot!(result, @r"

        name: Test Workflow
        on: push

        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
        ");
    }

    #[tokio::test]
    async fn test_obfuscation_fix_uses_path_dot() {
        let workflow_content = r#"
name: Test Workflow
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: github/codeql-action/./init@v2
"#;

        let result = apply_fix_for_snapshot(workflow_content, "obfuscation").await;
        insta::assert_snapshot!(result, @r"

        name: Test Workflow
        on: push

        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: github/codeql-action/init@v2
        ");
    }

    #[tokio::test]
    async fn test_obfuscation_fix_uses_path_double_dot() {
        let workflow_content = r#"
name: Test Workflow
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache/save/../save@v4
"#;

        let result = apply_fix_for_snapshot(workflow_content, "obfuscation").await;
        insta::assert_snapshot!(result, @r"

        name: Test Workflow
        on: push

        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache/save@v4
        ");
    }
}
