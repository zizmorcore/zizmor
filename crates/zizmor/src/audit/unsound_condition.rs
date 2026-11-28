use github_actions_models::common;

use crate::{
    audit::{Audit, AuditError, audit_meta},
    finding::{
        Confidence, Fix, FixDisposition, FixEdit, Severity,
        location::{Locatable as _, SymbolicLocation},
    },
    models::AsDocument,
    utils,
};
use yamlpatch::{Op, Patch};

pub(crate) struct UnsoundCondition;

audit_meta!(
    UnsoundCondition,
    "unsound-condition",
    "unsound conditional expression"
);

impl UnsoundCondition {
    /// Looks for unsound fenced expression expansions in conditions.
    ///
    /// These typically take the form of an explicit fence combined with
    /// a multiline YAML block scalar, as the two interact in a surprising way:
    /// * The explicit fence (`${{ ... }}`) means that the GitHub Actions
    ///   expression parser doesn't see any whitespace outside of the fence.
    /// * The multiline block scalar (`|` or `>`) means that the scalar
    ///   value itself often has trailing whitespace (e.g. one or more newlines).
    ///
    /// Put together, this means that a condition like this:
    /// ```yaml
    /// if: |
    ///   ${{
    ///     true
    ///       && false
    ///   }}
    /// ```
    ///
    /// Gets expanded to `false\n`, which in turn becomes truthy since
    /// all strings are truthy in GitHub Actions.
    fn unsound_fenced_expansion(cond: &common::If) -> Option<(&str, &str)> {
        let common::If::Expr(raw_expr) = cond else {
            // `if: true` and `if: false` are always sound.
            return None;
        };

        // The way we check for this is pretty simple: we attempt
        // to extract a fenced expression from the condition, and check
        // whether the overall string length of the condition is
        // greater than the length of the fenced expression. This indicates
        // leading or trailing content (like whitespace) that makes the
        // evaluation always true.
        let (expr, _) = utils::extract_fenced_expression(raw_expr, 0)?;
        (raw_expr.len() > expr.as_raw().len()).then_some((raw_expr, expr.as_raw()))
    }

    fn process_conditions<'a, 'doc>(
        &self,
        doc: &'a impl AsDocument<'a, 'doc>,
        conditions: impl Iterator<Item = (&'doc common::If, SymbolicLocation<'doc>)>,
    ) -> Result<Vec<super::Finding<'doc>>, AuditError> {
        let mut findings = vec![];
        for (cond, loc) in conditions {
            if let Some((raw, expression)) = Self::unsound_fenced_expansion(cond) {
                let mut finding_builder = Self::finding()
                    .severity(Severity::High)
                    .confidence(Confidence::High)
                    .add_location(loc.clone().hidden())
                    .add_location(
                        loc.with_keys(["if".into()])
                            .primary()
                            .annotated("condition always evaluates to true"),
                    );

                if raw.trim_end_matches('\n') == expression {
                    finding_builder = finding_builder.fix(Fix {
                        title: "strip trailing newlines from the condition".into(),
                        key: loc.key,
                        disposition: FixDisposition::Safe,
                        edit: FixEdit::Yaml(vec![Patch {
                            route: loc.route.with_key("if"),
                            operation: Op::Replace(astral_yaml_serde::Value::String(
                                expression.into(),
                            )),
                        }]),
                    });
                }

                findings.push(finding_builder.build(doc)?);
            }

            // TODO: Check for some other unsound conditions,
            // e.g. `if: ${{ foo.bar }}` where we know that `foo.bar`
            // is a string derived at runtime. GitHub Actions appears
            // to treat these as truthy even when they evaluate to `'false'`.
        }

        Ok(findings)
    }
}

#[async_trait::async_trait]
impl Audit for UnsoundCondition {
    fn new(_state: &crate::state::AuditState) -> Result<Self, super::AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_normal_job<'doc>(
        &self,
        job: &crate::models::workflow::NormalJob<'doc>,
        _group: &crate::registry::input::InputGroup,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, AuditError> {
        self.process_conditions(job, job.conditions())
    }

    async fn audit_reusable_job<'doc>(
        &self,
        job: &crate::models::workflow::ReusableWorkflowCallJob<'doc>,
        _group: &crate::registry::input::InputGroup,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, AuditError> {
        let conds = job.r#if.iter().map(|cond| (cond, job.location()));
        self.process_conditions(job, conds)
    }

    async fn audit_action<'doc>(
        &self,
        action: &'doc crate::models::action::Action,
        _group: &crate::registry::input::InputGroup,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, AuditError> {
        self.process_conditions(action, action.conditions())
    }
}
