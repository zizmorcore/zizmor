use github_actions_models::common;

use crate::{
    audit::{Audit, AuditError, audit_meta},
    finding::{
        Confidence, Fix, FixDisposition, Severity,
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
    fn is_unsound_fenced_expansion(&self, cond: &common::If) -> bool {
        let common::If::Expr(raw_expr) = cond else {
            // `if: true` and `if: false` are always sound.
            return false;
        };

        // The way we check for this is pretty simple: we attempt
        // to extract a fenced expression from the condition, and check
        // whether the overall string length of the condition is
        // greater than the length of the fenced expression. This indicates
        // leading or trailing content (like whitespace) that makes the
        // evaluation always true.
        let Some((expr, _)) = utils::extract_fenced_expression(raw_expr, 0) else {
            return false;
        };

        raw_expr.len() > expr.as_raw().len()
    }

    /// Attempts to create a fix for an unsound condition by replacing
    /// the block scalar style with a stripped version (| -> |-, > -> >-).
    fn attempt_fix<'a, 'doc>(
        &self,
        cond: &common::If,
        loc: &SymbolicLocation<'doc>,
        doc: &'a impl AsDocument<'a, 'doc>,
    ) -> Option<Fix<'doc>> {
        let common::If::Expr(raw_expr) = cond else {
            return None;
        };

        // The fix we apply below only works for trailing newlines.
        if !raw_expr.ends_with('\n') {
            return None;
        }

        // Get the document and feature for this condition
        let yaml_doc = doc.as_document();
        let feature =
            yamlpatch::route_to_feature_exact(&loc.route.with_key("if"), yaml_doc).ok()??;

        // Determine the current scalar style
        let style = yamlpatch::Style::from_feature(&feature, yaml_doc);

        // Only fix literal (|) and folded (>) scalar styles
        let (old_indicator, new_indicator) = match style {
            yamlpatch::Style::MultilineLiteralScalar => ("|", "|-"),
            yamlpatch::Style::MultilineFoldedScalar => (">", ">-"),
            _ => return None, // Not a style we can fix this way
        };

        // Create a patch that replaces the scalar indicator
        Some(Fix {
            title: format!(
                "replace unsound block scalar style '{old_indicator}' with sound style '{new_indicator}'"
            ),
            key: loc.key,
            disposition: FixDisposition::Safe,
            patches: vec![Patch {
                route: loc.route.with_key("if"),
                operation: Op::RewriteFragment {
                    from: subfeature::Subfeature::new(0, old_indicator),
                    to: new_indicator.into(),
                },
            }],
        })
    }

    fn process_conditions<'a, 'doc>(
        &self,
        doc: &'a impl AsDocument<'a, 'doc>,
        conditions: impl Iterator<Item = (&'doc common::If, SymbolicLocation<'doc>)>,
    ) -> Result<Vec<super::Finding<'doc>>, AuditError> {
        let mut findings = vec![];
        for (cond, loc) in conditions {
            if self.is_unsound_fenced_expansion(cond) {
                let mut finding_builder = Self::finding()
                    .severity(Severity::High)
                    .confidence(Confidence::High)
                    .add_location(loc.clone().hidden())
                    .add_location(
                        loc.with_keys(["if".into()])
                            .primary()
                            .annotated("condition always evaluates to true"),
                    );

                // Attempt to add a fix
                if let Some(fix) = self.attempt_fix(cond, &loc, doc) {
                    finding_builder = finding_builder.fix(fix);
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
        _config: &crate::config::Config,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, AuditError> {
        self.process_conditions(job, job.conditions())
    }

    async fn audit_reusable_job<'doc>(
        &self,
        job: &crate::models::workflow::ReusableWorkflowCallJob<'doc>,
        _config: &crate::config::Config,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, AuditError> {
        let conds = job.r#if.iter().map(|cond| (cond, job.location()));
        self.process_conditions(job, conds)
    }

    async fn audit_action<'doc>(
        &self,
        action: &'doc crate::models::action::Action,
        _config: &crate::config::Config,
    ) -> Result<Vec<crate::finding::Finding<'doc>>, AuditError> {
        self.process_conditions(action, action.conditions())
    }
}
