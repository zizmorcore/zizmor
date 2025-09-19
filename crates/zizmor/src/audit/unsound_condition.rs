use github_actions_models::common;

use crate::{
    audit::{Audit, audit_meta},
    finding::{
        Confidence, Fix, FixDisposition, Severity,
        location::{Locatable as _, SymbolicLocation},
    },
    models::{AsDocument, workflow::JobExt},
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
    ) -> anyhow::Result<Vec<super::Finding<'doc>>> {
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

impl Audit for UnsoundCondition {
    fn new(_state: &crate::state::AuditState) -> Result<Self, super::AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_normal_job<'doc>(
        &self,
        job: &crate::models::workflow::NormalJob<'doc>,
        _config: &crate::config::Config,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'doc>>> {
        self.process_conditions(job.parent(), job.conditions())
    }

    fn audit_reusable_job<'doc>(
        &self,
        job: &crate::models::workflow::ReusableWorkflowCallJob<'doc>,
        _config: &crate::config::Config,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'doc>>> {
        let conds = job.r#if.iter().map(|cond| (cond, job.location()));
        self.process_conditions(job.parent(), conds)
    }

    fn audit_action<'doc>(
        &self,
        action: &'doc crate::models::action::Action,
        _config: &crate::config::Config,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'doc>>> {
        self.process_conditions(action, action.conditions())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config,
        models::{AsDocument, workflow::Workflow},
        registry::input::InputKey,
        state::AuditState,
    };

    /// Macro for testing workflow audits with common boilerplate
    macro_rules! test_workflow_audit {
        ($audit_type:ty, $filename:expr, $workflow_content:expr, $test_fn:expr) => {{
            let key = InputKey::local("fakegroup".into(), $filename, None::<&str>).unwrap();
            let workflow = Workflow::from_string($workflow_content.to_string(), key).unwrap();
            let audit_state = AuditState::default();
            let audit = <$audit_type>::new(&audit_state).unwrap();
            let findings = audit.audit_workflow(&workflow, &Config::default()).unwrap();

            $test_fn(&workflow, findings)
        }};
    }

    /// Helper function to apply a fix and return the result for snapshot testing
    fn apply_fix_for_snapshot(
        document: &yamlpath::Document,
        findings: Vec<crate::finding::Finding>,
    ) -> yamlpath::Document {
        assert!(!findings.is_empty(), "Expected findings but got none");
        let finding = &findings[0];
        assert!(!finding.fixes.is_empty(), "Expected fixes but got none");

        let fix = &finding.fixes[0];
        assert!(fix.title.contains("replace unsound block scalar style"));

        fix.apply(document).unwrap()
    }

    #[test]
    fn test_simple_literal_block_fix() {
        let workflow_content = r#"
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: simple case
        if: |
          ${{ github.event_name == 'push' }}
        run: echo "test"
"#;

        test_workflow_audit!(
            UnsoundCondition,
            "test_simple_literal_block_fix.yml",
            workflow_content,
            |workflow: &Workflow, findings: Vec<crate::finding::Finding>| {
                assert_eq!(findings.len(), 1);

                let fixed_document = apply_fix_for_snapshot(workflow.as_document(), findings);
                insta::assert_snapshot!(fixed_document.source(), @r#"
                name: Test
                on: push
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - name: simple case
                        if: |-
                          ${{ github.event_name == 'push' }}
                        run: echo "test"
                "#);
            }
        );
    }

    #[test]
    fn test_folded_block_fix() {
        let workflow_content = r#"
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: folded case
        if: >
          ${{ github.actor == 'dependabot[bot]' }}
        run: echo "test"
"#;

        test_workflow_audit!(
            UnsoundCondition,
            "test_folded_block_fix.yml",
            workflow_content,
            |workflow: &Workflow, findings: Vec<crate::finding::Finding>| {
                assert_eq!(findings.len(), 1);

                let fixed_document = apply_fix_for_snapshot(workflow.as_document(), findings);
                insta::assert_snapshot!(fixed_document.source(), @r#"
                name: Test
                on: push
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - name: folded case
                        if: >-
                          ${{ github.actor == 'dependabot[bot]' }}
                        run: echo "test"
                "#);
            }
        );
    }

    #[test]
    fn test_multiline_expression_fix() {
        let workflow_content = r#"
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: multiline case
        if: |
          ${{ github.event_name == 'push'
            && github.ref == 'refs/heads/main' }}
        run: echo "test"
"#;

        test_workflow_audit!(
            UnsoundCondition,
            "test_multiline_expression_fix.yml",
            workflow_content,
            |workflow: &Workflow, findings: Vec<crate::finding::Finding>| {
                assert_eq!(findings.len(), 1);

                let fixed_document = apply_fix_for_snapshot(workflow.as_document(), findings);
                insta::assert_snapshot!(fixed_document.source(), @r#"
                name: Test
                on: push
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - name: multiline case
                        if: |-
                          ${{ github.event_name == 'push'
                            && github.ref == 'refs/heads/main' }}
                        run: echo "test"
                "#);
            }
        );
    }

    #[test]
    fn test_complex_multiline_fix() {
        let workflow_content = r#"
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: complex case
        if: |
          ${{
            github.event_name == 'push' &&
            (github.ref == 'refs/heads/main' ||
             startsWith(github.ref, 'refs/heads/release/'))
          }}
        run: echo "test"
"#;

        test_workflow_audit!(
            UnsoundCondition,
            "test_complex_multiline_fix.yml",
            workflow_content,
            |workflow: &Workflow, findings: Vec<crate::finding::Finding>| {
                assert_eq!(findings.len(), 1);

                let fixed_document = apply_fix_for_snapshot(workflow.as_document(), findings);
                insta::assert_snapshot!(fixed_document.source(), @r#"
                name: Test
                on: push
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - name: complex case
                        if: |-
                          ${{
                            github.event_name == 'push' &&
                            (github.ref == 'refs/heads/main' ||
                             startsWith(github.ref, 'refs/heads/release/'))
                          }}
                        run: echo "test"
                "#);
            }
        );
    }

    #[test]
    fn test_reusable_job_fix() {
        let workflow_content = r#"
name: Test
on: push
jobs:
  reusable-job:
    if: |
      ${{ github.event_name == 'pull_request' }}
    uses: ./.github/workflows/reusable.yml
"#;

        test_workflow_audit!(
            UnsoundCondition,
            "test_reusable_job_fix.yml",
            workflow_content,
            |workflow: &Workflow, findings: Vec<crate::finding::Finding>| {
                assert_eq!(findings.len(), 1);

                let fixed_document = apply_fix_for_snapshot(workflow.as_document(), findings);
                insta::assert_snapshot!(fixed_document.source(), @r#"
                name: Test
                on: push
                jobs:
                  reusable-job:
                    if: |-
                      ${{ github.event_name == 'pull_request' }}
                    uses: ./.github/workflows/reusable.yml
                "#);
            }
        );
    }

    #[test]
    fn test_multiple_fixes_together() {
        let workflow_content = r#"
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: literal block
        if: |
          ${{ github.event_name == 'push' }}
        run: echo "test"

      - name: folded block
        if: >
          ${{ github.actor == 'dependabot[bot]' }}
        run: echo "test"

      - name: multiline expression
        if: |
          ${{ github.event_name == 'push'
            && github.ref == 'refs/heads/main' }}
        run: echo "test"
"#;

        test_workflow_audit!(
            UnsoundCondition,
            "test_multiple_fixes_together.yml",
            workflow_content,
            |workflow: &Workflow, findings: Vec<crate::finding::Finding>| {
                assert_eq!(findings.len(), 3);

                // Apply all fixes in sequence
                let mut document = workflow.as_document().clone();
                for finding in &findings {
                    for fix in &finding.fixes {
                        if let Ok(new_document) = fix.apply(&document) {
                            document = new_document;
                        }
                    }
                }

                insta::assert_snapshot!(document.source(), @r#"
                name: Test
                on: push
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - name: literal block
                        if: |-
                          ${{ github.event_name == 'push' }}
                        run: echo "test"

                      - name: folded block
                        if: >-
                          ${{ github.actor == 'dependabot[bot]' }}
                        run: echo "test"

                      - name: multiline expression
                        if: |-
                          ${{ github.event_name == 'push'
                            && github.ref == 'refs/heads/main' }}
                        run: echo "test"
                "#);
            }
        );
    }

    #[test]
    fn test_no_fix_needed_cases() {
        let workflow_content = r#"
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      # These should not trigger any findings
      - name: already plain
        if: ${{ github.event_name == 'push' }}
        run: echo "test"

      - name: no fence
        if: |
          github.event_name == 'push'
        run: echo "test"

      - name: already stripped literal
        if: |-
          ${{ github.event_name == 'push' }}
        run: echo "test"

      - name: already stripped folded
        if: >-
          ${{ github.event_name == 'push' }}
        run: echo "test"
"#;

        test_workflow_audit!(
            UnsoundCondition,
            "test_no_fix_needed_cases.yml",
            workflow_content,
            |_workflow: &Workflow, findings: Vec<crate::finding::Finding>| {
                // No unsound conditions should be found
                assert_eq!(findings.len(), 0);
            }
        );
    }
}
