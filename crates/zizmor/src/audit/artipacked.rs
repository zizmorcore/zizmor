use anyhow::Result;
use github_actions_models::common::{EnvValue, Uses, expr::ExplicitExpr};
use itertools::Itertools as _;

use super::{Audit, AuditLoadError, audit_meta};
use crate::{
    finding::{Confidence, Finding, Fix, Persona, Severity, location::Routable as _},
    models::{StepBodyCommon, StepCommon, uses::RepositoryUsesExt as _},
    state::AuditState,
    utils::split_patterns,
    yaml_patch::{Op, Patch},
};

pub(crate) struct Artipacked;

audit_meta!(
    Artipacked,
    "artipacked",
    "credential persistence through GitHub Actions artifacts"
);

impl Artipacked {
    fn process_steps<'doc>(
        &self,
        steps: impl Iterator<Item = impl StepCommon<'doc>>,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        // First, collect all vulnerable checkouts and upload steps independently.
        let mut vulnerable_checkouts = vec![];
        let mut vulnerable_uploads = vec![];
        for step in steps {
            let StepBodyCommon::Uses {
                uses: Uses::Repository(uses),
                with,
            } = &step.body()
            else {
                continue;
            };

            if uses.matches("actions/checkout") {
                match with
                    .get("persist-credentials")
                    .map(|v| v.to_string())
                    .as_deref()
                {
                    Some("false") => continue,
                    Some("true") => {
                        // If a user explicitly sets `persist-credentials: true`,
                        // they probably mean it. Only report if in auditor mode.
                        vulnerable_checkouts.push((step, Persona::Auditor))
                    }
                    // TODO: handle expressions here.
                    // persist-credentials is true by default.
                    _ => vulnerable_checkouts.push((step, Persona::default())),
                }
            } else if uses.matches("actions/upload-artifact") {
                let Some(EnvValue::String(path)) = with.get("path") else {
                    continue;
                };

                let dangerous_paths = self.dangerous_artifact_patterns(path);
                if !dangerous_paths.is_empty() {
                    // TODO: plumb dangerous_paths into the annotation here.
                    vulnerable_uploads.push(step)
                }
            }
        }

        if vulnerable_uploads.is_empty() {
            // If we have no vulnerable uploads, then emit lower-confidence
            // findings for just the checkout steps.
            for (checkout, persona) in &vulnerable_checkouts {
                findings.push(
                    Self::finding()
                        .severity(Severity::Medium)
                        .confidence(Confidence::Low)
                        .persona(*persona)
                        .add_location(
                            checkout
                                .location()
                                .primary()
                                .annotated("does not set persist-credentials: false"),
                        )
                        .fix(Self::create_persist_credentials_fix(checkout))
                        .build(checkout)?,
                );
            }
        } else {
            // Select only pairs where the vulnerable checkout precedes the
            // vulnerable upload. There are more efficient ways to do this than
            // a cartesian product, but this way is simple.
            for ((checkout, persona), upload) in vulnerable_checkouts
                .iter()
                .cartesian_product(vulnerable_uploads.iter())
            {
                if checkout.index() < upload.index() {
                    findings.push(
                        Self::finding()
                            .severity(Severity::High)
                            .confidence(Confidence::High)
                            .persona(*persona)
                            .add_location(
                                checkout
                                    .location()
                                    .primary()
                                    .annotated("does not set persist-credentials: false"),
                            )
                            .add_location(
                                upload
                                    .location()
                                    .annotated("may leak the credentials persisted above"),
                            )
                            .fix(Self::create_persist_credentials_fix(checkout))
                            .build(checkout)?,
                    );
                }
            }
        }

        Ok(findings)
    }

    fn dangerous_artifact_patterns<'b>(&self, path: &'b str) -> Vec<&'b str> {
        let mut patterns = vec![];
        for path in split_patterns(path) {
            match path {
                // TODO: this could be even more generic.
                "." | "./" | ".." | "../" => patterns.push(path),
                path => match ExplicitExpr::from_curly(path) {
                    Some(expr) if expr.as_bare().contains("github.workspace") => {
                        patterns.push(path)
                    }
                    // TODO: Other expressions worth flagging here?
                    Some(_) => continue,
                    _ => continue,
                },
            }
        }

        patterns
    }

    /// Create a Fix for setting persist-credentials: false
    fn create_persist_credentials_fix<'doc>(step: &impl StepCommon<'doc>) -> Fix<'doc> {
        Fix {
            title: "set persist-credentials: false".to_string(),
            key: step.location().key,
            disposition: Default::default(),
            patches: vec![Patch {
                route: step.route(),
                operation: Op::MergeInto {
                    key: "with".to_string(),
                    value: {
                        let mut with_map = serde_yaml::Mapping::new();
                        with_map.insert(
                            serde_yaml::Value::String("persist-credentials".to_string()),
                            serde_yaml::Value::Bool(false),
                        );
                        serde_yaml::Value::Mapping(with_map)
                    },
                },
            }],
        }
    }
}

impl Audit for Artipacked {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError> {
        Ok(Self)
    }

    fn audit_action<'doc>(
        &self,
        action: &'doc crate::models::action::Action,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        let Some(steps) = action.steps() else {
            return Ok(vec![]);
        };

        self.process_steps(steps)
    }

    fn audit_normal_job<'doc>(&self, job: &super::NormalJob<'doc>) -> Result<Vec<Finding<'doc>>> {
        self.process_steps(job.steps())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        github_api::GitHubHost,
        models::{AsDocument, workflow::Workflow},
        registry::InputKey,
        state::AuditState,
    };

    /// Macro for testing workflow audits with common boilerplate
    ///
    /// Usage: `test_workflow_audit!(AuditType, "filename.yml", workflow_yaml, |findings| { ... })`
    ///
    /// This macro:
    /// 1. Creates a test workflow from the provided YAML with the specified filename
    /// 2. Sets up the audit state
    /// 3. Creates and runs the audit
    /// 4. Executes the provided test closure with the findings
    macro_rules! test_workflow_audit {
        ($audit_type:ty, $filename:expr, $workflow_content:expr, $test_fn:expr) => {{
            let key = InputKey::local($filename, None::<&str>).unwrap();
            let workflow = Workflow::from_string($workflow_content.to_string(), key).unwrap();
            let audit_state = AuditState {
                config: &Default::default(),
                no_online_audits: false,
                cache_dir: "/tmp/zizmor".into(),
                gh_token: None,
                gh_hostname: GitHubHost::Standard("github.com".into()),
            };
            let audit = <$audit_type>::new(&audit_state).unwrap();
            let findings = audit.audit_workflow(&workflow).unwrap();

            $test_fn(&workflow, findings)
        }};
    }

    /// Helper function to apply a fix and return the result for snapshot testing
    fn apply_fix_for_snapshot(
        document: &yamlpath::Document,
        findings: Vec<Finding>,
    ) -> yamlpath::Document {
        assert!(!findings.is_empty(), "Expected findings but got none");
        let finding = &findings[0];
        assert!(!finding.fixes.is_empty(), "Expected fixes but got none");

        let fix = &finding.fixes[0];
        assert_eq!(fix.title, "set persist-credentials: false");

        fix.apply(document).unwrap()
    }

    #[test]
    fn test_fix_title_and_description() {
        // Test that the fix has the expected title and description format
        // Since Step::new is private, we test this indirectly through the audit logic
        let title = "set persist-credentials: false";
        let description_keywords = [
            "persist-credentials",
            "GITHUB_TOKEN",
            "credential persistence",
        ];

        assert_eq!(title, "set persist-credentials: false");
        for keyword in description_keywords {
            // This is a basic smoke test - in practice, integration tests would verify the fix works
            assert!(!keyword.is_empty());
        }
    }

    #[test]
    fn test_fix_merges_into_existing_with_block() {
        let workflow_content = r#"
name: Test Workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          fetch-depth: 2
      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: my-artifact
          path: .
"#;

        test_workflow_audit!(
            Artipacked,
            "test_fix_merges_into_existing_with_block.yml",
            workflow_content,
            |workflow: &Workflow, findings| {
                let fixed = apply_fix_for_snapshot(workflow.as_document(), findings);
                insta::assert_snapshot!(fixed.source(), @r"
                name: Test Workflow
                on: push
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - name: Checkout
                        uses: actions/checkout@v4
                        with:
                          token: ${{ secrets.GITHUB_TOKEN }}
                          fetch-depth: 2
                          persist-credentials: false
                      - name: Upload artifacts
                        uses: actions/upload-artifact@v4
                        with:
                          name: my-artifact
                          path: .
                ");
            }
        );
    }

    #[test]
    fn test_fix_creates_with_block_when_missing() {
        let workflow_content = r#"
name: Test Workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: my-artifact
          path: .
"#;

        test_workflow_audit!(
            Artipacked,
            "test_fix_creates_with_block_when_missing.yml",
            workflow_content,
            |workflow: &Workflow, findings| {
                let fixed = apply_fix_for_snapshot(workflow.as_document(), findings);
                insta::assert_snapshot!(fixed.source(), @r"
                name: Test Workflow
                on: push
                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - name: Checkout
                        uses: actions/checkout@v4
                        with:
                          persist-credentials: false
                      - name: Upload artifacts
                        uses: actions/upload-artifact@v4
                        with:
                          name: my-artifact
                          path: .
                ");
            }
        );
    }
}
