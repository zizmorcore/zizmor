use super::{Audit, AuditLoadError, AuditState, audit_meta};
use crate::{
    audit::AuditError,
    finding::{
        Confidence, Finding, Fix, FixDisposition, Persona, Severity, location::Locatable as _,
    },
    models::workflow::NormalJob,
};

use yamlpatch::{Op, Patch};

pub(crate) struct TimeoutMinutes;

audit_meta!(TimeoutMinutes, "timeout-minutes", "missing timeout-minutes");

#[async_trait::async_trait]
impl Audit for TimeoutMinutes {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError> {
        Ok(Self)
    }

    async fn audit_normal_job<'doc>(
        &self,
        job: &NormalJob<'doc>,
        config: &crate::config::Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        if job.timeout_minutes.is_some() {
            return Ok(vec![]);
        }

        if job.steps().any(|step| step.timeout_minutes().is_none()) {
            return Ok(vec![
                Self::finding()
                    .severity(Severity::Low)
                    .confidence(Confidence::High)
                    .persona(Persona::Pedantic)
                    .add_location(
                        job.location()
                            .primary()
                            .annotated("job missing timeout-minutes"),
                    )
                    .fix(Self::create_add_timeout_fix_job(job, config))
                    .build(job)?,
            ]);
        }

        Ok(vec![])
    }
}

impl TimeoutMinutes {
    /// Creates a fix that adds timeout-minutes to a job
    fn create_add_timeout_fix_job<'doc>(
        job: &NormalJob<'doc>,
        config: &crate::config::Config,
    ) -> Fix<'doc> {
        Fix {
            title: "add timeout-minutes to the job".to_string(),
            key: job.location().key,
            disposition: FixDisposition::Unsafe,
            patches: vec![Patch {
                route: job.location().route,
                operation: Op::Add {
                    key: "timeout-minutes".to_string(),
                    value: yaml_serde::Value::Number(
                        config.timeout_minutes_config.minutes.get().into(),
                    ),
                },
            }],
        }
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
            let key = InputKey::local("fakegroup".into(), $filename, None, None);
            let workflow = Workflow::from_string($workflow_content.to_string(), key).unwrap();
            let audit_state = AuditState::default();
            let audit = <$audit_type>::new(&audit_state).unwrap();
            let findings = audit
                .audit_workflow(&workflow, &Config::default())
                .await
                .unwrap();

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
        assert!(fix.title.contains("add timeout-minutes to the job"));

        fix.apply(document).unwrap()
    }

    #[tokio::test]
    async fn test_simple_fix() {
        let workflow_content = r#"
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: simple case
        run: echo "test"
"#;

        test_workflow_audit!(
            TimeoutMinutes,
            "test_simple_fix.yml",
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
                        run: echo "test"
                    timeout-minutes: 30
                "#);
            }
        );
    }

    #[tokio::test]
    async fn test_fix_with_existing_step_timeout() {
        let workflow_content = r#"
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: step with some timeout
        timeout-minutes: 10
        run: echo "test"
      - name: step with no timeout
        run: echo "test"
"#;

        test_workflow_audit!(
            TimeoutMinutes,
            "test_fix_with_existing_step_timeout.yml",
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
                      - name: step with some timeout
                        timeout-minutes: 10
                        run: echo "test"
                      - name: step with no timeout
                        run: echo "test"
                    timeout-minutes: 30
                "#);
            }
        );
    }
}
