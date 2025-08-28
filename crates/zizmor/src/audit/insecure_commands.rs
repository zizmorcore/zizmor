use std::ops::Deref;

use anyhow::Result;
use github_actions_models::action;
use github_actions_models::common::Env;
use github_actions_models::common::expr::LoE;
use github_actions_models::workflow::job::StepBody;
use yamlpatch::{Op, Patch};

use super::{AuditLoadError, Job, audit_meta};
use crate::audit::Audit;
use crate::config::Config;
use crate::finding::location::Locatable as _;
use crate::finding::{
    Confidence, Finding, Fix, FixDisposition, Persona, Severity, location::SymbolicLocation,
};
use crate::models::{AsDocument, workflow::Steps, workflow::Workflow};
use crate::state::AuditState;

pub(crate) struct InsecureCommands;

audit_meta!(
    InsecureCommands,
    "insecure-commands",
    "execution of insecure workflow commands is enabled"
);

impl InsecureCommands {
    /// Creates a fix that removes the ACTIONS_ALLOW_UNSECURE_COMMANDS environment variable.
    fn create_fix<'doc>(&self, location: SymbolicLocation<'doc>) -> Fix<'doc> {
        Fix {
            title: "remove ACTIONS_ALLOW_UNSECURE_COMMANDS environment variable".into(),
            key: location.key,
            disposition: FixDisposition::default(),
            patches: vec![Patch {
                route: location
                    .route
                    .with_keys(["env".into(), "ACTIONS_ALLOW_UNSECURE_COMMANDS".into()]),
                operation: Op::Remove,
            }],
        }
    }

    fn insecure_commands_maybe_present<'a, 'doc>(
        &self,
        doc: &'a impl AsDocument<'a, 'doc>,
        location: SymbolicLocation<'doc>,
    ) -> Result<Finding<'doc>> {
        Self::finding()
            .confidence(Confidence::Low)
            .severity(Severity::High)
            .persona(Persona::Auditor)
            .add_location(
                location.primary().with_keys(["env".into()]).annotated(
                    "non-static environment may contain ACTIONS_ALLOW_UNSECURE_COMMANDS",
                ),
            )
            .build(doc)
    }

    fn insecure_commands_allowed<'s, 'doc>(
        &self,
        doc: &'s impl AsDocument<'s, 'doc>,
        location: SymbolicLocation<'doc>,
    ) -> Result<Finding<'doc>> {
        let fix = self.create_fix(location.clone());

        Self::finding()
            .confidence(Confidence::High)
            .severity(Severity::High)
            .add_location(
                location
                    .primary()
                    .with_keys(["env".into()])
                    .annotated("insecure commands enabled here"),
            )
            .fix(fix)
            .build(doc)
    }

    fn has_insecure_commands_enabled(&self, env: &Env) -> bool {
        match env.get("ACTIONS_ALLOW_UNSECURE_COMMANDS") {
            Some(value) => value.csharp_trueish(),
            None => false,
        }
    }

    fn audit_steps<'doc>(
        &self,
        workflow: &'doc Workflow,
        steps: Steps<'doc>,
    ) -> Result<Vec<Finding<'doc>>> {
        steps
            .into_iter()
            .filter_map(|step| {
                let StepBody::Run {
                    run: _,
                    working_directory: _,
                    shell: _,
                } = &step.deref().body
                else {
                    return None;
                };

                match &step.env {
                    // The entire environment block is an expression, which we
                    // can't follow (for now). Emit an auditor-only finding.
                    LoE::Expr(_) => {
                        Some(self.insecure_commands_maybe_present(workflow, step.location()))
                    }
                    LoE::Literal(env) => self
                        .has_insecure_commands_enabled(env)
                        .then(|| self.insecure_commands_allowed(workflow, step.location())),
                }
            })
            .collect()
    }
}

impl Audit for InsecureCommands {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_workflow<'doc>(
        &self,
        workflow: &'doc Workflow,
        _config: &Config,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut results = vec![];

        match &workflow.env {
            LoE::Expr(_) => {
                results.push(self.insecure_commands_maybe_present(workflow, workflow.location())?)
            }
            LoE::Literal(env) => {
                if self.has_insecure_commands_enabled(env) {
                    results.push(self.insecure_commands_allowed(workflow, workflow.location())?)
                }
            }
        }

        for job in workflow.jobs() {
            if let Job::NormalJob(normal) = job {
                match &normal.env {
                    LoE::Expr(_) => results
                        .push(self.insecure_commands_maybe_present(workflow, normal.location())?),
                    LoE::Literal(env) => {
                        if self.has_insecure_commands_enabled(env) {
                            results
                                .push(self.insecure_commands_allowed(workflow, normal.location())?);
                        }
                    }
                }

                results.extend(self.audit_steps(workflow, normal.steps())?)
            }
        }

        Ok(results)
    }

    fn audit_composite_step<'doc>(
        &self,
        step: &super::CompositeStep<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        let action::StepBody::Run { .. } = &step.body else {
            return Ok(findings);
        };

        match &step.env {
            LoE::Expr(_) => {
                findings.push(self.insecure_commands_maybe_present(step.action(), step.location())?)
            }
            LoE::Literal(env) => {
                if self.has_insecure_commands_enabled(env) {
                    findings.push(self.insecure_commands_allowed(step.action(), step.location())?);
                }
            }
        }

        Ok(findings)
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

    #[test]
    fn test_insecure_commands_fix_generation() {
        let workflow_content = r#"
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    env:
      ACTIONS_ALLOW_UNSECURE_COMMANDS: true
      OTHER_VAR: keep-me
    steps:
      - run: echo "test"
"#;

        test_workflow_audit!(
            InsecureCommands,
            "test_fix.yml",
            workflow_content,
            |_workflow: &Workflow, findings: Vec<Finding>| {
                assert_eq!(findings.len(), 1);
                let finding = &findings[0];
                assert_eq!(finding.ident, "insecure-commands");
                assert_eq!(finding.fixes.len(), 1);

                let fix = &finding.fixes[0];
                assert_eq!(
                    fix.title,
                    "remove ACTIONS_ALLOW_UNSECURE_COMMANDS environment variable"
                );
                assert_eq!(fix.patches.len(), 1);

                let patch = &fix.patches[0];
                assert!(matches!(patch.operation, Op::Remove));
            }
        );
    }

    #[test]
    fn test_fix_removes_insecure_commands_preserves_others() {
        let workflow_content = r#"
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    env:
      ACTIONS_ALLOW_UNSECURE_COMMANDS: true
      OTHER_VAR: keep-me
      ANOTHER_VAR: also-keep
    steps:
      - run: echo "test"
"#;

        test_workflow_audit!(
            InsecureCommands,
            "test_fix_preserve.yml",
            workflow_content,
            |workflow: &Workflow, findings: Vec<Finding>| {
                assert_eq!(findings.len(), 1);
                let finding = &findings[0];
                assert_eq!(finding.fixes.len(), 1);

                let fix = &finding.fixes[0];
                let fixed_document = fix.apply(workflow.as_document()).unwrap();

                // Check that ACTIONS_ALLOW_UNSECURE_COMMANDS is removed
                assert!(
                    !fixed_document
                        .source()
                        .contains("ACTIONS_ALLOW_UNSECURE_COMMANDS")
                );

                // Check that other environment variables are preserved
                assert!(fixed_document.source().contains("OTHER_VAR: keep-me"));
                assert!(fixed_document.source().contains("ANOTHER_VAR: also-keep"));

                insta::assert_snapshot!(fixed_document.source(), @r#"
                on: push

                jobs:
                  test:
                    runs-on: ubuntu-latest
                    env:
                      OTHER_VAR: keep-me
                      ANOTHER_VAR: also-keep
                    steps:
                      - run: echo "test"
                "#);
            }
        );
    }

    #[test]
    fn test_workflow_level_insecure_commands_fix() {
        let workflow_content = r#"
on: push

env:
  ACTIONS_ALLOW_UNSECURE_COMMANDS: true
  GLOBAL_VAR: keep-me

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "test"
"#;

        test_workflow_audit!(
            InsecureCommands,
            "test_workflow_fix.yml",
            workflow_content,
            |workflow: &Workflow, findings: Vec<Finding>| {
                assert_eq!(findings.len(), 1);
                let finding = &findings[0];
                assert_eq!(finding.fixes.len(), 1);

                let fix = &finding.fixes[0];
                let fixed_document = fix.apply(workflow.as_document()).unwrap();

                // Check that ACTIONS_ALLOW_UNSECURE_COMMANDS is removed at workflow level
                assert!(
                    !fixed_document
                        .source()
                        .contains("ACTIONS_ALLOW_UNSECURE_COMMANDS")
                );

                // Check that other workflow-level env vars are preserved
                assert!(fixed_document.source().contains("GLOBAL_VAR: keep-me"));

                insta::assert_snapshot!(fixed_document.source(), @r#"
                on: push

                env:
                  GLOBAL_VAR: keep-me

                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - run: echo "test"
                "#);
            }
        );
    }

    #[test]
    fn test_step_level_insecure_commands_fix() {
        let workflow_content = r#"
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: step with insecure commands
        run: echo "test"
        env:
          ACTIONS_ALLOW_UNSECURE_COMMANDS: true
          STEP_VAR: keep-me
"#;

        test_workflow_audit!(
            InsecureCommands,
            "test_step_fix.yml",
            workflow_content,
            |workflow: &Workflow, findings: Vec<Finding>| {
                assert_eq!(findings.len(), 1);
                let finding = &findings[0];
                assert_eq!(finding.fixes.len(), 1);

                let fix = &finding.fixes[0];
                let fixed_document = fix.apply(workflow.as_document()).unwrap();

                // Check that ACTIONS_ALLOW_UNSECURE_COMMANDS is removed at step level
                assert!(
                    !fixed_document
                        .source()
                        .contains("ACTIONS_ALLOW_UNSECURE_COMMANDS")
                );

                // Check that other step-level env vars are preserved
                assert!(fixed_document.source().contains("STEP_VAR: keep-me"));

                insta::assert_snapshot!(fixed_document.source(), @r#"
                on: push

                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - name: step with insecure commands
                        run: echo "test"
                        env:
                          STEP_VAR: keep-me
                "#);
            }
        );
    }

    #[test]
    fn test_string_value_insecure_commands_fix() {
        let workflow_content = r#"
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    env:
      ACTIONS_ALLOW_UNSECURE_COMMANDS: "true"
      OTHER_VAR: keep-me
    steps:
      - run: echo "test"
"#;

        test_workflow_audit!(
            InsecureCommands,
            "test_string_fix.yml",
            workflow_content,
            |workflow: &Workflow, findings: Vec<Finding>| {
                assert_eq!(findings.len(), 1);
                let finding = &findings[0];
                assert_eq!(finding.fixes.len(), 1);

                let fix = &finding.fixes[0];
                let fixed_document = fix.apply(workflow.as_document()).unwrap();

                insta::assert_snapshot!(fixed_document.source(), @r#"
                on: push

                jobs:
                  test:
                    runs-on: ubuntu-latest
                    env:
                      OTHER_VAR: keep-me
                    steps:
                      - run: echo "test"
                "#);
            }
        );
    }
}
