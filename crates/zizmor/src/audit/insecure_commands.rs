use std::ops::Deref as _;

use github_actions_models::action;
use github_actions_models::common::Env;
use github_actions_models::common::expr::LoE;
use github_actions_models::workflow::job;
use yamlpatch::{Op, Patch};

use super::{AuditLoadError, Job, audit_meta};
use crate::audit::{Audit, AuditError};
use crate::config::Config;
use crate::finding::location::Locatable as _;
use crate::finding::{
    Confidence, Finding, Fix, FixDisposition, Persona, Severity, location::SymbolicLocation,
};
use crate::models::workflow::StepInner;
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
    ) -> Result<Finding<'doc>, AuditError> {
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
    ) -> Result<Finding<'doc>, AuditError> {
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
            Some(value) => value.csharp_bool(),
            None => false,
        }
    }

    fn audit_steps<'doc>(
        &self,
        workflow: &'doc Workflow,
        steps: Steps<'doc>,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        steps
            .into_iter()
            .filter_map(|step| {
                let StepInner::Run(job::RunStep { shared, .. }) = &step.deref() else {
                    return None;
                };

                match &shared.env {
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

#[async_trait::async_trait]
impl Audit for InsecureCommands {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_workflow<'doc>(
        &self,
        workflow: &'doc Workflow,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
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

    async fn audit_composite_step<'doc>(
        &self,
        step: &super::CompositeStep<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
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
