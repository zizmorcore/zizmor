use std::ops::Deref;

use anyhow::Result;
use github_actions_models::action;
use github_actions_models::common::Env;
use github_actions_models::common::expr::LoE;
use github_actions_models::workflow::job::StepBody;

use super::{AuditLoadError, Job, audit_meta};
use crate::audit::Audit;
use crate::finding::{Confidence, Finding, Fix, Persona, Severity, SymbolicLocation};
use crate::models::{AsDocument, JobExt as _, StepCommon, Steps, Workflow};
use crate::state::AuditState;
use crate::{apply_yaml_patch, yaml_patch::YamlPatchOperation};

pub(crate) struct InsecureCommands;

audit_meta!(
    InsecureCommands,
    "insecure-commands",
    "execution of insecure workflow commands is enabled"
);

impl InsecureCommands {
    /// Create a fix that removes the ACTIONS_ALLOW_UNSECURE_COMMANDS environment variable
    fn create_remove_env_var_fix(path: &str, context: &str) -> Fix {
        Fix {
            title: format!("Remove ACTIONS_ALLOW_UNSECURE_COMMANDS from {}", context),
            description: format!(
                "Remove the ACTIONS_ALLOW_UNSECURE_COMMANDS environment variable from the {} environment. \
                This prevents the execution of insecure workflow commands, which is the recommended security practice. \
                Insecure commands like `::set-env` and `::add-path` can be exploited for code injection attacks.",
                context
            ),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Remove {
                path: format!("{}/ACTIONS_ALLOW_UNSECURE_COMMANDS", path),
            }]),
        }
    }

    /// Create a fix that sets ACTIONS_ALLOW_UNSECURE_COMMANDS to false
    fn create_disable_fix(path: &str, context: &str) -> Fix {
        Fix {
            title: format!(
                "Set ACTIONS_ALLOW_UNSECURE_COMMANDS to false in {}",
                context
            ),
            description: format!(
                "Explicitly set ACTIONS_ALLOW_UNSECURE_COMMANDS to false in the {} environment. \
                This makes the security intent clear and prevents the execution of insecure workflow commands. \
                While removing the variable entirely is also effective, this approach is more explicit.",
                context
            ),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Replace {
                path: format!("{}/ACTIONS_ALLOW_UNSECURE_COMMANDS", path),
                value: serde_yaml::Value::String("false".to_string()),
            }]),
        }
    }

    /// Create a fix that removes the entire step that enables insecure commands
    fn create_remove_step_fix(job_id: &str, step_index: usize) -> Fix {
        let step_path = format!("/jobs/{}/steps/{}", job_id, step_index);

        Fix {
            title: "Remove step with insecure commands enabled".to_string(),
            description: "Remove this step that enables insecure workflow commands. This eliminates the security risk \
                but you may need to replace the functionality with secure alternatives. Consider using step outputs, \
                job outputs, or environment variables set at the workflow level instead of insecure commands.".to_string(),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Remove {
                path: step_path,
            }]),
        }
    }

    /// Create a fix that removes the entire job that enables insecure commands
    fn create_remove_job_fix(job_id: &str) -> Fix {
        let job_path = format!("/jobs/{}", job_id);

        Fix {
            title: "Remove job with insecure commands enabled".to_string(),
            description: "Remove this job that enables insecure workflow commands. This eliminates the security risk \
                but you may need to replace the job functionality. Consider restructuring the workflow to avoid \
                the need for insecure commands.".to_string(),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Remove {
                path: job_path,
            }]),
        }
    }

    /// Get appropriate fixes for workflow-level insecure commands
    fn get_workflow_fixes(&self) -> Vec<Fix> {
        let env_path = "/env";
        vec![
            Self::create_remove_env_var_fix(env_path, "workflow"),
            Self::create_disable_fix(env_path, "workflow"),
        ]
    }

    /// Get appropriate fixes for job-level insecure commands
    fn get_job_fixes(&self, job_id: &str) -> Vec<Fix> {
        let env_path = format!("/jobs/{}/env", job_id);
        vec![
            Self::create_remove_env_var_fix(&env_path, "job"),
            Self::create_disable_fix(&env_path, "job"),
            Self::create_remove_job_fix(job_id),
        ]
    }

    /// Get appropriate fixes for step-level insecure commands
    fn get_step_fixes(&self, job_id: &str, step_index: usize) -> Vec<Fix> {
        let env_path = format!("/jobs/{}/steps/{}/env", job_id, step_index);
        vec![
            Self::create_remove_env_var_fix(&env_path, "step"),
            Self::create_disable_fix(&env_path, "step"),
            Self::create_remove_step_fix(job_id, step_index),
        ]
    }

    /// Get appropriate fixes for composite step insecure commands
    fn get_composite_step_fixes(&self, step_index: usize) -> Vec<Fix> {
        let env_path = format!("/runs/steps/{}/env", step_index);
        vec![
            Self::create_remove_env_var_fix(&env_path, "composite step"),
            Self::create_disable_fix(&env_path, "composite step"),
            Fix {
                title: "Remove composite step with insecure commands enabled".to_string(),
                description: "Remove this composite action step that enables insecure workflow commands. \
                    This eliminates the security risk but you may need to replace the step functionality \
                    with secure alternatives.".to_string(),
                apply: apply_yaml_patch!(vec![YamlPatchOperation::Remove {
                    path: format!("/runs/steps/{}", step_index),
                }]),
            },
        ]
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
                location.primary().with_keys(&["env".into()]).annotated(
                    "non-static environment may contain ACTIONS_ALLOW_UNSECURE_COMMANDS",
                ),
            )
            .build(doc)
    }

    fn insecure_commands_allowed<'s, 'doc>(
        &self,
        doc: &'s impl AsDocument<'s, 'doc>,
        location: SymbolicLocation<'doc>,
        fixes: Vec<Fix>,
    ) -> Result<Finding<'doc>> {
        let mut finding_builder = Self::finding()
            .confidence(Confidence::High)
            .severity(Severity::High)
            .add_location(
                location
                    .primary()
                    .with_keys(&["env".into()])
                    .annotated("insecure commands enabled here"),
            );

        for fix in fixes {
            finding_builder = finding_builder.fix(fix);
        }

        finding_builder.build(doc)
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
        job_id: &str,
        steps: Steps<'doc>,
    ) -> Result<Vec<Finding<'doc>>> {
        steps
            .into_iter()
            .filter_map(|step| {
                let StepBody::Run {
                    run: _,
                    working_directory: _,
                    shell: _,
                    env,
                } = &step.deref().body
                else {
                    return None;
                };

                match env {
                    // The entire environment block is an expression, which we
                    // can't follow (for now). Emit an auditor-only finding.
                    LoE::Expr(_) => {
                        Some(self.insecure_commands_maybe_present(workflow, step.location()))
                    }
                    LoE::Literal(env) => {
                        if self.has_insecure_commands_enabled(env) {
                            let fixes = self.get_step_fixes(job_id, step.index);
                            Some(self.insecure_commands_allowed(workflow, step.location(), fixes))
                        } else {
                            None
                        }
                    }
                }
            })
            .collect()
    }
}

impl Audit for InsecureCommands {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_workflow<'doc>(&self, workflow: &'doc Workflow) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut results = vec![];

        match &workflow.env {
            LoE::Expr(_) => {
                results.push(self.insecure_commands_maybe_present(workflow, workflow.location())?)
            }
            LoE::Literal(env) => {
                if self.has_insecure_commands_enabled(env) {
                    let fixes = self.get_workflow_fixes();
                    results.push(self.insecure_commands_allowed(
                        workflow,
                        workflow.location(),
                        fixes,
                    )?)
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
                            let fixes = self.get_job_fixes(normal.id());
                            results.push(self.insecure_commands_allowed(
                                workflow,
                                normal.location(),
                                fixes,
                            )?);
                        }
                    }
                }

                results.extend(self.audit_steps(workflow, normal.id(), normal.steps())?)
            }
        }

        Ok(results)
    }

    fn audit_composite_step<'doc>(
        &self,
        step: &super::CompositeStep<'doc>,
    ) -> Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        let action::StepBody::Run { env, .. } = &step.body else {
            return Ok(findings);
        };

        match env {
            LoE::Expr(_) => {
                findings.push(self.insecure_commands_maybe_present(step.action(), step.location())?)
            }
            LoE::Literal(env) => {
                if self.has_insecure_commands_enabled(env) {
                    let fixes = self.get_composite_step_fixes(step.index);
                    findings.push(self.insecure_commands_allowed(
                        step.action(),
                        step.location(),
                        fixes,
                    )?);
                }
            }
        }

        Ok(findings)
    }
}
