use super::{audit_meta, WorkflowAudit};
use crate::finding::{Confidence, Finding, Severity};
use crate::models::Step;
use crate::state::AuditState;
use anyhow::Context;
use github_actions_models::workflow::job::StepBody;
use std::ops::Deref;
use tree_sitter::Parser;

pub(crate) struct GitHubEnv;

audit_meta!(GitHubEnv, "github-env", "dangerous use of GITHUB_ENV");

impl GitHubEnv {
    fn evaluate_github_environment_within_bash_script(script_body: &str) -> anyhow::Result<bool> {
        let bash = tree_sitter_bash::LANGUAGE;
        let mut parser = Parser::new();
        parser
            .set_language(&bash.into())
            .context("failed to load bash parser")?;
        let tree = parser
            .parse(script_body, None)
            .context("failed to parse bash script body")?;

        let mut stack = vec![tree.root_node()];

        while let Some(node) = stack.pop() {
            if node.is_named() && (node.kind() == "file_redirect" || node.kind() == "pipeline") {
                let tree_expansion = &script_body[node.start_byte()..node.end_byte()];
                let targets_github_env = tree_expansion.contains("GITHUB_ENV");
                let exploitable_redirects =
                    tree_expansion.contains(">>") || tree_expansion.contains(">");

                // Eventually we can detect specific commands within the expansion,
                // tee and others
                let piped = tree_expansion.contains("|");

                if (piped || exploitable_redirects) && targets_github_env {
                    return Ok(true);
                }
            }

            for child in node.named_children(&mut node.walk()) {
                stack.push(child);
            }
        }

        Ok(false)
    }

    fn uses_github_environment(run_step_body: &str, shell: &str) -> anyhow::Result<bool> {
        // Note : as an upcoming refinement, we should evaluate shell interpreters
        // other than Bash

        match shell {
            "bash" => Self::evaluate_github_environment_within_bash_script(run_step_body),
            &_ => {
                log::warn!(
                    "'{}' shell not supported when evaluating usage of GITHUB_ENV",
                    shell
                );
                Ok(false)
            }
        }
    }
}

impl WorkflowAudit for GitHubEnv {
    fn new(_: AuditState) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_step<'w>(&self, step: &Step<'w>) -> anyhow::Result<Vec<Finding<'w>>> {
        let mut findings = vec![];

        let workflow = step.workflow();

        let has_dangerous_triggers =
            workflow.has_workflow_run() || workflow.has_pull_request_target();

        if !has_dangerous_triggers {
            return Ok(findings);
        }

        if let StepBody::Run { run, shell, .. } = &step.deref().body {
            let interpreter = shell.clone().unwrap_or("bash".into());
            if Self::uses_github_environment(run, &interpreter)? {
                findings.push(
                    Self::finding()
                        .severity(Severity::High)
                        .confidence(Confidence::Low)
                        .add_location(
                            step.location()
                                .with_keys(&["run".into()])
                                .annotated("GITHUB_ENV write may allow code execution"),
                        )
                        .build(step.workflow())?,
                )
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::github_env::GitHubEnv;

    #[test]
    fn test_exploitable_bash_patterns() {
        for case in &[
            // Common cases
            "echo foo >> $GITHUB_ENV",
            "echo foo >> \"$GITHUB_ENV\"",
            "echo foo >> ${GITHUB_ENV}",
            "echo foo >> \"${GITHUB_ENV}\"",
            // Single > is buggy most of the time, but still exploitable
            "echo foo > $GITHUB_ENV",
            "echo foo > \"$GITHUB_ENV\"",
            "echo foo > ${GITHUB_ENV}",
            "echo foo > \"${GITHUB_ENV}\"",
            // No spaces
            "echo foo>>$GITHUB_ENV",
            "echo foo>>\"$GITHUB_ENV\"",
            "echo foo>>${GITHUB_ENV}",
            "echo foo>>\"${GITHUB_ENV}\"",
            // tee cases
            "something | tee $GITHUB_ENV",
            "something | tee \"$GITHUB_ENV\"",
            "something | tee ${GITHUB_ENV}",
            "something | tee \"${GITHUB_ENV}\"",
            "something|tee $GITHUB_ENV",
            "something |tee $GITHUB_ENV",
            "something| tee $GITHUB_ENV",
        ] {
            let uses_github_env = GitHubEnv::uses_github_environment(case, "bash")
                .expect("test case is not valid Bash");
            assert!(uses_github_env);
        }
    }

    #[test]
    fn test_additional_bash_patterns() {
        for case in &[
            // Comments
            "echo foo >> $OTHER_ENV # not $GITHUB_ENV",
            "something | tee \"${$OTHER_ENV}\" # not $GITHUB_ENV",
        ] {
            let uses_github_env = GitHubEnv::uses_github_environment(case, "bash")
                .expect("test case is not valid Bash");
            assert!(!uses_github_env);
        }
    }
}
