use super::{audit_meta, WorkflowAudit};
use crate::finding::{Confidence, Finding, Severity};
use crate::models::Step;
use crate::state::AuditState;
use anyhow::Context;
use github_actions_models::workflow::job::StepBody;
use std::cell::RefCell;
use std::ops::Deref;
use tree_sitter::Parser;

pub(crate) struct GitHubEnv {
    // NOTE: interior mutability used since Parser::parse requires &mut self
    bash_parser: RefCell<Parser>,
}

audit_meta!(GitHubEnv, "github-env", "dangerous use of GITHUB_ENV");

impl GitHubEnv {
    fn bash_runs_has_github_env_write(&self, script_body: &str) -> anyhow::Result<bool> {
        let tree = &self
            .bash_parser
            .borrow_mut()
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
                // like tee and others
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

    fn uses_github_environment(&self, run_step_body: &str, shell: &str) -> anyhow::Result<bool> {
        // TODO: handle `run:` bodies other than bash.
        match shell {
            "bash" => self.bash_runs_has_github_env_write(run_step_body),
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
        let bash = tree_sitter_bash::LANGUAGE;
        let mut parser = Parser::new();
        parser
            .set_language(&bash.into())
            .context("failed to load bash parser")?;
        Ok(Self {
            bash_parser: RefCell::new(parser),
        })
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
            if self.uses_github_environment(run, &interpreter)? {
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
    use crate::audit::WorkflowAudit;
    use crate::state::{AuditState, Caches};

    #[test]
    fn test_exploitable_bash_patterns() {
        for (case, expected) in &[
            // Common cases
            ("echo foo >> $GITHUB_ENV", true),
            ("echo foo >> \"$GITHUB_ENV\"", true),
            ("echo foo >> ${GITHUB_ENV}", true),
            ("echo foo >> \"${GITHUB_ENV}\"", true),
            // Single > is buggy most of the time, but still exploitable
            ("echo foo > $GITHUB_ENV", true),
            ("echo foo > \"$GITHUB_ENV\"", true),
            ("echo foo > ${GITHUB_ENV}", true),
            ("echo foo > \"${GITHUB_ENV}\"", true),
            // No spaces
            ("echo foo>>$GITHUB_ENV", true),
            ("echo foo>>\"$GITHUB_ENV\"", true),
            ("echo foo>>${GITHUB_ENV}", true),
            ("echo foo>>\"${GITHUB_ENV}\"", true),
            // tee cases
            ("something | tee $GITHUB_ENV", true),
            ("something | tee \"$GITHUB_ENV\"", true),
            ("something | tee ${GITHUB_ENV}", true),
            ("something | tee \"${GITHUB_ENV}\"", true),
            ("something|tee $GITHUB_ENV", true),
            ("something |tee $GITHUB_ENV", true),
            ("something| tee $GITHUB_ENV", true),
            // negative cases (comments should not be detected)
            ("echo foo >> $OTHER_ENV # not $GITHUB_ENV", false),
            ("something | tee \"${$OTHER_ENV}\" # not $GITHUB_ENV", false),
        ] {
            let audit_state = AuditState {
                pedantic: false,
                offline: false,
                gh_token: None,
                caches: Caches::new(),
            };

            let sut = GitHubEnv::new(audit_state).expect("failed to create audit");

            let uses_github_env = sut
                .uses_github_environment(case, "bash")
                .expect("test case is not valid Bash");
            assert_eq!(uses_github_env, *expected);
        }
    }
}
