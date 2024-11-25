use super::{audit_meta, WorkflowAudit};
use crate::finding::{Confidence, Finding, Severity};
use crate::models::Step;
use crate::state::AuditState;
use github_actions_models::workflow::job::StepBody;
use regex::RegexSet;
use std::ops::Deref;
use std::sync::LazyLock;

static GITHUB_ENV_WRITE_SHELL: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        // matches the `... >> $GITHUB_ENV` pattern
        r#"(?m)^.+\s*>>?\s*"?\$\{?GITHUB_ENV\}?"?.*$"#,
        // matches the `... | tee $GITHUB_ENV` pattern
        r#"(?m)^.*\|\s*tee\s+"?\$\{?GITHUB_ENV\}?"?.*$"#,
    ])
    .unwrap()
});

pub(crate) struct GitHubEnv;

audit_meta!(GitHubEnv, "github-env", "dangerous use of GITHUB_ENV");

impl GitHubEnv {
    fn uses_github_environment(run_step_body: &str) -> bool {
        GITHUB_ENV_WRITE_SHELL.is_match(run_step_body)
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

        if let StepBody::Run { run, .. } = &step.deref().body {
            if Self::uses_github_environment(run) {
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
    fn test_shell_patterns() {
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
            assert!(GitHubEnv::uses_github_environment(case));
        }
    }
}
