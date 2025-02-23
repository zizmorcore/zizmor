use anyhow::{Context, Result};
use assert_cmd::Command;
use common::workflow_under_test;

mod common;

#[allow(dead_code)]
enum OutputMode {
    Stdout,
    Stderr,
    Both,
}

struct Zizmor {
    cmd: Command,
    offline: bool,
    workflow: Option<String>,
    output: OutputMode,
}

impl Zizmor {
    /// Create a new zizmor runner.
    fn new() -> Self {
        let cmd = Command::cargo_bin("zizmor").unwrap();

        Self {
            cmd,
            offline: true,
            workflow: None,
            output: OutputMode::Stdout,
        }
    }

    fn args<'a>(mut self, args: impl IntoIterator<Item = &'a str>) -> Self {
        self.cmd.args(args);
        self
    }

    #[allow(dead_code)]
    fn setenv(mut self, key: &str, value: &str) -> Self {
        self.cmd.env(key, value);
        self
    }

    fn unsetenv(mut self, key: &str) -> Self {
        self.cmd.env_remove(key);
        self
    }

    fn workflow(mut self, workflow: impl Into<String>) -> Self {
        self.workflow = Some(workflow.into());
        self
    }

    fn offline(mut self, flag: bool) -> Self {
        self.offline = flag;
        self
    }

    #[allow(dead_code)]
    fn output(mut self, output: OutputMode) -> Self {
        self.output = output;
        self
    }

    fn run(mut self) -> Result<String> {
        if self.offline {
            self.cmd.arg("--offline");
        } else {
            // If we're running in online mode, we pre-assert the
            // presence of GH_TOKEN to make configuration failures more obvious.
            std::env::var("GH_TOKEN").context("online tests require GH_TOKEN to be set")?;
        }

        if let Some(workflow) = &self.workflow {
            self.cmd.arg(workflow);
        }

        let output = self.cmd.output()?;

        let mut raw = String::from_utf8(match self.output {
            OutputMode::Stdout => output.stdout,
            OutputMode::Stderr => output.stderr,
            OutputMode::Both => [output.stdout, output.stderr].concat(),
        })?;

        if let Some(workflow) = &self.workflow {
            raw = raw.replace(workflow, "@@INPUT@@");
        }

        Ok(raw)
    }
}

fn zizmor() -> Zizmor {
    Zizmor::new()
}

#[test]
fn test_cant_retrieve() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .output(OutputMode::Stderr)
        .offline(true)
        .unsetenv("GH_TOKEN")
        .args(["pypa/sampleproject"])
        .run()?);

    Ok(())
}

#[test]
fn test_invalid_inputs() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .output(OutputMode::Stderr)
        .offline(true)
        .workflow(workflow_under_test("invalid/invalid-workflow.yml"))
        .run()?);

    Ok(())
}

#[test]
fn artipacked() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("artipacked.yml"))
        .args(["--persona=pedantic"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("artipacked.yml"))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("artipacked.yml"))
        .args(["--persona=auditor"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("artipacked/issue-447-repro.yml"))
        .args(["--persona=auditor"])
        .run()?);

    Ok(())
}

#[test]
fn self_hosted() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("self-hosted.yml"))
        .args(["--persona=auditor"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("self-hosted.yml"))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "self-hosted/self-hosted-runner-label.yml"
        ))
        .args(["--persona=auditor"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "self-hosted/self-hosted-runner-group.yml"
        ))
        .args(["--persona=auditor"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "self-hosted/self-hosted-matrix-dimension.yml"
        ))
        .args(["--persona=auditor"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "self-hosted/self-hosted-matrix-inclusion.yml"
        ))
        .args(["--persona=auditor"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "self-hosted/self-hosted-matrix-exclusion.yml"
        ))
        .args(["--persona=auditor"])
        .run()?);

    // Fixed regressions
    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("self-hosted/issue-283-repro.yml"))
        .args(["--persona=auditor"])
        .run()?);

    Ok(())
}

#[test]
fn unpinned_uses() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("unpinned-uses.yml"))
        .args(["--pedantic"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("unpinned-uses.yml"))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("unpinned-uses/action.yml"))
        .args(["--pedantic"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("unpinned-uses/issue-433-repro.yml"))
        .args(["--pedantic"])
        .run()?);

    Ok(())
}

#[test]
fn insecure_commands() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("insecure-commands.yml"))
        .args(["--persona=auditor"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("insecure-commands.yml"))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("insecure-commands/action.yml"))
        .args(["--persona=auditor"])
        .run()?);

    Ok(())
}

#[test]
fn template_injection() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "template-injection/template-injection-static-matrix.yml"
        ))
        .args(["--persona=auditor"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "template-injection/template-injection-dynamic-matrix.yml"
        ))
        .args(["--persona=auditor"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("template-injection/issue-22-repro.yml"))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("template-injection/pr-317-repro.yml"))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("template-injection/static-env.yml"))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "template-injection/issue-339-repro.yml"
        ))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "template-injection/issue-418-repro.yml"
        ))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "template-injection/pr-425-backstop/action.yml"
        ))
        .run()?);

    Ok(())
}

#[test]
fn cache_poisoning() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "cache-poisoning/caching-disabled-by-default.yml"
        ))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "cache-poisoning/caching-enabled-by-default.yml"
        ))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "cache-poisoning/caching-opt-in-boolean-toggle.yml"
        ))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "cache-poisoning/caching-opt-in-expression.yml"
        ))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "cache-poisoning/caching-opt-in-multi-value-toggle.yml"
        ))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("cache-poisoning/caching-opt-out.yml"))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "cache-poisoning/no-cache-aware-steps.yml"
        ))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "cache-poisoning/workflow-tag-trigger.yml"
        ))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "cache-poisoning/caching-opt-in-boolish-toggle.yml"
        ))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("cache-poisoning/publisher-step.yml"))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("cache-poisoning/issue-343-repro.yml"))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "cache-poisoning/caching-not-configurable.yml"
        ))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "cache-poisoning/workflow-release-branch-trigger.yml"
        ))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("cache-poisoning/issue-378-repro.yml"))
        .run()?);

    Ok(())
}

#[test]
fn excessive_permissions() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "excessive-permissions/issue-336-repro.yml"
        ))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "excessive-permissions/issue-336-repro.yml"
        ))
        .args(["--pedantic"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "excessive-permissions/workflow-default-perms.yml"
        ))
        .args(["--pedantic"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "excessive-permissions/workflow-read-all.yml"
        ))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "excessive-permissions/workflow-write-all.yml"
        ))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "excessive-permissions/workflow-empty-perms.yml"
        ))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "excessive-permissions/jobs-broaden-permissions.yml"
        ))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "excessive-permissions/workflow-write-explicit.yml"
        ))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "excessive-permissions/workflow-default-perms-all-jobs-explicit.yml"
        ))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "excessive-permissions/issue-472-repro.yml"
        ))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "excessive-permissions/reusable-workflow-call.yml"
        ))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "excessive-permissions/reusable-workflow-other-triggers.yml"
        ))
        .run()?);

    Ok(())
}

#[test]
fn github_env() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("github-env/action.yml"))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("github-env/github-path.yml"))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("github-env/issue-397-repro.yml"))
        .run()?);

    Ok(())
}

#[test]
fn secrets_inherit() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("secrets-inherit.yml"))
        .run()?);

    Ok(())
}

#[test]
fn bot_conditions() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("bot-conditions.yml"))
        .run()?);

    Ok(())
}

#[test]
fn overprovisioned_secrets() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("overprovisioned-secrets.yml"))
        .run()?);

    Ok(())
}

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn ref_confusion() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("ref-confusion.yml"))
        .offline(false)
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("ref-confusion/issue-518-repro.yml"))
        .offline(false)
        .run()?);

    Ok(())
}

#[test]
fn unredacted_secrets() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("unredacted-secrets.yml"))
        .run()?);

    Ok(())
}
