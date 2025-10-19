//! Snapshot integration tests.
//!
//! TODO: This file is too big; break it into multiple
//! modules, one per audit/conceptual group.

use crate::common::{input_under_test, zizmor};
use anyhow::Result;

#[test]
fn test_cant_retrieve_offline() -> Result<()> {
    // Fails because --offline prevents network access.
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .offline(true)
            .unsetenv("GH_TOKEN")
            .args(["pypa/sampleproject"])
            .run()?
    );

    Ok(())
}

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_cant_retrieve_no_gh_token() -> Result<()> {
    // Fails because GH_TOKEN is not set.
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .offline(false)
            .unsetenv("GH_TOKEN")
            .args(["pypa/sampleproject"])
            .run()?
    );

    Ok(())
}

#[test]
fn test_github_output() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(true)
            .input(input_under_test("several-vulnerabilities.yml"))
            .args(["--persona=auditor", "--format=github"])
            .run()?
    );

    Ok(())
}

#[test]
fn anonymous_definition() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("anonymous-definition.yml"))
            .args(["--persona=pedantic"])
            .run()?
    );

    Ok(())
}

#[test]
fn artipacked() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("artipacked.yml"))
            .args(["--persona=pedantic"])
            .run()?
    );

    insta::assert_snapshot!(zizmor().input(input_under_test("artipacked.yml")).run()?);

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("artipacked.yml"))
            .args(["--persona=auditor"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("artipacked/issue-447-repro.yml"))
            .args(["--persona=auditor"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("artipacked/demo-action/action.yml"))
            .args(["--persona=auditor"])
            .run()?
    );

    Ok(())
}

#[test]
fn self_hosted() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("self-hosted.yml"))
            .args(["--persona=auditor"])
            .run()?
    );

    insta::assert_snapshot!(zizmor().input(input_under_test("self-hosted.yml")).run()?);

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("self-hosted/self-hosted-runner-label.yml"))
            .args(["--persona=auditor"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("self-hosted/self-hosted-runner-group.yml"))
            .args(["--persona=auditor"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "self-hosted/self-hosted-matrix-dimension.yml"
            ))
            .args(["--persona=auditor"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "self-hosted/self-hosted-matrix-inclusion.yml"
            ))
            .args(["--persona=auditor"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "self-hosted/self-hosted-matrix-exclusion.yml"
            ))
            .args(["--persona=auditor"])
            .run()?
    );

    // Fixed regressions
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("self-hosted/issue-283-repro.yml"))
            .args(["--persona=auditor"])
            .run()?
    );

    Ok(())
}

#[test]
fn unpinned_uses() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses.yml"))
            .args(["--pedantic"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses/action.yml"))
            .args(["--pedantic"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses/issue-433-repro.yml"))
            .args(["--pedantic"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses/issue-659-repro.yml"))
            .args(["--pedantic"])
            .run()?
    );

    // Config tests for `unpinned-uses`.

    // Default policies (no explicit config).
    insta::assert_snapshot!(
        "unpinned-uses-default-config",
        zizmor()
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?
    );

    // Require all uses to be hash-pinned.
    insta::assert_snapshot!(
        "unpinned-uses-hash-pin-everything-config",
        zizmor()
            .config(input_under_test(
                "unpinned-uses/configs/hash-pin-everything.yml"
            ))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?
    );

    // Require all uses to be ref-pinned.
    insta::assert_snapshot!(
        "unpinned-uses-ref-pin-everything-config",
        zizmor()
            .config(input_under_test(
                "unpinned-uses/configs/ref-pin-everything.yml"
            ))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?
    );

    // Composite config cases.
    insta::assert_snapshot!(
        "unpinned-uses-composite-config",
        zizmor()
            .config(input_under_test("unpinned-uses/configs/composite.yml"))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        "unpinned-uses-composite-config-2",
        zizmor()
            .config(input_under_test("unpinned-uses/configs/composite-2.yml"))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?
    );

    // Empty config.
    insta::assert_snapshot!(
        "unpinned-uses-empty-config",
        zizmor()
            .config(input_under_test("unpinned-uses/configs/empty.yml"))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?
    );

    // Invalid config: invalid policy syntax cases.
    for tc in [
        "invalid-wrong-policy-object",
        "invalid-policy-syntax-1",
        "invalid-policy-syntax-2",
        "invalid-policy-syntax-3",
        "invalid-policy-syntax-4",
        "invalid-policy-syntax-5",
        "invalid-policy-syntax-6",
    ] {
        insta::assert_snapshot!(
            zizmor()
                .expects_failure(true)
                .config(input_under_test(
                    &format!("unpinned-uses/configs/{tc}.yml",)
                ))
                .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
                .run()?
        );
    }

    Ok(())
}

#[test]
fn use_trusted_publishing() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("use-trusted-publishing.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "use-trusted-publishing/demo-action/action.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("use-trusted-publishing/cargo-publish.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("use-trusted-publishing/npm-publish.yml"))
            .run()?
    );

    // No use-trusted-publishing findings expected here.
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "use-trusted-publishing/issue-1191-repro.yml"
            ))
            .run()?
    );

    Ok(())
}

#[test]
fn insecure_commands() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("insecure-commands.yml"))
            .args(["--persona=auditor"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("insecure-commands.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("insecure-commands/action.yml"))
            .args(["--persona=auditor"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("insecure-commands/issue-839-repro.yml"))
            .args(["--persona=auditor"])
            .run()?
    );

    Ok(())
}

#[test]
fn template_injection() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "template-injection/template-injection-static-matrix.yml"
            ))
            .args(["--persona=auditor"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "template-injection/template-injection-dynamic-matrix.yml"
            ))
            .args(["--persona=auditor"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection/issue-22-repro.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection/pr-317-repro.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection/static-env.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection/issue-339-repro.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection/issue-418-repro.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "template-injection/pr-425-backstop/action.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "template-injection/false-positive-menagerie.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection/issue-749-repro.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection/codeql-sinks.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection/pwsh-script.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "template-injection/issue-883-repro/action.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "template-injection/multiline-expression.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection/issue-988-repro.yml"))
            .args(["--persona=pedantic"])
            .run()?
    );

    Ok(())
}

#[test]
fn cache_poisoning() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "cache-poisoning/caching-disabled-by-default.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "cache-poisoning/caching-enabled-by-default.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "cache-poisoning/caching-opt-in-boolean-toggle.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "cache-poisoning/caching-opt-in-expression.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "cache-poisoning/caching-opt-in-multi-value-toggle.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("cache-poisoning/caching-opt-out.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("cache-poisoning/no-cache-aware-steps.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("cache-poisoning/workflow-tag-trigger.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "cache-poisoning/caching-opt-in-boolish-toggle.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("cache-poisoning/publisher-step.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("cache-poisoning/issue-343-repro.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "cache-poisoning/caching-not-configurable.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "cache-poisoning/workflow-release-branch-trigger.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("cache-poisoning/issue-378-repro.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("cache-poisoning/issue-642-repro.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("cache-poisoning/issue-1081-repro.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("cache-poisoning/issue-1152-repro.yml"))
            .run()?
    );

    Ok(())
}

#[test]
fn excessive_permissions() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/issue-336-repro.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/issue-336-repro.yml"
            ))
            .args(["--pedantic"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/workflow-default-perms.yml"
            ))
            .args(["--pedantic"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/workflow-read-all.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/workflow-write-all.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/workflow-empty-perms.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/jobs-broaden-permissions.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/workflow-write-explicit.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/workflow-default-perms-all-jobs-explicit.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/issue-472-repro.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/reusable-workflow-call.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/reusable-workflow-other-triggers.yml"
            ))
            .run()?
    );

    Ok(())
}

#[test]
fn github_env() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("github-env/action.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("github-env/github-path.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("github-env/issue-397-repro.yml"))
            .run()?
    );

    Ok(())
}

#[test]
fn secrets_inherit() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("secrets-inherit.yml"))
            .run()?
    );

    Ok(())
}

#[test]
fn unsound_contains() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unsound-contains.yml"))
            .run()?
    );

    Ok(())
}

#[test]
fn bot_conditions() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("bot-conditions.yml"))
            .run()?
    );

    Ok(())
}

#[test]
fn overprovisioned_secrets() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("overprovisioned-secrets.yml"))
            .run()?
    );

    Ok(())
}

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn ref_confusion() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("ref-confusion.yml"))
            .offline(false)
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("ref-confusion/issue-518-repro.yml"))
            .offline(false)
            .run()?
    );

    Ok(())
}

#[test]
fn unredacted_secrets() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unredacted-secrets.yml"))
            .run()?
    );

    Ok(())
}

#[test]
fn forbidden_uses() -> Result<()> {
    for config in [
        "allow-all",
        "deny-all",
        "allow-some",
        "deny-some",
        "deny-some-refs",
        "allow-some-refs",
    ] {
        insta::assert_snapshot!(
            zizmor()
                .config(input_under_test(&format!(
                    "forbidden-uses/configs/{config}.yml"
                )))
                .input(input_under_test(
                    "forbidden-uses/forbidden-uses-menagerie.yml"
                ))
                .run()?
        );
    }

    Ok(())
}

#[test]
fn obfuscation() -> Result<()> {
    insta::assert_snapshot!(zizmor().input(input_under_test("obfuscation.yml")).run()?);

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("obfuscation/computed-indices.yml"))
            .args(["--persona=pedantic"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("obfuscation/issue-1177-repro.yml"))
            .args(["--persona=pedantic"])
            .run()?
    );

    Ok(())
}

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn stale_action_refs() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("stale-action-refs.yml"))
            .offline(false)
            .args(["--persona=pedantic"])
            .run()?
    );

    Ok(())
}

#[test]
fn unpinned_images() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-images.yml"))
            .args(["--persona=pedantic"])
            .run()?
    );

    Ok(())
}

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn ref_version_mismatch() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .input(input_under_test("ref-version-mismatch.yml"))
            .run()?
    );

    // Tags that point to other tags are handled correctly.
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .input(input_under_test(
                "ref-version-mismatch/nested-annotated-tags.yml"
            ))
            .run()?,
        @"No findings to report. Good job! (1 suppressed)"
    );

    Ok(())
}

#[test]
fn undocumented_permissions() -> Result<()> {
    // Test with pedantic persona (should find issues)
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("undocumented-permissions.yml"))
            .args(["--persona=pedantic"])
            .run()?
    );

    // Test with regular persona (should not find issues)
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("undocumented-permissions.yml"))
            .run()?
    );

    // Test with properly documented permissions (should not find issues even with pedantic)
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("undocumented-permissions/documented.yml"))
            .args(["--persona=pedantic"])
            .run()?
    );

    // Test with only "contents: read" (should not trigger rule)
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "undocumented-permissions/contents-read-only.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?
    );

    // Test with empty permissions (should not trigger rule)
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "undocumented-permissions/empty-permissions.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?
    );

    // Test with contents: read plus other permissions (should trigger rule)
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "undocumented-permissions/contents-read-with-other.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?
    );

    // Test with partially documented permissions (should ideally only flag undocumented ones)
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "undocumented-permissions/partially-documented.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?
    );

    Ok(())
}

#[test]
fn unsound_condition() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unsound-condition.yml"))
            .run()?
    );

    Ok(())
}

#[test]
fn dependabot_execution() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "dependabot-execution/basic/dependabot.yml"
            ))
            .run()?,
        @r"
    error[dependabot-execution]: external code execution in Dependabot updates
      --> @@INPUT@@:10:5
       |
     4 |   - package-ecosystem: pip
       |     ---------------------- this ecosystem
    ...
    10 |     insecure-external-code-execution: allow
       |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ enabled here
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    1 findings (1 fixable): 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

#[test]
fn dependabot_cooldown() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "dependabot-cooldown/missing/dependabot.yml"
            ))
            .run()?,
        @r"
    warning[dependabot-cooldown]: insufficient cooldown in Dependabot updates
     --> @@INPUT@@:4:5
      |
    4 |   - package-ecosystem: pip
      |     ^^^^^^^^^^^^^^^^^^^^^^ missing cooldown configuration
      |
      = note: audit confidence → High
      = note: this finding has an auto-fix

    1 findings (1 fixable): 0 informational, 0 low, 1 medium, 0 high
    "
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "dependabot-cooldown/no-default-days/dependabot.yml"
            ))
            .run()?,
        @r"
    warning[dependabot-cooldown]: insufficient cooldown in Dependabot updates
     --> @@INPUT@@:6:5
      |
    6 |     cooldown: {}
      |     ^^^^^^^^^^^^ no default-days configured
      |
      = note: audit confidence → High
      = note: this finding has an auto-fix

    1 findings (1 fixable): 0 informational, 0 low, 1 medium, 0 high
    ");

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "dependabot-cooldown/default-days-too-short/dependabot.yml"
            ))
            .run()?,
        @r"
    help[dependabot-cooldown]: insufficient cooldown in Dependabot updates
     --> @@INPUT@@:7:7
      |
    7 |       default-days: 2
      |       ^^^^^^^^^^^^^^^ insufficient default-days configured
      |
      = note: audit confidence → Medium
      = note: this finding has an auto-fix

    1 findings (1 fixable): 0 informational, 1 low, 0 medium, 0 high
    ");

    Ok(())
}

#[test]
fn concurrency_limits() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "concurrency-limits/missing.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?,
        @r"
    help[concurrency-limits]: insufficient job-level concurrency limits
      --> @@INPUT@@:1:1
       |
     1 | / name: Workflow without concurrency
     2 | | on: push
     3 | | permissions: {}
    ...  |
    10 | |     - name: 1-ok
    11 | |       run: echo ok
       | |___________________^ missing concurrency setting
       |
       = note: audit confidence → High

    1 finding: 0 informational, 1 low, 0 medium, 0 high
    "
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "concurrency-limits/cancel-false.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?,
        @r"
    help[concurrency-limits]: insufficient job-level concurrency limits
     --> @@INPUT@@:5:1
      |
    5 | / concurrency:
    6 | |   group: ${{ github.workflow }}-${{ github.event.pull_request_number || github.ref }}
    7 | |   cancel-in-progress: false
      | |___________________________^ cancel-in-progress set to false
      |
      = note: audit confidence → High

    1 finding: 0 informational, 1 low, 0 medium, 0 high
    "
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "concurrency-limits/no-cancel.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?,
        @r"
    help[concurrency-limits]: insufficient job-level concurrency limits
     --> @@INPUT@@:5:1
      |
    5 | concurrency: group
      | ^^^^^^^^^^^^^^^^^^ concurrency is missing cancel-in-progress
      |
      = note: audit confidence → High

    1 finding: 0 informational, 1 low, 0 medium, 0 high
    "
    );

    Ok(())
}
