//! Per-audit integrationt tests, including snapshots.

mod adhoc_packages;
mod anonymous_definition;
mod archived_uses;
mod artipacked;
mod bot_conditions;
mod cache_poisoning;
mod concurrency_limits;
mod dangerous_triggers;
mod dependabot_cooldown;
mod dependabot_execution;
mod excessive_permissions;
mod forbidden_uses;
mod github_app;
mod github_env;
// mod hardcoded_container_credentials; // TODO
mod dangerous_checkout;
mod impostor_commit;
mod insecure_commands;
mod insecure_url_scheme;
mod known_vulnerable_actions;
mod misfeature;
mod obfuscation;
mod overprovisioned_secrets;
mod ref_confusion;
mod ref_version_mismatch;
mod secrets_inherit;
mod secrets_outside_env;
mod self_hosted_runner;
mod self_repository;
mod stale_action_refs;
mod superfluous_actions;
mod template_injection;
mod typosquat_uses;
mod undocumented_permissions;
mod unpinned_images;
mod unpinned_tools;
mod unpinned_uses;
mod unredacted_secrets;
mod unsound_condition;
mod unsound_contains;
mod unsound_ternary;
mod use_trusted_publishing;

/// Compare the complete fixed workflow and the version comment on the selected step.
#[cfg(feature = "gh-token-tests")]
fn assert_fixed_uses(
    workspace: &zizmor_dev::Workspace,
    expected: &str,
    uses: yamlpath::Route<'_>,
) -> anyhow::Result<()> {
    let path = workspace.path().join(".github/workflows/test.yml");
    let actual = yamlpath::Document::new(std::fs::read_to_string(path)?)?;
    let expected = yamlpath::Document::new(expected)?;
    assert_eq!(
        astral_yaml_serde::from_stream::<astral_yaml_serde::Value>(actual.stream())?,
        astral_yaml_serde::from_stream::<astral_yaml_serde::Value>(expected.stream())?,
    );
    let [actual_comment] = actual.comments(actual.entry_range(&uses)?) else {
        anyhow::bail!("expected a version comment on the fixed uses field");
    };
    let [expected_comment] = expected.comments(expected.entry_range(&uses)?) else {
        anyhow::bail!("the fixture must specify a version comment");
    };
    assert_eq!(actual_comment.text, expected_comment.text);
    Ok(())
}
