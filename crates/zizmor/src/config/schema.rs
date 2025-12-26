//! Schema types for JSON Schema generation of zizmor configuration.
//!
//! These types are used exclusively for generating JSON Schema via schemars.
//! They are not instantiated or read at runtime - schemars uses reflection
//! to inspect the type structure for schema generation.
//!
//! The `dead_code` lint is suppressed because the compiler cannot detect
//! that these types are accessed through schemars' procedural macros.

#![allow(dead_code)]

use std::collections::HashMap;

use schemars::JsonSchema;

use super::{DependabotCooldownConfig, UsesPolicy, WorkflowRule};
use crate::models::uses::RepositoryUsesPattern;

#[derive(Clone, Debug, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
struct BaseRuleConfig {
    #[serde(default)]
    disable: bool,

    #[serde(default)]
    ignore: Vec<WorkflowRule>,
}

/// Configuration for the `dependabot-cooldown` audit.
#[derive(Clone, Debug, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DependabotCooldownRuleConfig {
    #[serde(flatten)]
    base: BaseRuleConfig,

    #[serde(default)]
    config: DependabotCooldownConfig,
}

/// Configuration for the `forbidden-uses` audit.
#[derive(Clone, Debug, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ForbiddenUsesAllowConfig {
    allow: Vec<RepositoryUsesPattern>,
}

#[derive(Clone, Debug, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ForbiddenUsesDenyConfig {
    deny: Vec<RepositoryUsesPattern>,
}

#[derive(Clone, Debug, JsonSchema)]
#[serde(untagged)]
enum ForbiddenUsesConfig {
    Allow(ForbiddenUsesAllowConfig),
    Deny(ForbiddenUsesDenyConfig),
}

#[derive(Clone, Debug, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ForbiddenUsesRuleConfig {
    #[serde(flatten)]
    base: BaseRuleConfig,

    #[serde(default)]
    config: Option<ForbiddenUsesConfig>,
}

#[derive(Clone, Debug, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
struct UnpinnedUsesConfig {
    #[serde(default)]
    policies: HashMap<String, UsesPolicy>,
}

#[derive(Clone, Debug, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
struct UnpinnedUsesRuleConfig {
    #[serde(flatten)]
    base: BaseRuleConfig,

    #[serde(default)]
    config: Option<UnpinnedUsesConfig>,
}

macro_rules! define_audit_rules {
    (
        $( $field:ident => $name:literal, $desc:literal ),* $(,)?
        ;
        $( [$config_type:ty] $custom_field:ident => $custom_name:literal, $custom_desc:literal ),* $(,)?
    ) => {
        #[derive(Clone, Debug, Default, JsonSchema)]
        #[serde(deny_unknown_fields)]
        struct RulesConfig {
            $(
                #[doc = $desc]
                #[serde(default, rename = $name)]
                 $field: Option<BaseRuleConfig>,
            )*
            $(
                #[doc = $custom_desc]
                #[serde(default, rename = $custom_name)]
                 $custom_field: Option<$config_type>,
            )*
        }
    };
}

define_audit_rules! {
    artipacked => "artipacked", "credential persistence through GitHub Actions artifacts",
    unsound_contains => "unsound-contains", "unsound contains condition",
    excessive_permissions => "excessive-permissions", "overly broad permissions",
    dangerous_triggers => "dangerous-triggers", "use of fundamentally insecure workflow trigger",
    impostor_commit => "impostor-commit", "commit with no history in referenced repository",
    ref_confusion => "ref-confusion", "git ref for action with ambiguous ref type",
    use_trusted_publishing => "use-trusted-publishing", "prefer trusted publishing for authentication",
    template_injection => "template-injection", "code injection via template expansion",
    hardcoded_container_credentials => "hardcoded-container-credentials", "hardcoded credential in GitHub Actions container configurations",
    self_hosted_runner => "self-hosted-runner", "runs on a self-hosted runner",
    known_vulnerable_actions => "known-vulnerable-actions", "action has a known vulnerability",
    undocumented_permissions => "undocumented-permissions", "permissions without explanatory comments",
    insecure_commands => "insecure-commands", "execution of insecure workflow commands is enabled",
    github_env => "github-env", "dangerous use of environment file",
    cache_poisoning => "cache-poisoning", "runtime artifacts potentially vulnerable to a cache poisoning attack",
    secrets_inherit => "secrets-inherit", "secrets unconditionally inherited by called workflow",
    bot_conditions => "bot-conditions", "spoofable bot actor check",
    overprovisioned_secrets => "overprovisioned-secrets", "excessively provisioned secrets",
    unredacted_secrets => "unredacted-secrets", "leaked secret values",
    obfuscation => "obfuscation", "obfuscated usage of GitHub Actions features",
    stale_action_refs => "stale-action-refs", "commit hash does not point to a Git tag",
    unpinned_images => "unpinned-images", "unpinned image references",
    anonymous_definition => "anonymous-definition", "workflow or action definition without a name",
    unsound_condition => "unsound-condition", "unsound conditional expression",
    ref_version_mismatch => "ref-version-mismatch", "detects commit SHAs that don't match their version comment tags",
    dependabot_execution => "dependabot-execution", "external code execution in Dependabot updates",
    concurrency_limits => "concurrency-limits", "insufficient job-level concurrency limits",
    archived_uses => "archived-uses", "action or reusable workflow from archived repository";

    [DependabotCooldownRuleConfig] dependabot_cooldown => "dependabot-cooldown", "insufficient cooldown in Dependabot updates",
    [ForbiddenUsesRuleConfig] forbidden_uses => "forbidden-uses", "forbidden action used",
    [UnpinnedUsesRuleConfig] unpinned_uses => "unpinned-uses", "unpinned action reference"
}

/// # zizmor's configuration
///
/// Configuration file for zizmor, a static analysis tool for GitHub Actions.
///
/// See: https://docs.zizmor.sh/configuration/
#[derive(Clone, Debug, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default)]
    rules: RulesConfig,
}

pub(crate) fn generate_schema() -> String {
    // NOTE: We intentioally use Draft 7, since SchemaStore prefers it.
    let generator = schemars::generate::SchemaSettings::draft07().into_generator();
    let schema = generator.into_root_schema_for::<Config>();
    serde_json::to_string_pretty(&schema).expect("failed to serialize schema")
}

#[cfg(test)]
mod tests {
    use super::Config;
    use jsonschema::{Validator, validator_for};
    use std::sync::LazyLock;

    static SCHEMA_VALIDATOR: LazyLock<Validator> =
        LazyLock::new(|| validator_for(&schemars::schema_for!(Config).to_value()).unwrap());

    #[test]
    fn test_empty_rules() {
        let empty = "rules: {}";
        let instance = serde_yaml::from_str::<serde_json::Value>(empty).unwrap();

        SCHEMA_VALIDATOR
            .validate(&instance)
            .expect("empty rules should be valid");
    }

    #[test]
    fn test_disabled_rule() {
        let disabled = r#"
        rules:
          stale-action-refs:
            disable: true

          unpinned-uses:
            disable: false
        "#;
        let instance = serde_yaml::from_str::<serde_json::Value>(disabled).unwrap();

        SCHEMA_VALIDATOR
            .validate(&instance)
            .expect("disabled rule should be valid");
    }

    #[test]
    fn test_ignore_rule() {
        let ignore = r#"
        rules:
          stale-action-refs:
            ignore:
              - foo.yml
              - foo.yml:10
              - foo.yml:10:20
        "#;
        let instance = serde_yaml::from_str::<serde_json::Value>(ignore).unwrap();

        SCHEMA_VALIDATOR
            .validate(&instance)
            .expect("ignore rule should be valid");

        // Invalid workflow rules should be rejected.
        let invalid_ignore = r#"
        rules:
          stale-action-refs:
            ignore:
              - foo.yml:invalid
        "#;
        let instance = serde_yaml::from_str::<serde_json::Value>(invalid_ignore).unwrap();
        let errors = SCHEMA_VALIDATOR.iter_errors(&instance).into_errors();
        insta::assert_snapshot!(errors, @r#"
        Validation errors:
        01: {"ignore":["foo.yml:invalid"]} is not valid under any of the schemas listed in the 'anyOf' keyword
        "#);
    }

    #[test]
    fn test_unknown_audit() {
        let unknown_audit = r#"
        rules:
          this-audit-does-not-exist:
            disable: false
        "#;
        let instance = serde_yaml::from_str::<serde_json::Value>(unknown_audit).unwrap();

        let result = SCHEMA_VALIDATOR.validate(&instance);
        assert!(result.is_err(), "unknown audit should be invalid");
    }

    #[test]
    fn test_forbidden_uses_config() {
        let forbidden_uses_allow = r#"
        rules:
          forbidden-uses:
            config:
              allow:
                - actions/checkout@v2
                - actions/setup-node@v3
                - foo/*
        "#;
        let instance = serde_yaml::from_str::<serde_json::Value>(forbidden_uses_allow).unwrap();

        SCHEMA_VALIDATOR
            .validate(&instance)
            .expect("forbidden uses allow config should be valid");

        let forbidden_uses_deny = r#"
        rules:
          forbidden-uses:
            config:
              deny:
                - actions/checkout@v1
                - actions/setup-node@v1
                - foo/*
        "#;
        let instance = serde_yaml::from_str::<serde_json::Value>(forbidden_uses_deny).unwrap();

        SCHEMA_VALIDATOR
            .validate(&instance)
            .expect("forbidden uses deny config should be valid");
    }

    #[test]
    fn test_unpinned_uses_config() {
        let valid = r#"
        rules:
          unpinned-uses:
            config:
              policies:
                actions/checkout: hash-pin
        "#;
        let instance = serde_yaml::from_str::<serde_json::Value>(valid).unwrap();
        SCHEMA_VALIDATOR
            .validate(&instance)
            .expect("unpinned uses config should be valid");

        let unknown_policy = r#"
        rules:
          unpinned-uses:
            config:
              policies:
                actions/checkout: unknown-policy
        "#;
        let instance = serde_yaml::from_str::<serde_json::Value>(unknown_policy).unwrap();
        let errors = SCHEMA_VALIDATOR.iter_errors(&instance).into_errors();
        insta::assert_snapshot!(errors, @r#"
        Validation errors:
        01: {"config":{"policies":{"actions/checkout":"unknown-policy"}}} is not valid under any of the schemas listed in the 'anyOf' keyword
        "#);
    }
}
