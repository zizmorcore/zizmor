//! Schema types for JSON Schema generation of zizmor configuration.
//!
//! These types are used exclusively for generating JSON Schema via schemars.
//! They are not instantiated or read at runtime - schemars uses reflection
//! to inspect the type structure for schema generation.
//!
//! The `dead_code` lint is suppressed because the compiler cannot detect
//! that these types are accessed through schemars' procedural macros.

#![allow(dead_code)]

use schemars::JsonSchema;

use super::{DependabotCooldownConfig, ForbiddenUsesConfig, UnpinnedUsesConfig, WorkflowRule};

/// Base configuration for all audit rules.
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
#[derive(Clone, Debug, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ForbiddenUsesRuleConfig {
    #[serde(flatten)]
    base: BaseRuleConfig,

    #[serde(default)]
    config: Option<ForbiddenUsesConfig>,
}

/// Configuration for the `unpinned-uses` audit.
#[derive(Debug, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
struct UnpinnedUsesRuleConfig {
    #[serde(flatten)]
    base: BaseRuleConfig,

    #[serde(default)]
    config: UnpinnedUsesConfig,
}

macro_rules! define_audit_rules {
    (
        $( $field:ident ),* $(,)?
        ;
        $( [$config_type:ty] $custom_field:ident ),* $(,)?
    ) => {
        #[derive(Debug, Default, JsonSchema)]
        #[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
        struct RulesConfig {
            $(
                $field: BaseRuleConfig,
            )*
            $(
                $custom_field: $config_type,
            )*
        }
    };
}

define_audit_rules! {
    artipacked,
    unsound_contains,
    excessive_permissions,
    dangerous_triggers,
    impostor_commit,
    ref_confusion,
    use_trusted_publishing,
    template_injection,
    hardcoded_container_credentials,
    self_hosted_runner,
    known_vulnerable_actions,
    undocumented_permissions,
    insecure_commands,
    github_env,
    cache_poisoning,
    secrets_inherit,
    bot_conditions,
    overprovisioned_secrets,
    unredacted_secrets,
    obfuscation,
    stale_action_refs,
    unpinned_images,
    anonymous_definition,
    unsound_condition,
    ref_version_mismatch,
    dependabot_execution,
    concurrency_limits,
    archived_uses,
    misfeature;

    [DependabotCooldownRuleConfig] dependabot_cooldown,
    [ForbiddenUsesRuleConfig] forbidden_uses,
    [UnpinnedUsesRuleConfig] unpinned_uses,
}

/// # zizmor's configuration
///
/// Configuration file for zizmor, a static analysis tool for GitHub Actions.
///
/// See: https://docs.zizmor.sh/configuration/
#[derive(Debug, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default)]
    rules: RulesConfig,
}

pub(crate) fn generate_schema() -> String {
    // NOTE: We intentionally use Draft 7, since SchemaStore prefers it.
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
        01: "foo.yml:invalid" does not match "^[^:]+\.ya?ml(:[1-9][0-9]*)?(:[1-9][0-9]*)?$"
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
        01: "unknown-policy" is not valid under any of the schemas listed in the 'oneOf' keyword
        "#);
    }
}
