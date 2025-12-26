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
pub struct BaseRuleConfig {
    #[serde(default)]
    pub disable: bool,

    #[serde(default)]
    pub ignore: Vec<WorkflowRule>,
}

#[derive(Clone, Debug, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DependabotCooldownRuleConfig {
    #[serde(flatten)]
    pub base: BaseRuleConfig,

    #[serde(default)]
    pub config: DependabotCooldownConfig,
}

#[derive(Clone, Debug, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForbiddenUsesAllowConfig {
    pub allow: Vec<RepositoryUsesPattern>,
}

#[derive(Clone, Debug, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForbiddenUsesDenyConfig {
    pub deny: Vec<RepositoryUsesPattern>,
}

#[derive(Clone, Debug, JsonSchema)]
#[serde(untagged)]
pub enum ForbiddenUsesConfig {
    Allow(ForbiddenUsesAllowConfig),
    Deny(ForbiddenUsesDenyConfig),
}

#[derive(Clone, Debug, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForbiddenUsesRuleConfig {
    #[serde(flatten)]
    pub base: BaseRuleConfig,

    #[serde(default)]
    pub config: Option<ForbiddenUsesConfig>,
}

#[derive(Clone, Debug, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnpinnedUsesConfig {
    #[serde(default)]
    pub policies: HashMap<String, UsesPolicy>,
}

#[derive(Clone, Debug, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnpinnedUsesRuleConfig {
    #[serde(flatten)]
    pub base: BaseRuleConfig,

    #[serde(default)]
    pub config: Option<UnpinnedUsesConfig>,
}

macro_rules! define_audit_rules {
    (
        $( $field:ident => $name:literal, $desc:literal ),* $(,)?
        ;
        $( [$config_type:ty] $custom_field:ident => $custom_name:literal, $custom_desc:literal ),* $(,)?
    ) => {
        #[derive(Clone, Debug, Default, JsonSchema)]
        #[serde(deny_unknown_fields)]
        pub struct RulesConfig {
            $(
                #[doc = $desc]
                #[serde(default, rename = $name)]
                pub $field: Option<BaseRuleConfig>,
            )*
            $(
                #[doc = $custom_desc]
                #[serde(default, rename = $custom_name)]
                pub $custom_field: Option<$config_type>,
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

#[derive(Clone, Debug, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(
    title = "zizmor configuration",
    description = "Configuration file for zizmor, a static analysis tool for GitHub Actions\nhttps://docs.zizmor.sh/configuration/"
)]
pub struct Config {
    #[serde(default)]
    pub rules: RulesConfig,
}

pub fn generate_schema() -> String {
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
}
