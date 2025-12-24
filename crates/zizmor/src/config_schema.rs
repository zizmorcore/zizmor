use std::collections::HashMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::config::{UsesPolicy, WorkflowRule};
use crate::models::uses::RepositoryUsesPattern;

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BaseRuleConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "workflow_rule_vec_schema")]
    pub ignore: Option<Vec<String>>,
}

fn workflow_rule_vec_schema(
    generator: &mut schemars::r#gen::SchemaGenerator,
) -> schemars::schema::Schema {
    generator.subschema_for::<Option<Vec<WorkflowRule>>>()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DependabotCooldownConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DependabotCooldownRuleConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "workflow_rule_vec_schema")]
    pub ignore: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<DependabotCooldownConfig>,
}

fn repo_uses_pattern_vec_schema(
    generator: &mut schemars::r#gen::SchemaGenerator,
) -> schemars::schema::Schema {
    generator.subschema_for::<Vec<RepositoryUsesPattern>>()
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForbiddenUsesAllowConfig {
    #[schemars(schema_with = "repo_uses_pattern_vec_schema")]
    pub allow: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForbiddenUsesDenyConfig {
    #[schemars(schema_with = "repo_uses_pattern_vec_schema")]
    pub deny: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ForbiddenUsesConfig {
    Allow(ForbiddenUsesAllowConfig),
    Deny(ForbiddenUsesDenyConfig),
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForbiddenUsesRuleConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "workflow_rule_vec_schema")]
    pub ignore: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<ForbiddenUsesConfig>,
}

fn policies_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
    let policy_schema = generator.subschema_for::<UsesPolicy>();
    schemars::schema::Schema::Object(schemars::schema::SchemaObject {
        instance_type: Some(schemars::schema::InstanceType::Object.into()),
        metadata: Some(Box::new(schemars::schema::Metadata {
            description: Some(
                "A mapping of action patterns to pinning policies. \
                Keys are patterns like '*', 'owner/*', 'owner/repo', etc."
                    .to_string(),
            ),
            ..Default::default()
        })),
        object: Some(Box::new(schemars::schema::ObjectValidation {
            additional_properties: Some(Box::new(policy_schema)),
            ..Default::default()
        })),
        ..Default::default()
    })
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnpinnedUsesConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "policies_schema")]
    pub policies: Option<HashMap<String, UsesPolicy>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnpinnedUsesRuleConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "workflow_rule_vec_schema")]
    pub ignore: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<UnpinnedUsesConfig>,
}

macro_rules! define_audit_rules {
    (
        $( $field:ident => $name:literal, $desc:literal ),* $(,)?
        ;
        $( [$config_type:ty] $custom_field:ident => $custom_name:literal, $custom_desc:literal ),* $(,)?
    ) => {
        #[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
        #[serde(deny_unknown_fields)]
        pub struct RulesConfig {
            $(
                #[doc = $desc]
                #[serde(default, rename = $name, skip_serializing_if = "Option::is_none")]
                pub $field: Option<BaseRuleConfig>,
            )*
            $(
                #[doc = $custom_desc]
                #[serde(default, rename = $custom_name, skip_serializing_if = "Option::is_none")]
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

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(
    title = "zizmor configuration",
    description = "Configuration file for zizmor, a static analysis tool for GitHub Actions\nhttps://docs.zizmor.sh/configuration/"
)]
pub struct ZizmorConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<RulesConfig>,
}

pub fn generate_schema() -> String {
    let schema = schemars::schema_for!(ZizmorConfig);
    serde_json::to_string_pretty(&schema).expect("failed to serialize schema")
}
