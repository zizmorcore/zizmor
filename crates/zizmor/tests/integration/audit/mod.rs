//! Per-audit integrationt tests, including snapshots.

mod anonymous_definition;
mod archived_uses;
mod artipacked;
mod bot_conditions;
mod cache_poisoning;
mod concurrency_limits;
// mod dangerous_triggers; // TODO
mod dependabot_cooldown;
mod dependabot_execution;
mod excessive_permissions;
mod forbidden_uses;
mod github_env;
// mod hardcoded_container_credentials; // TODO
mod impostor_commit;
mod insecure_commands;
// mod known_vulnerable_actions; // TODO
mod obfuscation;
mod overprovisioned_secrets;
mod ref_confusion;
mod ref_version_mismatch;
mod secrets_inherit;
mod self_hosted_runner;
mod stale_action_refs;
mod template_injection;
mod undocumented_permissions;
mod unpinned_images;
mod unpinned_uses;
mod unredacted_secrets;
mod unsound_condition;
mod unsound_contains;
mod use_trusted_publishing;
