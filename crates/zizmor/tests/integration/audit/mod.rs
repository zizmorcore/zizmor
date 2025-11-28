//! Per-audit integrationt tests, including snapshots.

mod anonymous_definition;
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
// mod impostor_commit; // TODO
mod insecure_commands;
// mod known_vulnerable_actions; // TODO
mod obfuscation;
mod overprovisioned_secrets;
