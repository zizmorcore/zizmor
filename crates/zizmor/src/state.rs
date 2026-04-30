//! zizmor's runtime state, including application-level caching.

use std::collections::HashMap;

use github_actions_models::common::Permission;

use crate::github::Client;

pub(crate) struct AuditState {
    /// Whether online audits should be skipped.
    pub(crate) no_online_audits: bool,
    /// A cache-configured GitHub API client, if a GitHub API token is given.
    pub(crate) gh_client: Option<Client>,
    /// Optional external action knowledge base loaded from `--action-kb`.
    ///
    /// Keys are `"owner/repo"` or `"owner/repo/subpath"` (lowercase, no `@version`).
    /// Values map permission scopes to their minimum required level.
    ///
    /// Entries here take precedence over the built-in KB in
    /// [`crate::audit::excessive_permissions`].
    pub(crate) action_kb: HashMap<String, HashMap<String, Permission>>,
}

impl AuditState {
    pub(crate) fn new(no_online_audits: bool, gh_client: Option<Client>) -> Self {
        Self {
            no_online_audits,
            gh_client,
            action_kb: HashMap::new(),
        }
    }
}

impl Default for AuditState {
    fn default() -> Self {
        Self {
            no_online_audits: true,
            gh_client: None,
            action_kb: HashMap::new(),
        }
    }
}
