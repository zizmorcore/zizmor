//! zizmor's runtime state, including application-level caching.

use crate::github_api::Client;

pub(crate) struct AuditState {
    /// Whether online audits should be skipped.
    pub(crate) no_online_audits: bool,
    /// A cache-configured GitHub API client, if a GitHub API token is given.
    pub(crate) gh_client: Option<Client>,
}

impl AuditState {
    pub(crate) fn new(no_online_audits: bool, gh_client: Option<Client>) -> Self {
        Self {
            no_online_audits,
            gh_client,
        }
    }
}

impl Default for AuditState {
    fn default() -> Self {
        Self {
            no_online_audits: true,
            gh_client: None,
        }
    }
}
