//! zizmor's runtime state, including application-level caching.

use crate::{github_api::Client, App};

#[derive(Clone)]
pub(crate) struct AuditState {
    pub(crate) no_online_audits: bool,
    pub(crate) gh_token: Option<String>,
}

impl AuditState {
    pub(crate) fn new(app: &App) -> Self {
        Self {
            no_online_audits: app.no_online_audits,
            gh_token: app.gh_token.clone(),
        }
    }

    /// Return a cache-configured GitHub API client, if
    /// a GitHub API token is present.
    pub(crate) fn github_client(&self) -> Option<Client> {
        self.gh_token.as_ref().map(|token| Client::new(token))
    }
}
