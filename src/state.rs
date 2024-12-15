//! zizmor's runtime state, including application-level caching.

use moka::sync::Cache;

use crate::{
    github_api::{Branch, Client, ComparisonStatus, Tag},
    App,
};

#[derive(Clone)]
pub(crate) struct AuditState {
    pub(crate) no_online_audits: bool,
    pub(crate) gh_token: Option<String>,
    pub(crate) caches: Caches,
}

impl AuditState {
    pub(crate) fn new(app: &App) -> Self {
        Self {
            caches: Caches::new(),
            no_online_audits: app.no_online_audits,
            gh_token: app.gh_token.clone(),
        }
    }

    /// Return a cache-configured GitHub API client, if
    /// a GitHub API token is present.
    pub(crate) fn github_client(&self) -> Option<Client> {
        self.gh_token
            .as_ref()
            .map(|token| Client::new(token, self.caches.clone()))
    }
}

/// Runtime caches.
#[derive(Clone)]
pub(crate) struct Caches {
    /// A cache of `(owner, repo) => branches`.
    pub(crate) branch_cache: Cache<(String, String), Vec<Branch>>,

    /// A cache of `(owner, repo) => tags`.
    pub(crate) tag_cache: Cache<(String, String), Vec<Tag>>,

    /// A cache of `(base_ref, head_ref) => status`.
    ///
    /// We don't bother disambiguating this cache by `owner/repo`, since
    /// `head_ref` is a SHA ref and we expect those to be globally unique.
    /// This is not technically true of Git SHAs due to SHAttered, but is
    /// effectively true for SHAs on GitHub due to GitHub's collision detection.
    pub(crate) ref_comparison_cache: Cache<(String, String), Option<ComparisonStatus>>,
}

impl Caches {
    pub(crate) fn new() -> Self {
        Self {
            // TODO: Increase these empirically? Would be good to have
            // stats on how many unique repo slugs an average run sees.
            branch_cache: Cache::new(1000),
            tag_cache: Cache::new(1000),
            ref_comparison_cache: Cache::new(10000),
        }
    }
}
