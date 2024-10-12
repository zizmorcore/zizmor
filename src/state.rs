//! Per-run cross-audit state types and routines.
//!
//! Primarily for maintaining caches between audits and audit runs.

use moka::sync::Cache;

use crate::{
    github_api::{Branch, ComparisonStatus, Tag},
    AuditConfig,
};

#[derive(Clone)]
pub(crate) struct State {
    /// The current config.
    pub(crate) config: AuditConfig,
    pub(crate) caches: Caches,
}

impl State {
    pub(crate) fn new(config: AuditConfig) -> Self {
        Self {
            config,
            caches: Caches::new(),
        }
    }
}

#[derive(Clone)]
/// Runtime caches.
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
