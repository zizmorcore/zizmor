//! Per-run cross-audit state types and routines.
//!
//! Primarily for maintaining caches between audits and audit runs.

use moka::sync::Cache;

use crate::{
    github_api::{Branch, Tag},
    AuditConfig,
};

#[derive(Clone)]
pub(crate) struct State {
    /// The current config.
    pub(crate) config: AuditConfig,

    /// A cache of all symbolic refs (branches and tags)
    /// for a given `(owner, repo)` on GitHub.
    ref_cache: Cache<(String, String), (Vec<Branch>, Vec<Tag>)>,

    /// A cache of `(base_ref, head_ref) => status`.
    ///
    /// We don't bother disambiguating this cache by `owner/repo`, since
    /// `head_ref` is a SHA ref and we expect those to be globally unique.
    /// This is not technically true of Git SHAs due to SHAttered, but is
    /// effectively true for SHAs on GitHub due to GitHub's collision detection.
    ref_comparison_cache: Cache<(String, String), bool>,
}

impl State {
    pub(crate) fn new(config: AuditConfig) -> Self {
        Self {
            config,
            // TODO: Increase these empirically? Would be good to have
            // stats on how many unique repo slugs an average run sees.
            ref_cache: Cache::new(1000),
            ref_comparison_cache: Cache::new(1000),
        }
    }
}
