use github_actions_models::common::CacheMode;

use crate::models::workflow::JobCommon;

/// Tracks the effective cache mode for a workflow along with how it was
/// made effective. The how (implicit or explicit) is important for presenting
/// a useful location in diagnostics, since implicit cache modes won't have
/// a `cache-mode:` key present in the workflow.
///
/// See [`super::JobCommon::effective_cache_mode`].
#[derive(Copy, Clone, Debug)]
pub(crate) enum EffectiveCacheMode {
    /// The cache mode is implicit, i.e. implied by the workflow's trigger.
    Implicit(CacheMode),
    /// The cache mode is explicit, i.e. set directly by `cache-mode: ...`.
    Explicit(CacheMode),
}

/// Exposes a job's effective cache mode.
///
/// Logically this is also a good fit for a default implementation on [`JobCommon`],
/// but a distinct trait makes it easier to keep it local with the [`EffectiveCacheMode`]
/// type.
pub(crate) trait HasEffectiveCacheMode {
    /// The effective cache mode.
    ///
    /// This is either the job's explicitly declared cache mode or the job's parent's
    /// effective cache mode.
    fn effective_cache_mode(&self) -> EffectiveCacheMode;
}

impl<'doc, Job: JobCommon<'doc>> HasEffectiveCacheMode for Job {
    fn effective_cache_mode(&self) -> EffectiveCacheMode {
        self.cache_mode().map_or_else(
            || self.parent().effective_cache_mode(),
            EffectiveCacheMode::Explicit,
        )
    }
}
