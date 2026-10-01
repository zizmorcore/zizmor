use github_actions_models::common::CacheMode;

use crate::{finding::location::SymbolicLocation, models::workflow::JobCommon};

/// Tracks the effective cache mode for a job along with how it was made effective.
///
/// The "how" (implicit or explicit) is conveyed through the presence of a symbolic
/// location, which provides a useful location for diagnostics when a `cache-mode:`
/// clause is explcitly used.
#[derive(Clone, Debug)]
pub(crate) struct EffectiveCacheMode<'doc> {
    /// The effective cache mode.
    pub(crate) mode: CacheMode,
    /// If the cache mode is explicit, this is the symbolic location
    /// where it appears.
    _location: Option<SymbolicLocation<'doc>>,
}

/// Exposes a job's effective cache mode.
///
/// Logically this is also a good fit for a default implementation on [`JobCommon`],
/// but a distinct trait makes it easier to keep it local with the [`EffectiveCacheMode`]
/// type.
pub(crate) trait HasEffectiveCacheMode<'doc> {
    /// The effective cache mode.
    ///
    /// This is either the job's explicitly declared cache mode or the job's parent's
    /// effective cache mode.
    fn effective_cache_mode(&self) -> EffectiveCacheMode<'doc>;
}

impl<'doc, Job: JobCommon<'doc>> HasEffectiveCacheMode<'doc> for Job {
    fn effective_cache_mode(&self) -> EffectiveCacheMode<'doc> {
        match self.cache_mode() {
            // The job itself has an explicit cache-mode.
            Some(mode) => EffectiveCacheMode {
                mode,
                _location: Some(self.location().with_keys(["cache-mode".into()])),
            },
            None => match self.parent().cache_mode {
                // The parent (workflow) has an explicit cache-mode.
                Some(mode) => EffectiveCacheMode {
                    mode,
                    _location: Some(self.parent().location().with_keys(["cache-mode".into()])),
                },
                // Neither the job nor the workfloe has an explicit-cache mode,
                // so we get an implied one from the triggers.
                None => {
                    // TODO: This is wrong, we need some kind of set operation here.
                    let events = &self.parent().on.events;
                    if events.push.is_present()
                        || events.workflow_dispatch.is_present()
                        || events.repository_dispatch.is_present()
                        || events.delete.is_present()
                        || events.registry_package.is_present()
                        || events.page_build.is_present()
                        || events.schedule.is_present()
                    {
                        EffectiveCacheMode {
                            mode: CacheMode::Write,
                            _location: None,
                        }
                    } else {
                        // Everything else gets `cache-mode: read` by default.
                        EffectiveCacheMode {
                            mode: CacheMode::Read,
                            _location: None,
                        }
                    }
                }
            },
        }
    }
}
