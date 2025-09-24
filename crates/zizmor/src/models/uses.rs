//! Extension traits for the `Uses` APIs.

use github_actions_models::common::Uses;

use crate::models::uses::repository::RepositoryUsesExt as _;

pub(crate) mod docker;
pub(crate) mod repository;

/// Useful APIs for interacting with all kinds of `uses:` clauses.
pub(crate) trait UsesExt {
    fn unpinned(&self) -> bool;
    fn unhashed(&self) -> bool;
}

impl UsesExt for Uses {
    /// Whether the `uses:` is unpinned.
    fn unpinned(&self) -> bool {
        match self {
            Uses::Docker(docker) => docker.hash.is_none() && docker.tag.is_none(),
            Uses::Repository(_) => false,
            // Local `uses:` are always unpinned; any `@ref` component
            // is actually part of the path.
            Uses::Local(_) => true,
        }
    }

    /// Whether the `uses:` is unhashed (but potentially pinned with a non-hash),
    fn unhashed(&self) -> bool {
        match self {
            // TODO: Handle this case. Right now it's not very important,
            // since we don't really analyze local action uses at all,
            // and the "hashedness" of a local action is mostly moot anyways
            // (since it's fully contained within the calling repo),
            Uses::Local(_) => false,
            Uses::Repository(repo) => !repo.ref_is_commit(),
            Uses::Docker(docker) => docker.hash.is_none(),
        }
    }
}
