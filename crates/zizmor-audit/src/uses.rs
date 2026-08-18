//! Extension traits for the `Uses` APIs.
//!
//! This is for GitHub Actions style `uses:` clauses;
//! more general "reference to repository" handling
//! lives in [`zizmor_core::models::repo_ref`].

use github_actions_models::common::{RepositoryUses, Uses};
use zizmor_core::models::repo_ref::RepoRef;

/// Useful APIs for interacting with `uses: owner/repo` clauses.
///
/// Some of these APIs are projections of [`RepoRef`]'s APIs.
pub(crate) trait RepositoryUsesExt {
    /// See [`RepoRef::matches`].
    fn matches(&self, pattern: &str) -> bool;

    /// See [`RepoRef::ref_is_commit`].
    fn ref_is_commit(&self) -> bool;

    /// See [`RepoRef::commit_ref`].
    fn commit_ref(&self) -> Option<&str>;
}

impl RepositoryUsesExt for RepositoryUses {
    fn matches(&self, template: &str) -> bool {
        RepoRef::from(self).matches(template)
    }

    fn ref_is_commit(&self) -> bool {
        RepoRef::from(self).ref_is_commit()
    }

    fn commit_ref(&self) -> Option<&str> {
        RepoRef::from(self).commit_ref()
    }
}

/// Useful APIs for interacting with all kinds of `uses:` clauses.
pub(crate) trait UsesExt {
    fn unpinned(&self) -> bool;
    fn unhashed(&self) -> bool;
}

impl UsesExt for Uses {
    /// Whether the `uses:` is unpinned.
    fn unpinned(&self) -> bool {
        match self {
            Self::Docker(docker) => docker.hash().is_none() && docker.tag().is_none(),
            Self::Repository(_) => false,
            // Local `uses:` are always unpinned; any `@ref` component
            // is actually part of the path.
            Self::Local(_) => true,
        }
    }

    /// Whether the `uses:` is unhashed (but potentially pinned with a non-hash),
    fn unhashed(&self) -> bool {
        match self {
            // TODO: Handle this case. Right now it's not very important,
            // since we don't really analyze local action uses at all,
            // and the "hashedness" of a local action is mostly moot anyways
            // (since it's fully contained within the calling repo),
            Self::Local(_) => false,
            Self::Repository(repo) => !RepoRef::from(repo).ref_is_commit(),
            Self::Docker(docker) => docker.hash().is_none(),
        }
    }
}
