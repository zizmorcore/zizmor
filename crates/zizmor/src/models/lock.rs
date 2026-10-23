//! GitHub Actions workflow lockfile models.
//!
//! These models enrich the models under [`github_actions_models::lock`],
//! providing higher-level APIs for zizmor to use.

use std::sync::LazyLock;

use github_actions_models::lock;

use crate::{
    github::Client,
    models::Validatable,
    registry::input::{CollectionError, InputKey, InputSlug, root::Root},
};

const LOCKFILE_PATH: &str = ".github/workflows/actions.lock";

static LOCK_VALIDATOR: LazyLock<jsonschema::Validator> = LazyLock::new(|| {
    jsonschema::validator_for(
        &serde_json::from_str(include_str!("../data/github-lock.json"))
            .expect("internal error: compiled asset not JSON?"),
    )
    .expect("internal error: failed to load workflow schema")
});

/// Represents a GitHub Actions lockfile.
pub(crate) struct Lock {
    inner: lock::Lock,
}

impl<'de> Validatable<'de> for Lock {
    type Target = lock::Lock;

    type Skeleton = yaml_serde::Mapping;

    fn validator() -> &'static jsonschema::Validator {
        &LOCK_VALIDATOR
    }
}

impl std::ops::Deref for Lock {
    type Target = lock::Lock;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Lock {
    /// Load an Actions lockfile from the given string.
    ///
    /// Fails if the lockfile is malformed.
    // TODO(ww): `CollectionError` is a slightly weird error type here, but
    // we'd need to first refactor `Validatable` to not use `CollectionError`.
    fn from_string(contents: String) -> Result<Self, CollectionError> {
        Self::validate(&contents).map(|lock| Self { inner: lock })
    }

    /// Discover an Actions lockfile, relative to the given Git repo root.
    ///
    /// Returns `None` if the lockfile does not exist.
    pub(crate) fn discover_local(root: &Root) -> Result<Option<Self>, CollectionError> {
        let lockfile_path = root.path().join(LOCKFILE_PATH);

        match std::fs::read_to_string(lockfile_path) {
            Ok(contents) => Ok(Some(Self::from_string(contents)?)),
            Err(err) if matches!(err.kind(), std::io::ErrorKind::NotFound) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    /// Discover an Actions lockfile for a repository slug.
    ///
    /// Returns `None` if the lockfile does not exist.
    pub(crate) async fn discover_remote(
        client: &Client,
        slug: &InputSlug,
    ) -> Result<Option<Self>, CollectionError> {
        match client.fetch_single_file(slug, LOCKFILE_PATH).await {
            Ok(Some(contents)) => Ok(Some(Self::from_string(contents)?)),
            Ok(None) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    /// Test whether the given input is locked, i.e. is present
    /// in the lockfile.
    pub(crate) fn is_locked(&self, input: &impl AsRef<InputKey>) -> bool {
        let input = input.as_ref();

        match input {
            InputKey::Local(key) => {
                if let Some(path) = key.root_relative_path() {
                    self.inner.workflows.contains_key(path.as_str())
                } else {
                    false
                }
            }
            InputKey::Remote(key) => self.inner.workflows.contains_key(key.path().as_str()),
            // We have no meaningful way to determine whether a `stdin`
            // input is present in the lockfile.
            InputKey::Stdin(_) => false,
        }
    }
}
