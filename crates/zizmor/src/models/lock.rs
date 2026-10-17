//! GitHub Actions lock models.
//!
//! These models enrich the models under [`github_actions_models::lock`],
//! providing higher-level APIs for zizmor to use.

use std::sync::LazyLock;

use github_actions_models::lock;
use thiserror::Error;

use crate::models::Validatable;

static LOCK_VALIDATOR: LazyLock<jsonschema::Validator> = LazyLock::new(|| {
    jsonschema::validator_for(
        &serde_json::from_str(include_str!("../data/github-lock.json"))
            .expect("internal error: compiled asset not JSON?"),
    )
    .expect("internal error: failed to load workflow schema")
});

/// Errors that can occur when loading a GitHub Actions lockfile.
#[derive(Debug, Error)]
pub(crate) enum LockError {}

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
    pub(crate) fn from_string(contents: String) -> Result<Self, LockError> {
        todo!()
    }
}
