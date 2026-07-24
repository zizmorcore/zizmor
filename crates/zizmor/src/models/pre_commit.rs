//! Pre-commit models.
//!
//! These models enrich the models under [`pre_commit_models`],
//! providing higher-level APIs for zizmor to use.

use std::sync::LazyLock;

use terminal_link::Link;

use crate::{
    finding::location::{Locatable, SymbolicFeature, SymbolicLocation},
    models::{AsDocument, Validatable},
    registry::input::{CollectionError, InputKey},
};

static PRE_COMMIT_CONFIG_VALIDATOR: LazyLock<jsonschema::Validator> = LazyLock::new(|| {
    jsonschema::validator_for(
        &serde_json::from_str(include_str!("../data/pre-commit-config.json"))
            .expect("internal error: compiled asset not JSON?"),
    )
    .expect("internal error: failed to load pre-commit config schema")
});

static PRE_COMMIT_HOOKS_VALIDATOR: LazyLock<jsonschema::Validator> = LazyLock::new(|| {
    jsonschema::validator_for(
        &serde_json::from_str(include_str!("../data/pre-commit-hooks.json"))
            .expect("internal error: compiled asset not JSON?"),
    )
    .expect("internal error: failed to load pre-commit hooks schema")
});

pub(crate) struct PreCommitConfig {
    pub(crate) key: InputKey,
    pub(crate) link: Option<String>,
    document: yamlpath::Document,
    inner: pre_commit_models::config::Config,
}

impl<'de> Validatable<'de> for PreCommitConfig {
    type Target = pre_commit_models::config::Config;

    type Skeleton = yaml_serde::Mapping;

    fn validator() -> &'static jsonschema::Validator {
        &PRE_COMMIT_CONFIG_VALIDATOR
    }
}

impl<'a> AsDocument<'a, 'a> for PreCommitConfig {
    fn as_document(&'a self) -> &'a yamlpath::Document {
        &self.document
    }
}

impl std::ops::Deref for PreCommitConfig {
    type Target = pre_commit_models::config::Config;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl std::fmt::Debug for PreCommitConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{key}", key = self.key)
    }
}

impl PreCommitConfig {
    pub(crate) fn from_string(contents: String, key: InputKey) -> Result<Self, CollectionError> {
        let inner = Self::validate(&contents)?;

        let document = yamlpath::Document::new(&contents)?;

        let link = match key {
            InputKey::Local(_) | InputKey::Stdin(_) => None,
            InputKey::Remote(_) => {
                // NOTE: InputKey's Display produces a URL, hence `key.to_string()`.
                Some(Link::new(key.presentation_path(), &key.to_string()).to_string())
            }
        };

        Ok(Self {
            key,
            link,
            document,
            inner,
        })
    }

    /// Returns this pre-commit config's [`SymbolicLocation`].
    ///
    /// See [`Workflow::location`] for an explanation of why this isn't
    /// implemented through the [`Locatable`] trait.
    pub(crate) fn location(&self) -> SymbolicLocation<'_> {
        SymbolicLocation {
            key: &self.key,
            annotation: "this pre-commit config".into(),
            link: None,
            route: Default::default(),
            feature_kind: SymbolicFeature::Normal,
            kind: Default::default(),
        }
    }

    pub(crate) fn repos(&self) -> Repos<'_> {
        Repos::new(self)
    }
}

/// An iterable container for repositories within a [`PreCommitConfig`].
pub(crate) struct Repos<'doc> {
    parent: &'doc PreCommitConfig,
    inner: std::iter::Enumerate<std::slice::Iter<'doc, pre_commit_models::config::Repo>>,
}

impl<'doc> Repos<'doc> {
    pub(crate) fn new(config: &'doc PreCommitConfig) -> Self {
        Self {
            parent: config,
            inner: config.repos.iter().enumerate(),
        }
    }
}

impl<'doc> Iterator for Repos<'doc> {
    type Item = Repo<'doc>;

    fn next(&mut self) -> Option<Self::Item> {
        let (idx, inner) = self.inner.next()?;

        Some(Repo::new(idx, inner, &self.parent))
    }
}

pub(crate) struct Repo<'doc> {
    index: usize,
    inner: &'doc pre_commit_models::config::Repo,
    parent: &'doc PreCommitConfig,
}

impl<'doc> Repo<'doc> {
    fn new(
        index: usize,
        inner: &'doc pre_commit_models::config::Repo,
        parent: &'doc PreCommitConfig,
    ) -> Self {
        Self {
            index,
            inner,
            parent,
        }
    }
}

impl<'doc> Locatable<'doc> for Repo<'doc> {
    fn location(&self) -> SymbolicLocation<'doc> {
        self.parent
            .location()
            .with_keys(["repos".into(), self.index.into()])
            .annotated("this repo")
    }

    fn location_with_grip(&self) -> SymbolicLocation<'doc> {
        self.location().with_keys(["repo".into()])
    }
}

pub(crate) struct PreCommitHooks {
    pub(crate) key: InputKey,
    pub(crate) link: Option<String>,
    document: yamlpath::Document,
    inner: pre_commit_models::hooks::Hooks,
}

impl<'de> Validatable<'de> for PreCommitHooks {
    type Target = pre_commit_models::hooks::Hooks;

    type Skeleton = yaml_serde::Sequence;

    fn validator() -> &'static jsonschema::Validator {
        &PRE_COMMIT_HOOKS_VALIDATOR
    }
}

impl<'a> AsDocument<'a, 'a> for PreCommitHooks {
    fn as_document(&'a self) -> &'a yamlpath::Document {
        &self.document
    }
}

impl std::ops::Deref for PreCommitHooks {
    type Target = pre_commit_models::hooks::Hooks;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl std::fmt::Debug for PreCommitHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{key}", key = self.key)
    }
}

impl PreCommitHooks {
    pub(crate) fn from_string(contents: String, key: InputKey) -> Result<Self, CollectionError> {
        let inner = Self::validate(&contents)?;

        let document = yamlpath::Document::new(&contents)?;

        let link = match key {
            InputKey::Local(_) | InputKey::Stdin(_) => None,
            InputKey::Remote(_) => {
                // NOTE: InputKey's Display produces a URL, hence `key.to_string()`.
                Some(Link::new(key.presentation_path(), &key.to_string()).to_string())
            }
        };

        Ok(Self {
            key,
            link,
            document,
            inner,
        })
    }

    /// Returns this pre-commit config's [`SymbolicLocation`].
    ///
    /// See [`Workflow::location`] for an explanation of why this isn't
    /// implemented through the [`Locatable`] trait.
    pub(crate) fn location(&self) -> SymbolicLocation<'_> {
        SymbolicLocation {
            key: &self.key,
            annotation: "this pre-commit hooks definition".into(),
            link: None,
            route: Default::default(),
            feature_kind: SymbolicFeature::Normal,
            kind: Default::default(),
        }
    }
}
