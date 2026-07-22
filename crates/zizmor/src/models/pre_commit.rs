//! Pre-commit models.
//!
//! These models enrich the models under [`pre_commit_models`],
//! providing higher-level APIs for zizmor to use.

use terminal_link::Link;

use crate::{
    finding::location::{SymbolicFeature, SymbolicLocation},
    models::AsDocument,
    registry::input::{CollectionError, InputKey},
};

pub(crate) struct PreCommitConfig {
    pub(crate) key: InputKey,
    pub(crate) link: Option<String>,
    document: yamlpath::Document,
    inner: pre_commit_models::config::Config,
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
        // TODO: `from_str_with_validation` here.
        let inner = yaml_serde::from_str(&contents)?;

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
}

pub(crate) struct PreCommitHooks {
    pub(crate) key: InputKey,
    pub(crate) link: Option<String>,
    document: yamlpath::Document,
    inner: pre_commit_models::hooks::Hooks,
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
        // TODO: `from_str_with_validation` here.
        let inner = yaml_serde::from_str(&contents)?;

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
