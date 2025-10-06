//! Dependabot config models.
//!
//! These models enrich the models under [`github_actions_models::dependabot`],
//! providing higher-level APIs for zizmor to use.

use github_actions_models::dependabot;
use terminal_link::Link;

use crate::{
    finding::location::{SymbolicFeature, SymbolicLocation},
    models::AsDocument,
    registry::input::{CollectionError, InputKey},
    utils::{DEPENDABOT_VALIDATOR, from_str_with_validation},
};

pub(crate) struct Dependabot {
    pub(crate) key: InputKey,
    pub(crate) link: Option<String>,
    document: yamlpath::Document,
    inner: dependabot::v2::Dependabot,
}

impl<'a> AsDocument<'a, 'a> for Dependabot {
    fn as_document(&'a self) -> &'a yamlpath::Document {
        &self.document
    }
}

impl std::ops::Deref for Dependabot {
    type Target = dependabot::v2::Dependabot;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl std::fmt::Debug for Dependabot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{key}", key = self.key)
    }
}

impl Dependabot {
    pub(crate) fn from_string(contents: String, key: InputKey) -> Result<Self, CollectionError> {
        let inner = from_str_with_validation(&contents, &DEPENDABOT_VALIDATOR)?;

        let document = yamlpath::Document::new(&contents)?;

        let link = match key {
            InputKey::Local(_) => None,
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

    /// Returns this Dependabot config's [`SymbolicLocation`].
    ///
    /// See [`Workflow::location`] for an explanation of why this isn't
    /// implemented through the [`Locatable`] trait.
    pub(crate) fn location(&self) -> SymbolicLocation<'_> {
        SymbolicLocation {
            key: &self.key,
            annotation: "this config".to_string(),
            link: None,
            route: Default::default(),
            feature_kind: SymbolicFeature::Normal,
            kind: Default::default(),
        }
    }
}
