//! Dependabot config models.
//!
//! These models enrich the models under [`github_actions_models::dependabot`],
//! providing higher-level APIs for zizmor to use.

use std::sync::LazyLock;

use github_actions_models::dependabot;
use terminal_link::Link;

use crate::{
    finding::location::{Locatable, SymbolicFeature, SymbolicLocation},
    models::{AsDocument, Validatable},
    registry::input::{CollectionError, InputKey},
};

static DEPENDABOT_VALIDATOR: LazyLock<jsonschema::Validator> = LazyLock::new(|| {
    jsonschema::validator_for(
        &serde_json::from_str(include_str!("../data/dependabot-2.0.json"))
            .expect("internal error: compiled asset not JSON?"),
    )
    .expect("internal error: failed to load dependabot schema")
});

pub(crate) struct Dependabot {
    pub(crate) key: InputKey,
    pub(crate) link: Option<String>,
    document: yamlpath::Document,
    inner: dependabot::v2::Dependabot,
}

impl<'de> Validatable<'de> for Dependabot {
    type Target = dependabot::v2::Dependabot;

    type Skeleton = yaml_serde::Mapping;

    fn validator() -> &'static jsonschema::Validator {
        &DEPENDABOT_VALIDATOR
    }
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

    /// Returns this Dependabot config's [`SymbolicLocation`].
    ///
    /// See [`Workflow::location`] for an explanation of why this isn't
    /// implemented through the [`Locatable`] trait.
    pub(crate) fn location(&self) -> SymbolicLocation<'_> {
        SymbolicLocation {
            key: &self.key,
            annotation: "this config".into(),
            link: None,
            route: Default::default(),
            feature_kind: SymbolicFeature::Normal,
            kind: Default::default(),
        }
    }

    pub(crate) fn updates(&self) -> Updates<'_> {
        Updates::new(self)
    }
}

pub(crate) struct Updates<'doc> {
    parent: &'doc Dependabot,
    inner:
        std::iter::Enumerate<std::slice::Iter<'doc, github_actions_models::dependabot::v2::Update>>,
}

impl<'doc> Updates<'doc> {
    fn new(parent: &'doc Dependabot) -> Self {
        Self {
            parent,
            inner: parent.inner.updates.iter().enumerate(),
        }
    }
}

impl<'doc> Iterator for Updates<'doc> {
    type Item = Update<'doc>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(idx, update)| Update {
            parent: self.parent,
            index: idx,
            inner: update,
        })
    }
}

pub(crate) struct Update<'doc> {
    parent: &'doc Dependabot,
    index: usize,
    inner: &'doc github_actions_models::dependabot::v2::Update,
}

impl<'doc> std::ops::Deref for Update<'doc> {
    type Target = github_actions_models::dependabot::v2::Update;

    fn deref(&self) -> &Self::Target {
        self.inner
    }
}

impl<'doc> Locatable<'doc> for Update<'doc> {
    fn location(&self) -> SymbolicLocation<'doc> {
        self.parent
            .location()
            .with_keys(["updates".into(), self.index.into()])
            .annotated("this update rule")
    }

    fn location_with_grip(&self) -> SymbolicLocation<'doc> {
        self.location()
            .with_keys(["package-ecosystem".into()])
            .annotated("this ecosystem")
    }
}
