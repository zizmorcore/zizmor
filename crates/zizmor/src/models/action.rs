//! GitHub Actions composite action models.
//!
//! These models enrich the models under [`github_actions_models::action`],
//! providing higher-level APIs for zizmor to use.

use anyhow::Context;
use github_actions_expressions::context;
use github_actions_models::{action, common, workflow::job::Strategy};
use terminal_link::Link;

use crate::{
    InputKey,
    finding::location::{Locatable, Route, SymbolicFeature, SymbolicLocation},
    models::{
        AsDocument, StepBodyCommon, StepCommon,
        inputs::{Capability, HasInputs},
    },
    registry::InputError,
    utils::{self, ACTION_VALIDATOR, from_str_with_validation},
};

/// Represents an entire (composite) action.
///
/// This type implements [`Deref`] for [`action::Action`], providing
/// access to the underlying data model.
pub(crate) struct Action {
    /// This action's unique key into zizmor's runtime registry.
    pub(crate) key: InputKey,
    pub(crate) link: Option<String>,
    document: yamlpath::Document,
    inner: action::Action,
}

impl<'a> AsDocument<'a, 'a> for Action {
    fn as_document(&'a self) -> &'a yamlpath::Document {
        &self.document
    }
}

impl std::ops::Deref for Action {
    type Target = action::Action;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl std::fmt::Debug for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{key}", key = self.key)
    }
}

impl HasInputs for Action {
    fn get_input(&self, name: &str) -> Option<Capability> {
        // Action inputs are always arbitrary strings.
        self.inputs.get(name).map(|_| Capability::Arbitrary)
    }
}

impl Action {
    /// Load an action from a buffer, with an assigned name.
    pub(crate) fn from_string(contents: String, key: InputKey) -> Result<Self, InputError> {
        let inner = from_str_with_validation(&contents, &ACTION_VALIDATOR)?;

        let document = yamlpath::Document::new(&contents)
            .context("failed to load internal pathing document")?;

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

    /// Returns a [`CompositeSteps`] iterator over this actions's constituent
    /// [`CompositeStep`]s, or `None` if the action is not a composite action.
    pub(crate) fn steps(&self) -> Option<CompositeSteps<'_>> {
        CompositeSteps::new(self)
    }

    /// Returns this action's [`SymbolicLocation`].
    ///
    /// See [`Workflow::location`] for an explanation of why this isn't
    /// implemented through the [`Locatable`] trait.
    pub(crate) fn location(&self) -> SymbolicLocation<'_> {
        SymbolicLocation {
            key: &self.key,
            annotation: "this action".to_string(),
            link: None,
            route: Route::new(),
            feature_kind: SymbolicFeature::Normal,
            kind: Default::default(),
        }
    }
}

/// An iterable container for steps within a [`Job`].
pub(crate) struct CompositeSteps<'a> {
    inner: std::iter::Enumerate<std::slice::Iter<'a, github_actions_models::action::Step>>,
    parent: &'a Action,
}

impl<'a> CompositeSteps<'a> {
    /// Create a new [`CompositeSteps`], or `None` if the action is not a composite action.
    fn new(action: &'a Action) -> Option<Self> {
        match &action.inner.runs {
            action::Runs::Composite(composite) => Some(Self {
                inner: composite.steps.iter().enumerate(),
                parent: action,
            }),
            _ => None,
        }
    }
}

impl<'a> Iterator for CompositeSteps<'a> {
    type Item = CompositeStep<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.inner.next();

        match item {
            Some((idx, step)) => Some(CompositeStep::new(idx, step, self.parent)),
            None => None,
        }
    }
}

pub(crate) struct CompositeStep<'a> {
    /// The step's index within its parent job.
    pub(crate) index: usize,
    /// The inner step model.
    pub(crate) inner: &'a action::Step,
    /// The parent [`Action`].
    pub(crate) parent: &'a Action,
}

impl<'a> std::ops::Deref for CompositeStep<'a> {
    type Target = &'a action::Step;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'doc> Locatable<'doc> for CompositeStep<'doc> {
    fn location(&self) -> SymbolicLocation<'doc> {
        self.parent.location().annotated("this step").with_keys(&[
            "runs".into(),
            "steps".into(),
            self.index.into(),
        ])
    }

    fn location_with_name(&self) -> SymbolicLocation<'doc> {
        match self.inner.name {
            Some(_) => self.location().with_keys(&["name".into()]),
            None => self.location(),
        }
    }
}

impl HasInputs for CompositeStep<'_> {
    fn get_input(&self, name: &str) -> Option<Capability> {
        self.parent.get_input(name)
    }
}

impl<'doc> StepCommon<'doc> for CompositeStep<'doc> {
    fn index(&self) -> usize {
        self.index
    }

    fn env_is_static(&self, ctx: &context::Context) -> bool {
        utils::env_is_static(ctx, &[&self.env])
    }

    fn uses(&self) -> Option<&common::Uses> {
        let action::StepBody::Uses { uses, .. } = &self.inner.body else {
            return None;
        };

        Some(uses)
    }

    fn strategy(&self) -> Option<&Strategy> {
        None
    }

    fn body(&self) -> StepBodyCommon<'doc> {
        match &self.body {
            action::StepBody::Uses { uses, with } => StepBodyCommon::Uses { uses, with },
            action::StepBody::Run {
                run,
                working_directory,
                shell,
            } => StepBodyCommon::Run {
                run,
                _working_directory: working_directory.as_deref(),
                _shell: Some(shell),
            },
        }
    }

    fn document(&self) -> &'doc yamlpath::Document {
        self.action().as_document()
    }
}

impl<'a> CompositeStep<'a> {
    pub(crate) fn new(index: usize, inner: &'a action::Step, parent: &'a Action) -> Self {
        Self {
            index,
            inner,
            parent,
        }
    }

    /// Returns this composite step's parent [`Action`].
    pub(crate) fn action(&self) -> &'a Action {
        self.parent
    }
}
