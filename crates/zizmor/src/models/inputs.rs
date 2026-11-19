//! Common interfaces for modeling inputs across both workflows and actions.

use crate::finding::location::SymbolicLocation;
use github_actions_models::workflow::event::{
    BareEvent, OptionalBody, WorkflowCall, WorkflowCallInputType, WorkflowDispatch,
    WorkflowDispatchInputType,
};

use super::workflow::Workflow;

/// Represents the "capability" of an (input) value, i.e. how it expands.
///
/// This is shared by both inputs and contexts more generally, the latter
/// in the setting of the `template-injection` audit.
#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum Capability {
    /// The value's expansion is fully arbitrary, e.g. arbitrary code.
    Arbitrary,
    /// The value's expansion is structured, i.e. partially controlled
    /// by the user, but fully controlled.
    ///
    /// An example of a structured value would be one with a fixed prefix:
    /// the value might be `prefix-${{ foo }}`, where the user can control
    /// the `${{ foo }}` part, but not the `prefix-` part.
    Structured,
    /// The value's expansion is fully fixed, i.e. not controlled by the user.
    ///
    /// The user might control the *choice* of the value, but not its
    /// contents. For example, a choice-style input has multiple chooseable
    /// values, but the user cannot control the contents of those values.
    Fixed,
}

impl Capability {
    /// Unify two capabilities in favor of the more permissive one.
    pub(crate) fn unify(self, other: Self) -> Self {
        match (self, other) {
            (Self::Arbitrary, _) | (_, Self::Arbitrary) => Self::Arbitrary,
            (Self::Structured, _) | (_, Self::Structured) => Self::Structured,
            _ => self,
        }
    }
}

/// A trait for types that have inputs, such as workflows and actions.
pub(crate) trait HasInputs {
    fn get_input(&self, name: &str) -> Option<Capability>;
}

/// The declarations visible to a single workflow run. Triggers without
/// declarations share the empty input set.
#[derive(Clone, Copy)]
pub(super) enum WorkflowInputs<'doc> {
    Call(&'doc WorkflowCall),
    Dispatch(&'doc WorkflowDispatch),
    Empty,
}

impl Workflow {
    pub(super) fn input_declarations(&self) -> impl Iterator<Item = WorkflowInputs<'_>> {
        let events = &self.on.events;
        let call = match &events.workflow_call {
            OptionalBody::Body(call) => Some(WorkflowInputs::Call(call)),
            _ => None,
        };
        let dispatch = match &events.workflow_dispatch {
            OptionalBody::Body(dispatch) => Some(WorkflowInputs::Dispatch(dispatch)),
            _ => None,
        };
        let declared = u32::from(call.is_some()) + u32::from(dispatch.is_some());
        let empty = declared == 0 || declared < events.count();
        [call, dispatch, empty.then_some(WorkflowInputs::Empty)]
            .into_iter()
            .flatten()
    }
}

impl HasInputs for Workflow {
    fn get_input(&self, name: &str) -> Option<Capability> {
        self.input_declarations()
            .filter_map(|inputs| inputs.capability(name))
            .reduce(Capability::unify)
    }
}

impl<'doc> WorkflowInputs<'doc> {
    fn capability(self, name: &str) -> Option<Capability> {
        let arbitrary = match self {
            Self::Call(call) => {
                matches!(call.inputs.get(name)?.r#type, WorkflowCallInputType::String)
            }
            Self::Dispatch(dispatch) => matches!(
                dispatch.inputs.get(name)?.r#type,
                WorkflowDispatchInputType::String
            ),
            Self::Empty => return None,
        };
        Some(if arbitrary {
            Capability::Arbitrary
        } else {
            Capability::Fixed
        })
    }

    pub(super) fn declarations(self, workflow: &'doc Workflow) -> Vec<InputDeclaration<'doc>> {
        let declaration = |event: BareEvent, name: &'doc str, boolean| InputDeclaration {
            name,
            boolean,
            location: workflow
                .location()
                .with_keys([
                    "on".into(),
                    event.as_str().into(),
                    "inputs".into(),
                    name.into(),
                ])
                .key_only(),
        };
        match self {
            Self::Call(call) => call
                .inputs
                .iter()
                .map(|(name, input)| {
                    declaration(
                        BareEvent::WorkflowCall,
                        name,
                        matches!(input.r#type, WorkflowCallInputType::Boolean),
                    )
                })
                .collect(),
            Self::Dispatch(dispatch) => dispatch
                .inputs
                .iter()
                .map(|(name, input)| {
                    declaration(
                        BareEvent::WorkflowDispatch,
                        name,
                        matches!(input.r#type, WorkflowDispatchInputType::Boolean),
                    )
                })
                .collect(),
            Self::Empty => vec![],
        }
    }
}

pub(super) struct InputDeclaration<'doc> {
    pub(super) name: &'doc str,
    pub(super) boolean: bool,
    pub(super) location: SymbolicLocation<'doc>,
}
