//! Common interfaces for modeling inputs across both workflows and actions.

use crate::finding::location::{Locatable, SymbolicLocation};
use github_actions_expressions::{
    Evaluation,
    evaluation::{
        AbstractValue, AlternativeId, Evaluator, Outcome, Outcomes, OutcomesExt as _, Shape,
        Source, TrackedValue,
    },
};
use github_actions_models::workflow::event::{
    BareEvent, OptionalBody, WorkflowCall, WorkflowCallInputType, WorkflowDispatch,
    WorkflowDispatchInputType,
};
use indexmap::IndexMap;

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
    Call(&'doc Workflow, &'doc WorkflowCall),
    Dispatch(&'doc Workflow, &'doc WorkflowDispatch),
    Empty,
}

impl Workflow {
    pub(super) fn input_declarations(&self) -> impl Iterator<Item = WorkflowInputs<'_>> {
        let events = &self.on.events;
        let call = match &events.workflow_call {
            OptionalBody::Body(call) => Some(WorkflowInputs::Call(self, call)),
            _ => None,
        };
        let dispatch = match &events.workflow_dispatch {
            OptionalBody::Body(dispatch) => Some(WorkflowInputs::Dispatch(self, dispatch)),
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
            .filter_map(|inputs| inputs.get(name).map(|input| input.capability()))
            .reduce(Capability::unify)
    }
}

impl<'doc> WorkflowInputs<'doc> {
    pub(super) fn names(self) -> Box<dyn Iterator<Item = &'doc String> + 'doc> {
        match self {
            Self::Call(_, call) => Box::new(call.inputs.keys()),
            Self::Dispatch(_, dispatch) => Box::new(dispatch.inputs.keys()),
            Self::Empty => Box::new(std::iter::empty()),
        }
    }

    /// Look up a declared input using Actions' case-insensitive property access.
    pub(super) fn get(self, name: &str) -> Option<InputDeclaration<'doc>> {
        fn lookup<'a, T>(
            inputs: &'a IndexMap<String, T>,
            name: &str,
        ) -> Option<(&'a String, &'a T)> {
            inputs
                .iter()
                .rev()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
        }

        let (workflow, name, kind) = match self {
            Self::Call(workflow, call) => {
                let (name, input) = lookup(&call.inputs, name)?;
                (workflow, name, InputType::Call(&input.r#type))
            }
            Self::Dispatch(workflow, dispatch) => {
                let (name, input) = lookup(&dispatch.inputs, name)?;
                (workflow, name, InputType::Dispatch(&input.r#type))
            }
            Self::Empty => return None,
        };
        Some(InputDeclaration {
            workflow,
            name,
            kind,
        })
    }
}

enum InputType<'doc> {
    Call(&'doc WorkflowCallInputType),
    Dispatch(&'doc WorkflowDispatchInputType),
}

pub(super) struct InputDeclaration<'doc> {
    workflow: &'doc Workflow,
    pub(super) name: &'doc str,
    kind: InputType<'doc>,
}

impl InputDeclaration<'_> {
    /// Possible values of this input for one invocation. Repeated reads use
    /// the same decision for the two values of a declared boolean.
    pub(super) fn values(&self, eval: &mut Evaluator) -> Outcomes {
        use WorkflowCallInputType as Call;
        use WorkflowDispatchInputType as Dispatch;
        let values = match self.kind {
            InputType::Call(Call::Boolean) | InputType::Dispatch(Dispatch::Boolean) => {
                let decision = eval.decision();
                [false, true]
                    .into_iter()
                    .filter_map(|flag| {
                        Outcome::known(Evaluation::Boolean(flag))
                            .assume(decision, AlternativeId::new(usize::from(flag)))
                    })
                    .collect()
            }
            InputType::Call(Call::Number) | InputType::Dispatch(Dispatch::Number) => {
                vec![Outcome::new(TrackedValue::new(AbstractValue::Unknown(
                    Shape::Number,
                )))]
            }
            InputType::Call(Call::String)
            | InputType::Dispatch(Dispatch::String | Dispatch::Choice | Dispatch::Environment) => {
                vec![Outcome::new(TrackedValue::new(AbstractValue::Unknown(
                    Shape::String,
                )))]
            }
        };
        let source = Source::new(format!("inputs.{}", self.name));
        values.map(|mut value| {
            value.provenance.sources.insert(source.clone());
            value
        })
    }

    fn capability(&self) -> Capability {
        use WorkflowCallInputType as Call;
        use WorkflowDispatchInputType as Dispatch;
        match self.kind {
            InputType::Call(Call::String) | InputType::Dispatch(Dispatch::String) => {
                Capability::Arbitrary
            }
            InputType::Call(Call::Boolean | Call::Number)
            | InputType::Dispatch(
                Dispatch::Boolean | Dispatch::Number | Dispatch::Choice | Dispatch::Environment,
            ) => Capability::Fixed,
        }
    }
}

impl<'doc> Locatable<'doc> for InputDeclaration<'doc> {
    fn location(&self) -> SymbolicLocation<'doc> {
        let event = match self.kind {
            InputType::Call(_) => BareEvent::WorkflowCall,
            InputType::Dispatch(_) => BareEvent::WorkflowDispatch,
        };
        self.workflow
            .location()
            .with_keys([
                "on".into(),
                event.as_str().into(),
                "inputs".into(),
                self.name.into(),
            ])
            .key_only()
    }
}
