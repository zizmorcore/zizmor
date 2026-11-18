//! Resolve named inputs against the declarations for each workflow trigger.

use github_actions_models::workflow::event::{
    OptionalBody, WorkflowCallInputType, WorkflowDispatchInputType,
};
use indexmap::IndexMap;

use super::*;
use crate::models::workflow::Workflow;

impl<'doc> Bindings<'doc> {
    pub(super) fn input(
        &mut self,
        state: &mut State,
        workflow: &'doc Workflow,
        name: &str,
    ) -> Outcomes {
        let name = name.to_ascii_lowercase();
        if let Some(values) = self.inputs.get(&name) {
            return values.clone();
        }

        let events = &workflow.on.events;
        let location = |event: &'static str| {
            workflow
                .location()
                .with_keys(["on".into(), event.into(), "inputs".into()])
        };
        let boolean = state.decision();
        let mut triggers = Vec::new();
        if let OptionalBody::Body(call) = &events.workflow_call {
            triggers.push(self.declared_input(
                &call.inputs,
                &name,
                location("workflow_call"),
                boolean,
                |input| matches!(input.r#type, WorkflowCallInputType::Boolean),
            ));
        }
        if let OptionalBody::Body(dispatch) = &events.workflow_dispatch {
            triggers.push(self.declared_input(
                &dispatch.inputs,
                &name,
                location("workflow_dispatch"),
                boolean,
                |input| matches!(input.r#type, WorkflowDispatchInputType::Boolean),
            ));
        }

        let missing = || vec![Outcome::known(Evaluation::String(String::new()))];
        if triggers.iter().all(Option::is_none) {
            return missing();
        }
        // All other triggers, including a bare workflow_dispatch, have no inputs.
        if triggers.len() < events.count() as usize {
            triggers.push(None);
        }

        // Keep trigger indices stable across names. A run cannot mix inputs
        // from the workflow_call and workflow_dispatch declarations.
        let trigger = *self.input_trigger.get_or_insert_with(|| state.decision());
        let mut values = Vec::new();
        for (index, declared) in triggers.into_iter().enumerate() {
            for mut outcome in declared.unwrap_or_else(missing) {
                outcome.choices.insert(trigger, AlternativeId::new(index));
                values.push(outcome);
            }
        }
        self.inputs.insert(name, values.clone());
        values
    }

    fn declared_input<T>(
        &mut self,
        inputs: &'doc IndexMap<String, T>,
        name: &str,
        location: SymbolicLocation<'doc>,
        boolean: DecisionId,
        is_boolean: impl FnOnce(&T) -> bool,
    ) -> Option<Outcomes> {
        let (key, input) = inputs
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))?;
        let mut values = if is_boolean(input) {
            [false, true]
                .into_iter()
                .map(|value| {
                    let mut outcome = Outcome::known(Evaluation::Boolean(value));
                    outcome
                        .choices
                        .insert(boolean, AlternativeId::new(usize::from(value)));
                    outcome
                })
                .collect()
        } else {
            vec![Outcome::new(TrackedValue::unknown())]
        };

        for outcome in &mut values {
            outcome
                .value
                .provenance
                .sources
                .insert(format!("inputs.{key}"));
        }
        let location = location
            .with_keys([key.as_str().into()])
            .key_only()
            .annotated(format!("input {key} declared here"));
        Some(self.explain(values, location))
    }
}
