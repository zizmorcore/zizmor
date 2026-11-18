//! Each input declaration belongs to one trigger. Selecting the namespace
//! once keeps reads of different inputs consistent within a run.
use super::*;
use crate::models::workflow::Workflow;
use github_actions_models::workflow::event::{
    OptionalBody, WorkflowCallInputType, WorkflowDispatchInputType,
};
use indexmap::IndexMap;

impl<'doc> Builder<'doc> {
    pub(super) fn inputs(&mut self, workflow: &'doc Workflow) -> Definition {
        let events = &workflow.on.events;
        let mut triggers = Vec::new();
        if let OptionalBody::Body(call) = &events.workflow_call {
            triggers.push(
                self.input_scope(workflow, "workflow_call", &call.inputs, |input| {
                    matches!(input.r#type, WorkflowCallInputType::Boolean)
                }),
            );
        }
        if let OptionalBody::Body(dispatch) = &events.workflow_dispatch {
            triggers.push(self.input_scope(
                workflow,
                "workflow_dispatch",
                &dispatch.inputs,
                |input| matches!(input.r#type, WorkflowDispatchInputType::Boolean),
            ));
        }
        if triggers.len() < events.count() as usize || triggers.is_empty() {
            triggers.push(Definition::namespace(
                Scope::new(Definition::runtime(String::new())).with_missing(empty()),
            ));
        }
        if triggers.len() == 1 {
            triggers.pop().expect("one trigger")
        } else {
            Definition::choice(triggers)
        }
    }

    fn input_scope<T>(
        &mut self,
        workflow: &'doc Workflow,
        event: &'static str,
        inputs: &'doc IndexMap<String, T>,
        is_boolean: impl Fn(&T) -> bool,
    ) -> Definition {
        let mut scope = Scope::new(Definition::runtime(String::new())).with_missing(empty());
        for (name, input) in inputs {
            let sourced = |mut value: TrackedValue| {
                value.provenance.sources.insert(format!("inputs.{name}"));
                Definition::value(value)
            };
            let value = if is_boolean(input) {
                Definition::choice(
                    [false, true]
                        .into_iter()
                        .map(|flag| sourced(TrackedValue::known(Evaluation::Boolean(flag))))
                        .collect(),
                )
            } else {
                sourced(TrackedValue::unknown())
            };
            let location = workflow
                .location()
                .with_keys([
                    "on".into(),
                    event.into(),
                    "inputs".into(),
                    name.as_str().into(),
                ])
                .key_only()
                .annotated(format!("input {name} declared here"));
            scope.bind(name, value.located(self.record(location)));
        }
        Definition::namespace(scope)
    }
}
