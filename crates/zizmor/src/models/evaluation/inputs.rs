//! A run gets its input declarations from one trigger.
use super::*;
use crate::models::workflow::Workflow;
use github_actions_models::workflow::event::{
    OptionalBody, WorkflowCallInputType, WorkflowDispatchInputType,
};

pub(super) fn environments<'doc>(
    workflow: Option<&'doc Workflow>,
    eval: &mut Evaluator,
    results: &mut Results<'doc>,
) -> Vec<BTreeMap<String, Outcomes>> {
    let Some(workflow) = workflow else {
        return vec![BTreeMap::new()];
    };
    let events = &workflow.on.events;
    let mut environments = Vec::new();
    if let OptionalBody::Body(call) = &events.workflow_call {
        environments.push(declared(
            workflow,
            "workflow_call",
            &call.inputs,
            |input| matches!(input.r#type, WorkflowCallInputType::Boolean),
            eval,
            results,
        ));
    }
    if let OptionalBody::Body(dispatch) = &events.workflow_dispatch {
        environments.push(declared(
            workflow,
            "workflow_dispatch",
            &dispatch.inputs,
            |input| matches!(input.r#type, WorkflowDispatchInputType::Boolean),
            eval,
            results,
        ));
    }
    if environments.len() < events.count() as usize || environments.is_empty() {
        environments.push(BTreeMap::new());
    }
    environments
}

fn declared<'doc, T>(
    workflow: &'doc Workflow,
    event: &'static str,
    inputs: &'doc IndexMap<String, T>,
    boolean: impl Fn(&T) -> bool,
    eval: &mut Evaluator,
    results: &mut Results<'doc>,
) -> BTreeMap<String, Outcomes> {
    inputs
        .iter()
        .map(|(name, input)| {
            let mut values = if boolean(input) {
                let decision = eval.decision();
                [false, true]
                    .into_iter()
                    .filter_map(|flag| {
                        Outcome::known(Evaluation::Boolean(flag))
                            .assume(decision, AlternativeId::new(usize::from(flag)))
                    })
                    .collect()
            } else {
                vec![Outcome::new(TrackedValue::unknown())]
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
            let id = results.record(location);
            for outcome in &mut values {
                outcome
                    .value
                    .provenance
                    .sources
                    .insert(format!("inputs.{name}"));
                outcome.value.provenance.evidence.insert(id);
            }
            (name.to_ascii_lowercase(), values)
        })
        .collect()
}
