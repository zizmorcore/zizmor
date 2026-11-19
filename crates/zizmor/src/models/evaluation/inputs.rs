//! A run gets its input declarations from one trigger.
use super::*;
use crate::models::{inputs::InputDeclaration, workflow::Workflow};

pub(super) fn environments<'doc>(
    workflow: Option<&'doc Workflow>,
    eval: &mut Evaluator,
    results: &mut Evidence<'doc>,
) -> Vec<BTreeMap<String, Outcomes>> {
    let Some(workflow) = workflow else {
        return vec![BTreeMap::new()];
    };
    workflow
        .input_declarations()
        .map(|inputs| {
            inputs
                .declarations(workflow)
                .into_iter()
                .map(|input| (input.name.to_ascii_lowercase(), input.values(eval, results)))
                .collect()
        })
        .collect()
}

impl<'doc> InputDeclaration<'doc> {
    fn values(self, eval: &mut Evaluator, evidence: &mut Evidence<'doc>) -> Outcomes {
        let name = self.name;
        let mut values = if self.boolean {
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
        let id = evidence.record(
            self.location
                .annotated(format!("input {name} declared here")),
        );
        for outcome in &mut values {
            outcome
                .value
                .provenance
                .sources
                .insert(Source::new(format!("inputs.{name}")));
            outcome.value.provenance.evidence.insert(id);
        }
        values
    }
}
