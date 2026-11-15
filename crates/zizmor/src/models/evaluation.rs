//! Resolve workflow expressions and record where their inputs were defined.

use github_actions_expressions::evaluation::*;
use std::{collections::BTreeSet, sync::Arc};

use crate::{finding::location::SymbolicLocation, utils::extract_fenced_expressions};
use github_actions_expressions::{
    Evaluation, Expr, Origin, SpannedExpr,
    call::{Call, Function},
};

use super::workflow::NormalJob;

#[derive(Clone, Default)]
pub(crate) struct Context<'doc> {
    job: Option<NormalJob<'doc>>,
}

/// Workflow bindings and source locations for one evaluation.
#[derive(Default)]
pub(crate) struct Analysis<'doc> {
    state: State,
    evidence: Vec<SymbolicLocation<'doc>>,
}

impl<'doc> Analysis<'doc> {
    pub(crate) fn locations<'a>(
        &self,
        outcomes: impl IntoIterator<Item = &'a Outcome>,
    ) -> Vec<SymbolicLocation<'doc>> {
        let ids = outcomes
            .into_iter()
            .flat_map(|outcome| outcome.value.dependencies().evidence)
            .collect::<BTreeSet<_>>();
        ids.into_iter()
            .map(|id| self.evidence[id].clone())
            .collect()
    }

    fn template(&mut self, text: &str, context: &Context<'doc>) -> Outcomes {
        if !text.contains("${{") {
            return vec![Outcome::known(Evaluation::String(text.into()))];
        }

        let escape = |literal: &str| literal.replace('{', "{{").replace('}', "}}");
        let mut format = String::new();
        let mut args = vec![];
        let mut offset = 0;
        for (expression, span) in extract_fenced_expressions(text) {
            let parsed = match Expr::parse(expression.as_bare()) {
                Ok(parsed) => parsed,
                Err(github_actions_expressions::Error::Depth) => {
                    return vec![Outcome::new(TrackedValue::incomplete())];
                }
                Err(_) => return Outcomes::default(),
            };
            if span == (0..text.len()) {
                return parsed.evaluate(self, context);
            }
            format.push_str(&escape(&text[offset..span.start]));
            format.push_str(&format!("{{{}}}", args.len()));
            args.push(parsed);
            offset = span.end;
        }
        if text[offset..].contains("${{") {
            return Outcomes::default();
        }

        // Use format for interpolation so arguments retain their sources.
        format.push_str(&escape(&text[offset..]));
        let synthetic = |inner| SpannedExpr {
            inner,
            origin: Origin::new(0..0, ""),
        };
        args.insert(0, synthetic(Expr::from(format)));
        synthetic(Expr::Call(Call {
            func: Function::Format,
            args,
        }))
        .evaluate(self, context)
    }

    fn explain(&mut self, values: Outcomes, location: SymbolicLocation<'doc>) -> Outcomes {
        let id = self.evidence.len();
        self.evidence.push(location);
        values.map(|mut value| {
            value.provenance.evidence.insert(id);
            value
        })
    }

    fn runtime(&self, path: &[Access], _context: &Context<'doc>) -> Outcomes {
        let root = path[0].text();
        if root.eq_ignore_ascii_case("github") {
            return vec![Outcome::new(TrackedValue::new(AbstractValue::Reference(
                path.to_vec(),
            )))];
        }

        let mut value = TrackedValue::unknown();
        let identity = path.iter().map(Access::text).collect::<Vec<_>>().join(".");
        value.provenance.sources.insert(identity);
        vec![Outcome::new(value)]
    }
}

impl<'doc> Resolver for Analysis<'doc> {
    type Scope = Context<'doc>;

    fn state(&mut self) -> &mut State {
        &mut self.state
    }

    fn resolve(&mut self, path: &[Access], context: &Context<'doc>) -> Outcomes {
        self.runtime(path, context)
    }
}

impl<'doc> Analysis<'doc> {
    /// Evaluate expressions throughout a field, retaining its native types and locations.
    pub(crate) fn definition(
        &mut self,
        value: &serde_json::Value,
        location: SymbolicLocation<'doc>,
        context: &Context<'doc>,
    ) -> Outcomes {
        let values = self.decode(value, location, context);
        self.state.finish(values)
    }

    fn decode(
        &mut self,
        value: &serde_json::Value,
        location: SymbolicLocation<'doc>,
        context: &Context<'doc>,
    ) -> Outcomes {
        if !self.state.checkpoint() {
            return Outcomes::default();
        }
        let entries: Vec<_> = match value {
            serde_json::Value::String(text) => {
                let values = self.template(text, context);
                return self.explain(values, location);
            }
            serde_json::Value::Array(values) => values
                .iter()
                .enumerate()
                .map(|(index, value)| (value, location.with_keys([index.into()])))
                .collect(),
            serde_json::Value::Object(fields) => fields
                .iter()
                .map(|(key, value)| (value, location.with_keys([key.clone().into()])))
                .collect(),
            _ => {
                return vec![Outcome::known(
                    value.clone().try_into().expect("JSON scalar"),
                )];
            }
        };
        let alternatives = self.sequence(entries, |analysis, (value, location)| {
            analysis.decode(value, location, context)
        });
        alternatives.map(|items| {
            TrackedValue::new(match value {
                serde_json::Value::Object(fields) => {
                    AbstractValue::Object(Arc::new(fields.keys().cloned().zip(items).collect()))
                }
                _ => AbstractValue::Array(Arc::new(items)),
            })
        })
    }
}
