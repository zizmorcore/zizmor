//! Resolve workflow expressions and record where their inputs were defined.

mod inputs;
mod matrix;

use github_actions_expressions::evaluation::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use crate::{finding::location::SymbolicLocation, utils::extract_fenced_expressions};
use github_actions_expressions::{
    Evaluation, Expr, Origin, SpannedExpr,
    call::{Call, Function},
};

use super::{
    StepCommon as _,
    action::CompositeStep,
    workflow::{JobCommon as _, NormalJob, Step},
};
use crate::finding::location::Locatable as _;
use github_actions_models::common::{Env, expr::LoE};

#[derive(Clone, Copy, Default, PartialEq)]
enum Phase {
    #[default]
    Step,
    Env,
    Matrix,
}

type EnvScope<'doc> = (&'doc LoE<Env>, SymbolicLocation<'doc>, bool);

#[derive(Clone, Default)]
pub(crate) struct Context<'doc> {
    envs: Vec<EnvScope<'doc>>,
    prior_steps: bool,
    phase: Phase,
    job: Option<NormalJob<'doc>>,
}

impl<'doc> Context<'doc> {
    pub(crate) fn job(job: NormalJob<'doc>) -> Self {
        let workflow = job.parent();
        Self {
            envs: vec![
                (&workflow.env, workflow.location(), false),
                (&job.env, job.location(), false),
            ],
            prior_steps: true,
            job: Some(job),
            ..Self::default()
        }
    }

    pub(crate) fn workflow_step(step: &Step<'doc>) -> Self {
        let mut context = Context::job(step.job().clone());
        context.envs.push((step.env(), step.location(), true));
        context.prior_steps = step.job().steps().any(|prior| prior.ord() < step.ord());
        context
    }

    pub(crate) fn composite_step(step: &CompositeStep<'doc>) -> Self {
        Self {
            envs: vec![(&step.inner.env, step.location(), true)],
            prior_steps: step.index > 0,
            ..Self::default()
        }
    }
}

/// Evaluate expressions against workflow definitions and retain their source locations.
#[derive(Default)]
pub(crate) struct Analysis<'doc> {
    state: State,
    bindings: Bindings<'doc>,
}

#[derive(Default)]
struct Bindings<'doc> {
    evidence: Vec<SymbolicLocation<'doc>>,
    input_trigger: Option<DecisionId>,
    inputs: BTreeMap<String, Outcomes>,
    matrices: BTreeMap<String, (DecisionId, Outcomes)>,
    job_states: BTreeMap<String, DecisionId>,
}

impl<'doc> Analysis<'doc> {
    pub(crate) fn evaluate(&mut self, expr: &Expr<'_>, context: &Context<'doc>) -> Outcomes {
        self.bindings.evaluate(&mut self.state, expr, context)
    }

    pub(crate) fn locations<'a>(
        &self,
        outcomes: impl IntoIterator<Item = &'a Outcome>,
    ) -> Vec<SymbolicLocation<'doc>> {
        let ids = outcomes
            .into_iter()
            .flat_map(|outcome| outcome.value.dependencies().evidence)
            .collect::<BTreeSet<_>>();
        ids.into_iter()
            .map(|id| self.bindings.evidence[id].clone())
            .collect()
    }
}

impl<'doc> Bindings<'doc> {
    fn evaluate(
        &mut self,
        state: &mut State,
        expr: &Expr<'_>,
        context: &Context<'doc>,
    ) -> Outcomes {
        expr.evaluate(state, |state, path| self.resolve(state, path, context))
    }

    fn resolve(&mut self, state: &mut State, path: &[Access], context: &Context<'doc>) -> Outcomes {
        match path[0].text().to_ascii_lowercase().as_str() {
            "inputs" => match (&context.job, path) {
                (Some(job), [_, Access::Key(name), rest @ ..]) => {
                    self.input(state, job.parent(), name).map(|value| {
                        rest.iter()
                            .fold(value, |value, access| value.apply_access(access))
                    })
                }
                _ => self.runtime(path, context),
            },
            "needs" => self
                .output(state, path, context)
                .unwrap_or_else(|| vec![Outcome::new(TrackedValue::incomplete())]),
            "matrix" if context.phase != Phase::Matrix => self.matrix(state, path, context),
            "env" if context.phase == Phase::Step => self.environment(state, path, context),
            "env" | "matrix" | "steps" | "runner" | "job" if context.phase != Phase::Step => {
                vec![Outcome::new(TrackedValue::incomplete())]
            }
            _ => self.runtime(path, context),
        }
    }

    fn environment(
        &mut self,
        state: &mut State,
        path: &[Access],
        context: &Context<'doc>,
    ) -> Outcomes {
        let [_, Access::Key(name)] = path else {
            return self.runtime(path, context);
        };
        for index in (0..context.envs.len()).rev() {
            let (values, location, step) = context.envs[index].clone();
            let LoE::Literal(env) = values else {
                return self.runtime(path, context);
            };
            let Some((key, value)) = env.iter().find(|(key, _)| key.eq_ignore_ascii_case(name))
            else {
                continue;
            };
            let location = location
                .with_keys(["env".into(), key.as_str().into()])
                .annotated(format!("{name} is defined here"));

            // Step env values see outer scopes; other env definitions cannot reference env.
            let outer_scopes = if step { index } else { 0 };
            let child = Context {
                envs: context.envs[..outer_scopes].to_vec(),
                phase: if step { Phase::Step } else { Phase::Env },
                ..context.clone()
            };
            let mut values = self.template(state, &value.to_string(), &child);
            if context.prior_steps && !step {
                let runtime = self.runtime(path, context);
                let overwrite = location
                    .clone()
                    .annotated(format!("an earlier step may overwrite {name}"));
                values.extend(self.explain(runtime, overwrite));
            }
            return self.explain(values, location);
        }
        self.runtime(path, context)
    }

    fn output(
        &mut self,
        state: &mut State,
        path: &[Access],
        context: &Context<'doc>,
    ) -> Option<Outcomes> {
        let [_, Access::Key(id), Access::Key(field), Access::Key(name)] = path else {
            return Some(self.runtime(path, context));
        };
        if !field.eq_ignore_ascii_case("outputs") {
            return Some(self.runtime(path, context));
        }
        let consumer = context.job.as_ref()?;
        if !consumer
            .needs
            .iter()
            .any(|need| need.eq_ignore_ascii_case(id))
        {
            return None;
        }
        let workflow = consumer.parent();
        let (job_id, producer) = workflow
            .jobs
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(id))?;
        let github_actions_models::workflow::Job::NormalJob(inner) = producer else {
            return Some(self.runtime(path, context));
        };
        let producer = NormalJob::new(job_id, inner, workflow);
        let Some((name, value)) = inner
            .outputs
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
        else {
            return Some(vec![Outcome::known(Evaluation::String(String::new()))]);
        };
        let location = producer
            .location()
            .with_keys(["outputs".into(), name.as_str().into()])
            .annotated(format!("this job declares output {name}"));

        let child = Context::job(producer);
        let mut values = self.template(state, &value.to_string(), &child);

        // A skipped job has empty outputs. Keep repeated reads consistent.
        let status = *self
            .job_states
            .entry(job_id.clone())
            .or_insert_with(|| state.decision());
        for value in &mut values {
            value.choices.insert(status, AlternativeId::new(1));
        }
        let mut skipped = Outcome::known(Evaluation::String(String::new()));
        skipped.choices.insert(status, AlternativeId::new(0));
        values.push(skipped);
        let values = state.bound(values);
        Some(self.explain(values, location))
    }

    fn template(&mut self, state: &mut State, text: &str, context: &Context<'doc>) -> Outcomes {
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
                return self.evaluate(state, &parsed, context);
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
        let expr = Expr::Call(Call {
            func: Function::Format,
            args,
        });
        self.evaluate(state, &expr, context)
    }

    fn explain(&mut self, values: Outcomes, location: SymbolicLocation<'doc>) -> Outcomes {
        let id = self.evidence.len();
        self.evidence.push(location);
        values.map(|mut value| {
            value.provenance.evidence.insert(id);
            value
        })
    }

    fn runtime(&self, path: &[Access], context: &Context<'doc>) -> Outcomes {
        let root = path[0].text();
        if root.eq_ignore_ascii_case("github") {
            return vec![Outcome::new(TrackedValue::new(AbstractValue::Reference(
                path.to_vec(),
            )))];
        }

        let mut value = TrackedValue::unknown();
        let identity = path.iter().map(Access::text).collect::<Vec<_>>().join(".");
        let identity = if let Some(job) = &context.job
            && !root.eq_ignore_ascii_case("inputs")
        {
            format!("job:{}:{identity}", job.id())
        } else {
            identity
        };
        value.provenance.sources.insert(identity);
        vec![Outcome::new(value)]
    }

    fn decode(
        &mut self,
        state: &mut State,
        value: &serde_json::Value,
        location: SymbolicLocation<'doc>,
        context: &Context<'doc>,
    ) -> Outcomes {
        if !state.checkpoint() {
            return Outcomes::default();
        }
        let entries: Vec<_> = match value {
            serde_json::Value::String(text) => {
                let values = self.template(state, text, context);
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
        let alternatives = state.sequence(entries, |state, (value, location)| {
            self.decode(state, value, location, context)
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
