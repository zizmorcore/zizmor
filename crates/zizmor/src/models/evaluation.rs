//! Bindings visible to an expression at a workflow job, step, or composite step.
//! The same expression is evaluated once for each possible trigger and matrix
//! row. Reading a job output switches to the producer's bindings.

mod inputs;
mod matrix;

use super::{
    StepCommon as _,
    action::CompositeStep,
    workflow::{JobCommon as _, NormalJob, Step},
};
use crate::finding::location::{Locatable as _, SymbolicLocation};
use github_actions_expressions::{Evaluation, Expr, evaluation::*};
use github_actions_models::common::{Env, expr::LoE};
use indexmap::IndexMap;
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
};

#[derive(Clone, Copy, Default, PartialEq)]
enum Phase {
    #[default]
    Step,
    Job,
    Matrix,
}

#[derive(Clone)]
struct EnvScope<'doc> {
    values: &'doc LoE<Env>,
    location: SymbolicLocation<'doc>,
    phase: Phase,
}

#[derive(Clone, Default)]
pub(crate) struct Context<'doc> {
    row: Option<(usize, TrackedValue)>,
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
                EnvScope {
                    values: &workflow.env,
                    location: workflow.location(),
                    phase: Phase::Job,
                },
                EnvScope {
                    values: &job.env,
                    location: job.location(),
                    phase: Phase::Job,
                },
            ],
            phase: Phase::Job,
            job: Some(job),
            ..Self::default()
        }
    }

    pub(crate) fn workflow_step(step: &Step<'doc>) -> Self {
        let mut context = Context::job(step.job().clone());
        context.phase = Phase::Step;
        context.envs.push(EnvScope {
            values: step.env(),
            location: step.location(),
            phase: Phase::Step,
        });
        context.prior_steps = step.job().steps().any(|prior| prior.ord() < step.ord());
        context
    }

    pub(crate) fn composite_step(step: &CompositeStep<'doc>) -> Self {
        Self {
            envs: vec![EnvScope {
                values: &step.inner.env,
                location: step.location(),
                phase: Phase::Step,
            }],
            prior_steps: step.index > 0,
            ..Self::default()
        }
    }

    pub(crate) fn evaluate(&self, expr: &Expr<'_>) -> Results<'doc> {
        self.evaluate_with(|eval, env| eval.evaluate(expr, env))
    }

    fn evaluate_with(
        &self,
        run: impl Fn(&mut Evaluator, &mut Environment<'_, 'doc>) -> Outcomes,
    ) -> Results<'doc> {
        let mut results = Results::default();
        let mut eval = Evaluator::default();
        let outcomes = eval.within_limits(|eval| {
            let mut outcomes = Vec::new();
            for inputs in inputs::environments(
                self.job.as_ref().map(|job| job.parent()),
                eval,
                &mut results,
            ) {
                let mut cache = Cache::default();
                let mut env = Environment {
                    context: self,
                    inputs: &inputs,
                    results: &mut results,
                    cache: &mut cache,
                };
                outcomes.extend(env.in_rows(eval, &run));
            }
            outcomes
        });
        results.outcomes = outcomes;
        results
    }
}

/// Outcomes and the source locations their evidence indices refer to.
#[derive(Default)]
pub(crate) struct Results<'doc> {
    pub(crate) outcomes: Outcomes,
    evidence: IndexMap<(yamlpath::Route<'doc>, Cow<'doc, str>), SymbolicLocation<'doc>>,
}

impl<'doc> Results<'doc> {
    pub(crate) fn incomplete() -> Self {
        Self {
            outcomes: vec![Outcome::new(TrackedValue::incomplete())],
            ..Self::default()
        }
    }

    pub(crate) fn locations<'a>(
        &self,
        values: impl IntoIterator<Item = &'a TrackedValue>,
    ) -> Vec<SymbolicLocation<'doc>> {
        let ids: BTreeSet<_> = values
            .into_iter()
            .flat_map(|value| value.dependencies().evidence)
            .collect();
        ids.into_iter()
            .map(|id| self.evidence[id].clone())
            .collect()
    }

    fn record(&mut self, location: SymbolicLocation<'doc>) -> usize {
        let key = (location.route.clone(), location.annotation.clone());
        self.evidence.insert_full(key, location).0
    }
}

#[derive(Default)]
struct Cache {
    rows: BTreeMap<String, Outcomes<(usize, TrackedValue)>>,
    outputs: BTreeMap<(String, String), Outcomes>,
    status: BTreeMap<String, DecisionId>,
    env: BTreeMap<(usize, String, Option<usize>, bool), Outcomes>,
}

struct Environment<'a, 'doc> {
    context: &'a Context<'doc>,
    inputs: &'a BTreeMap<String, Outcomes>,
    results: &'a mut Results<'doc>,
    cache: &'a mut Cache,
}

fn empty() -> Outcome {
    Outcome::known(Evaluation::String(String::new()))
}

impl Bindings for Environment<'_, '_> {
    fn lookup(&mut self, path: &[Access], eval: &mut Evaluator) -> Outcomes {
        let context = self.context;
        match path[0].text().to_ascii_lowercase().as_str() {
            "github" => vec![Outcome::new(TrackedValue::new(AbstractValue::Reference(
                path.to_vec(),
            )))],
            "inputs" if context.job.is_some() => {
                if let [_, Access::Key(name), rest @ ..] = path {
                    let values = self
                        .inputs
                        .get(&name.to_ascii_lowercase())
                        .cloned()
                        .unwrap_or_else(|| vec![empty()]);
                    values.map(|value| {
                        rest.iter()
                            .fold(value, |value, key| value.apply_access(key))
                    })
                } else {
                    self.runtime(path)
                }
            }
            "matrix" if context.phase != Phase::Matrix && context.job.is_some() => {
                let Some((_, row)) = &context.row else {
                    return vec![empty()];
                };
                vec![Outcome::new(
                    path[1..]
                        .iter()
                        .fold(row.clone(), |value, key| value.apply_access(key)),
                )]
            }
            "env" if context.phase == Phase::Step => self.environment(eval, path),
            "needs" => self
                .output(eval, path)
                .unwrap_or_else(|| vec![Outcome::new(TrackedValue::incomplete())]),
            "env" | "matrix" | "steps" | "runner" | "job" if context.phase != Phase::Step => {
                vec![Outcome::new(TrackedValue::incomplete())]
            }
            _ => self.runtime(path),
        }
    }
}

impl<'doc> Environment<'_, 'doc> {
    fn at<'a>(&'a mut self, context: &'a Context<'doc>) -> Environment<'a, 'doc> {
        Environment {
            context,
            inputs: self.inputs,
            results: self.results,
            cache: self.cache,
        }
    }

    fn runtime(&self, path: &[Access]) -> Outcomes {
        let mut value = TrackedValue::unknown();
        let name = path.iter().map(Access::text).collect::<Vec<_>>().join(".");
        let name = match &self.context.job {
            Some(job) if !path[0].text().eq_ignore_ascii_case("inputs") => {
                match &self.context.row {
                    Some((row, _)) => format!("job:{}[{row}]:{name}", job.id()),
                    None => format!("job:{}:{name}", job.id()),
                }
            }
            _ => name,
        };
        value.provenance.sources.insert(name);
        vec![Outcome::new(value)]
    }

    fn environment(&mut self, eval: &mut Evaluator, path: &[Access]) -> Outcomes {
        let context = self.context;
        let [_, Access::Key(name), rest @ ..] = path else {
            return self.runtime(path);
        };
        for (index, scope) in context.envs.iter().enumerate().rev() {
            let LoE::Literal(env) = scope.values else {
                return self.runtime(path);
            };
            let Some((name, value)) = env.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)) else {
                continue;
            };
            let location = scope
                .location
                .with_keys(["env".into(), name.clone().into()]);
            let overwrite = (context.prior_steps && scope.phase == Phase::Job).then(|| {
                self.results.record(
                    location
                        .clone()
                        .annotated(format!("an earlier step may overwrite {name}")),
                )
            });
            let id = self.results.record(
                location
                    .clone()
                    .annotated(format!("{name} is defined here")),
            );
            let key = (
                id,
                context.job.as_ref().map_or("", |j| j.id()).to_owned(),
                context.row.as_ref().map(|(i, _)| *i),
                context.prior_steps,
            );
            let values = if let Some(cached) = self.cache.env.get(&key) {
                cached.clone()
            } else {
                let child = Context {
                    // A step's env can refer to the outer env.
                    envs: context.envs[..index].to_vec(),
                    phase: scope.phase,
                    ..context.clone()
                };
                let mut values = eval.template(&value.to_string(), &mut self.at(&child));
                if let Some(overwrite) = overwrite {
                    let decision = eval.decision();
                    values = values
                        .into_iter()
                        .filter_map(|v| v.assume(decision, AlternativeId::new(0)))
                        .collect();
                    values.extend(
                        located(self.runtime(&path[..2]), overwrite)
                            .into_iter()
                            .filter_map(|v| v.assume(decision, AlternativeId::new(1))),
                    );
                }
                let values = located(values, id);
                self.cache.env.insert(key, values.clone());
                values
            };
            return values.map(|value| {
                rest.iter()
                    .fold(value, |value, key| value.apply_access(key))
            });
        }
        self.runtime(path)
    }

    fn output(&mut self, eval: &mut Evaluator, path: &[Access]) -> Option<Outcomes> {
        let [
            _,
            Access::Key(id),
            Access::Key(field),
            Access::Key(name),
            rest @ ..,
        ] = path
        else {
            return Some(self.runtime(path));
        };
        if !field.eq_ignore_ascii_case("outputs") {
            return Some(self.runtime(path));
        }
        let consumer = self.context.job.as_ref()?;
        if !consumer
            .needs
            .iter()
            .any(|need| need.eq_ignore_ascii_case(id))
        {
            return None;
        }
        let workflow = consumer.parent();
        let (id, job) = workflow
            .jobs
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(id))?;
        let github_actions_models::workflow::Job::NormalJob(inner) = job else {
            return Some(self.runtime(path));
        };
        let Some((name, value)) = inner
            .outputs
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
        else {
            return Some(vec![empty()]);
        };
        let key = (id.clone(), name.clone());
        if !self.cache.outputs.contains_key(&key) {
            let producer = NormalJob::new(id, inner, workflow);
            let location = producer
                .location()
                .with_keys(["outputs".into(), name.as_str().into()])
                .annotated(format!("this job declares output {name}"));
            let child = Context {
                phase: Phase::Step,
                prior_steps: true,
                ..Context::job(producer)
            };
            let text = value.to_string();
            let values = self
                .at(&child)
                .in_rows(eval, |eval, env| eval.template(&text, env));
            // Matrix jobs merge outputs by name. Each name can come from a
            // different row, but all reads of that name see the same value.
            let winner = eval.decision();
            let decision = *self
                .cache
                .status
                .entry(id.clone())
                .or_insert_with(|| eval.decision());
            let values = values
                .into_iter()
                .enumerate()
                .filter_map(|(i, value)| value.assume(winner, AlternativeId::new(i)))
                .filter_map(|value| value.assume(decision, AlternativeId::new(1)))
                .chain(empty().assume(decision, AlternativeId::new(0)))
                .collect();
            self.cache
                .outputs
                .insert(key.clone(), located(values, self.results.record(location)));
        }
        Some(
            self.cache.outputs[&key]
                .clone()
                .map(|value| rest.iter().fold(value, |v, k| v.apply_access(k))),
        )
    }
}

fn located(values: Outcomes, id: usize) -> Outcomes {
    values.map(|mut value| {
        value.provenance.evidence.insert(id);
        value
    })
}
