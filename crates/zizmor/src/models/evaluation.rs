//! Build the context visible at a workflow expression.
//!
//! For `needs.build.outputs.image`, the build job's output template captures
//! its own environment and matrix. The consumer's `needs` scope points to a
//! choice between that job's outputs and its skipped outputs. The expression
//! evaluator follows those definitions and returns the locations it visited.

mod inputs;

use std::collections::{BTreeMap, BTreeSet};

use github_actions_expressions::{
    Evaluation,
    evaluation::{AbstractValue, Access, Definition, Outcome, Scope, TrackedValue},
};
use github_actions_models::{
    common::{Env, expr::LoE},
    workflow::Job,
};

use super::{
    StepCommon as _,
    action::CompositeStep,
    workflow::{JobCommon as _, NormalJob, Step},
};
use crate::finding::location::{Locatable as _, SymbolicLocation};

pub(crate) struct Context<'doc> {
    pub(crate) scope: Scope,
    locations: Vec<SymbolicLocation<'doc>>,
}

#[derive(Default)]
struct Builder<'doc> {
    locations: Vec<SymbolicLocation<'doc>>,
}

impl<'doc> Builder<'doc> {
    fn record(&mut self, location: SymbolicLocation<'doc>) -> usize {
        let id = self.locations.len();
        self.locations.push(location);
        id
    }
}

fn empty() -> Definition {
    Definition::known(Evaluation::String(String::new()))
}

fn incomplete() -> Definition {
    Definition::value(TrackedValue::incomplete())
}

fn runtime_scope(runtime: &Definition) -> Scope {
    let mut scope = Scope::new(runtime.clone());
    scope.bind(
        "github",
        Definition::value(TrackedValue::new(AbstractValue::Reference(vec![
            Access::Key("github".into()),
        ]))),
    );
    scope
}

impl<'doc> Context<'doc> {
    pub(crate) fn workflow_step(step: &Step<'doc>) -> Self {
        let job = step.job();
        let mut builder = Builder::default();
        let scopes = builder.job_scopes(job);
        let runtime = scopes.runtime.clone();
        let prior_steps = job.steps().any(|prior| prior.ord() < step.ord());
        let (mut scope, outer_env) = scopes.with_environment(job, prior_steps, &mut builder);
        let env = builder.environment(
            outer_env,
            step.env(),
            step.location(),
            &scope,
            &runtime,
            false,
        );
        scope.bind("env", Definition::namespace(env));
        Self {
            scope,
            locations: builder.locations,
        }
    }

    pub(crate) fn composite_step(step: &CompositeStep<'doc>) -> Self {
        let mut builder = Builder::default();
        let runtime = Definition::runtime(String::new());
        let mut scope = runtime_scope(&runtime);
        scope.bind("needs", Definition::namespace(needs_scope(&runtime)));
        let env = builder.environment(
            Scope::new(runtime.clone()),
            &step.inner.env,
            step.location(),
            &scope,
            &runtime,
            false,
        );
        scope.bind("env", Definition::namespace(env));
        Self {
            scope,
            locations: builder.locations,
        }
    }

    pub(crate) fn locations<'a>(
        &self,
        outcomes: impl IntoIterator<Item = &'a Outcome>,
    ) -> Vec<SymbolicLocation<'doc>> {
        let ids: BTreeSet<_> = outcomes
            .into_iter()
            .flat_map(|outcome| outcome.value.dependencies().evidence)
            .collect();
        ids.into_iter()
            .map(|id| self.locations[id].clone())
            .collect()
    }
}

/// Contexts visible before steps run. The matrix captures the scope that
/// existed before the job's own matrix became available.
struct JobScope {
    scope: Scope,
    runtime: Definition,
}

impl JobScope {
    fn with_environment<'doc>(
        &self,
        job: &NormalJob<'doc>,
        prior_steps: bool,
        builder: &mut Builder<'doc>,
    ) -> (Scope, Scope) {
        let mut env = Scope::new(self.runtime.clone());
        for (values, location) in [
            (&job.parent().env, job.parent().location()),
            (&job.env, job.location()),
        ] {
            env = builder.environment(
                env,
                values,
                location,
                &self.scope,
                &self.runtime,
                prior_steps,
            );
        }
        let mut scope = self.scope.clone();
        for name in ["steps", "runner", "job"] {
            scope.bind(name, self.runtime.clone());
        }
        scope.bind("env", Definition::namespace(env.clone()));
        (scope, env)
    }
}

fn needs_scope(runtime: &Definition) -> Scope {
    let mut unavailable = Scope::new(runtime.clone());
    let outputs = Scope::new(runtime.clone()).with_missing(incomplete());
    unavailable.bind("outputs", Definition::namespace(outputs));
    Scope::new(runtime.clone()).with_missing(Definition::namespace(unavailable))
}

impl<'doc> Builder<'doc> {
    fn environment(
        &mut self,
        mut env: Scope,
        values: &LoE<Env>,
        location: SymbolicLocation<'doc>,
        scope: &Scope,
        runtime: &Definition,
        prior_steps: bool,
    ) -> Scope {
        let LoE::Literal(values) = values else {
            return Scope::new(runtime.clone());
        };
        for (name, value) in values {
            let location = location.with_keys(["env".into(), name.clone().into()]);
            let mut definition = Definition::template(value.to_string(), scope.clone());
            if prior_steps {
                let overwrite = self.record(
                    location
                        .clone()
                        .annotated(format!("an earlier step may overwrite {name}")),
                );
                definition =
                    Definition::choice(vec![definition, runtime.clone().located(overwrite)]);
            }
            env.bind(
                name,
                definition
                    .located(self.record(location.annotated(format!("{name} is defined here")))),
            );
        }
        env
    }

    /// Build producers before their consumers. Shared upstream jobs contribute
    /// one output choice even when several dependency paths lead to them.
    fn job_scopes(&mut self, target: &NormalJob<'doc>) -> JobScope {
        let workflow = target.parent();
        let inputs = self.inputs(workflow);
        let jobs: BTreeMap<_, _> = workflow
            .jobs
            .iter()
            .map(|(id, job)| (id.to_ascii_lowercase(), (id, job)))
            .collect();
        let mut outputs = BTreeMap::new();
        let mut pending = vec![(target.clone(), false)];
        while let Some((job, visited)) = pending.pop() {
            let key = job.id().to_ascii_lowercase();
            if outputs.contains_key(&key) {
                continue;
            }
            if !visited {
                pending.push((job.clone(), true));
                for need in &job.needs {
                    if let Some((id, Job::NormalJob(inner))) = jobs.get(&need.to_ascii_lowercase())
                    {
                        pending.push((NormalJob::new(id, inner, workflow), false));
                    }
                }
                continue;
            }

            let scopes = self.job_scope(&job, &inputs, &outputs);
            if job.id() == target.id() {
                return scopes;
            }
            let (producer, _) = scopes.with_environment(&job, true, self);
            let output = self.outputs(&job, &producer, &scopes.runtime);
            outputs.insert(key, output);
        }
        unreachable!("the validated job graph includes the target")
    }

    fn job_scope(
        &mut self,
        job: &NormalJob<'doc>,
        inputs: &Definition,
        outputs: &BTreeMap<String, Definition>,
    ) -> JobScope {
        let runtime = Definition::runtime(format!("job:{}:", job.id()));
        let mut needs = needs_scope(&runtime);
        for name in &job.needs {
            let key = name.to_ascii_lowercase();
            if let Some(definition) = outputs.get(&key) {
                let mut producer = Scope::new(runtime.clone());
                producer.bind("outputs", definition.clone());
                needs.bind(name, Definition::namespace(producer));
            } else if job
                .parent()
                .jobs
                .keys()
                .any(|id| id.eq_ignore_ascii_case(name))
            {
                needs.bind(name, runtime.clone());
            }
        }

        let mut scope = runtime_scope(&runtime);
        scope.bind("inputs", inputs.clone());
        scope.bind("needs", Definition::namespace(needs));
        for name in ["env", "steps", "runner", "job", "matrix"] {
            scope.bind(name, incomplete());
        }
        let matrix = job
            .strategy
            .as_ref()
            .and_then(|strategy| strategy.matrix.as_ref());
        let matrix = matrix.map_or_else(empty, |matrix| {
            let location = job
                .location()
                .with_keys(["strategy".into(), "matrix".into()])
                .annotated("matrix value defined here");
            let value = serde_json::to_value(matrix).expect("validated matrix");
            Definition::matrix(self.decode(&value, location, &scope))
        });
        scope.bind("matrix", matrix);
        JobScope { scope, runtime }
    }

    fn outputs(
        &mut self,
        job: &NormalJob<'doc>,
        producer: &Scope,
        runtime: &Definition,
    ) -> Definition {
        let mut ran = Scope::new(runtime.clone()).with_missing(empty());
        let mut skipped = ran.clone();
        for (name, value) in &job.outputs {
            let location = job
                .location()
                .with_keys(["outputs".into(), name.as_str().into()])
                .annotated(format!("this job declares output {name}"));
            let id = self.record(location);
            ran.bind(
                name,
                Definition::template(value.to_string(), producer.clone()).located(id),
            );
            skipped.bind(name, empty().located(id));
        }
        Definition::choice(vec![
            Definition::namespace(ran),
            Definition::namespace(skipped),
        ])
    }

    fn decode(
        &mut self,
        value: &serde_json::Value,
        location: SymbolicLocation<'doc>,
        scope: &Scope,
    ) -> Definition {
        match value {
            serde_json::Value::String(text) => {
                Definition::template(text.clone(), scope.clone()).located(self.record(location))
            }
            serde_json::Value::Array(items) => Definition::array(
                items
                    .iter()
                    .enumerate()
                    .map(|(i, item)| self.decode(item, location.with_keys([i.into()]), scope))
                    .collect(),
            ),
            serde_json::Value::Object(fields) => Definition::object(
                fields
                    .iter()
                    .map(|(key, item)| {
                        (
                            key.clone(),
                            self.decode(item, location.with_keys([key.clone().into()]), scope),
                        )
                    })
                    .collect(),
            ),
            value => Definition::known(value.clone().try_into().expect("JSON scalar")),
        }
    }
}
