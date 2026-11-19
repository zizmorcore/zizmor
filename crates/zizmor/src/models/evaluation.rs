//! Bindings visible to an expression at a workflow job, step, or composite step.
//! Each trigger supplies its input declarations. Expressions that use a matrix
//! row run once per row. Reading a job output switches to the producer's bindings.

use super::{
    StepCommon as _,
    action::CompositeStep,
    inputs::WorkflowInputs,
    workflow::{JobCommon as _, NormalJob, Step},
};
use crate::finding::location::{Locatable as _, SymbolicLocation};
use github_actions_expressions::{Evaluation, Expr, evaluation::*};
use github_actions_models::common::{Env, expr::LoE};
use indexmap::IndexMap;
use std::{
    borrow::Cow,
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
};

/// The part of the document that supplies the bindings for a read.
/// Aliases switch to their declaration site, keeping the current invocation.
#[derive(Clone, Copy)]
pub(super) enum Site<'a, 'doc> {
    Step(&'a Step<'doc>),
    StepEnv(&'a Step<'doc>),
    CompositeStep(&'a CompositeStep<'doc>),
    CompositeEnv,
    Job(&'a NormalJob<'doc>),
    Matrix(&'a NormalJob<'doc>),
    JobOutput(&'a NormalJob<'doc>),
}

struct EnvScope<'a, 'doc> {
    values: &'doc LoE<Env>,
    location: SymbolicLocation<'doc>,
    declared_at: Site<'a, 'doc>,
    may_be_overwritten: bool,
}

impl<'a, 'doc> Site<'a, 'doc> {
    fn job(self) -> Option<&'a NormalJob<'doc>> {
        match self {
            Self::Step(step) | Self::StepEnv(step) => Some(step.job()),
            Self::Job(job) | Self::JobOutput(job) | Self::Matrix(job) => Some(job),
            Self::CompositeStep(_) | Self::CompositeEnv => None,
        }
    }

    fn before_steps(self) -> bool {
        matches!(self, Self::Job(_) | Self::Matrix(_))
    }

    /// In lookup order. A step env declaration can read its outer scopes.
    fn env_scopes(self) -> impl Iterator<Item = EnvScope<'a, 'doc>> {
        let local = match self {
            Self::Step(step) => Some(EnvScope {
                values: step.env(),
                location: step.location(),
                declared_at: Self::StepEnv(step),
                may_be_overwritten: false,
            }),
            Self::CompositeStep(step) => Some(EnvScope {
                values: &step.inner.env,
                location: step.location(),
                declared_at: Self::CompositeEnv,
                may_be_overwritten: false,
            }),
            _ => None,
        };
        let prior_steps = match self {
            Self::Step(step) | Self::StepEnv(step) => step
                .job()
                .steps()
                .next()
                .is_some_and(|first| first.ord() < step.ord()),
            Self::JobOutput(_) => true,
            _ => false,
        };
        let outer = self.job().into_iter().flat_map(move |job| {
            let workflow = job.parent();
            [
                (&job.env, job.location()),
                (&workflow.env, workflow.location()),
            ]
            .map(|(values, location)| EnvScope {
                values,
                location,
                declared_at: Self::Job(job),
                may_be_overwritten: prior_steps,
            })
        });
        local.into_iter().chain(outer)
    }

    pub(crate) fn evaluate(&self, expr: &Expr<'_>) -> Evaluated<'doc> {
        self.evaluate_with(|eval, env| eval.evaluate(expr, env))
    }

    fn evaluate_with(
        self,
        run: impl Fn(&mut Evaluator, &mut Environment<'_, 'doc>) -> Outcomes,
    ) -> Evaluated<'doc> {
        let mut evidence = Evidence::default();
        let mut eval = Evaluator::default();
        let outcomes = eval.within_limits(|eval| {
            let mut outcomes = Vec::new();
            let triggers = match self.job() {
                Some(job) => job.parent().input_declarations().collect(),
                None => vec![WorkflowInputs::Empty],
            };
            for inputs in triggers {
                let mut cache = Cache::default();
                let env = Environment {
                    site: self,
                    row: None,
                    inputs,
                    evidence: &mut evidence,
                    cache: &mut cache,
                    needs_row: None,
                };
                outcomes.extend(env.in_rows(eval, &run));
            }
            outcomes
        });
        Evaluated {
            values: outcomes.into_iter().map(|outcome| outcome.value).collect(),
            evidence,
        }
    }
}

/// Possible values of an expression and their locations in this document.
#[derive(Default)]
pub(crate) struct Evaluated<'doc> {
    pub(crate) values: Vec<TrackedValue>,
    evidence: Evidence<'doc>,
}

impl<'doc> Evaluated<'doc> {
    pub(crate) fn incomplete() -> Self {
        Self {
            values: vec![TrackedValue::incomplete()],
            ..Self::default()
        }
    }

    /// The distinct locations that contributed to the selected values.
    pub(crate) fn locations<'a>(
        &self,
        values: impl IntoIterator<Item = &'a TrackedValue>,
    ) -> Vec<SymbolicLocation<'doc>> {
        let ids: BTreeSet<_> = values
            .into_iter()
            .flat_map(|value| value.dependencies().evidence)
            .collect();
        ids.into_iter()
            .map(|id| self.evidence.locations[id].clone())
            .collect()
    }
}

#[derive(Default)]
struct Evidence<'doc> {
    locations: IndexMap<(yamlpath::Route<'doc>, Cow<'doc, str>), SymbolicLocation<'doc>>,
}

impl<'doc> Evidence<'doc> {
    fn record(&mut self, location: SymbolicLocation<'doc>) -> usize {
        let key = (location.route.clone(), location.annotation.clone());
        self.locations.insert_full(key, location).0
    }
}

#[derive(Default)]
struct Cache {
    inputs: BTreeMap<String, Outcomes>,
    rows: BTreeMap<String, Outcomes<(usize, TrackedValue)>>,
    outputs: BTreeMap<(String, String), Outcomes>,
    status: BTreeMap<String, DecisionId>,
    env: BTreeMap<(usize, String, Option<usize>, bool), Outcomes>,
}

struct Environment<'a, 'doc> {
    site: Site<'a, 'doc>,
    row: Option<&'a (usize, TrackedValue)>,
    inputs: WorkflowInputs<'doc>,
    evidence: &'a mut Evidence<'doc>,
    cache: &'a mut Cache,
    /// Set when a lookup requires a row during the first pass over a matrix job.
    needs_row: Option<&'a Cell<bool>>,
}

fn empty() -> Outcome {
    Outcome::known(Evaluation::String(String::new()))
}

impl Bindings for Environment<'_, '_> {
    fn lookup(&mut self, path: &[Access], eval: &mut Evaluator) -> Outcomes {
        let site = self.site;
        match path[0].text().to_ascii_lowercase().as_str() {
            "github" => vec![Outcome::new(TrackedValue::new(AbstractValue::Reference(
                path.to_vec(),
            )))],
            "inputs" if site.job().is_some() => self.input(eval, path),
            "matrix" if !matches!(site, Site::Matrix(_)) && site.job().is_some() => {
                if self.defer_until_row() {
                    return vec![];
                }
                let Some((_, row)) = self.row else {
                    return vec![empty()];
                };
                vec![Outcome::new(row.clone().apply_path(&path[1..]))]
            }
            "env" if !site.before_steps() => self.environment(eval, path),
            "needs" => self
                .output(eval, path)
                .unwrap_or_else(|| vec![Outcome::new(TrackedValue::incomplete())]),
            "env" | "matrix" | "steps" | "runner" | "job" if site.before_steps() => {
                vec![Outcome::new(TrackedValue::incomplete())]
            }
            _ => self.runtime(path),
        }
    }
}

impl<'doc> Environment<'_, 'doc> {
    fn in_rows(
        mut self,
        eval: &mut Evaluator,
        run: impl Fn(&mut Evaluator, &mut Environment<'_, 'doc>) -> Outcomes,
    ) -> Outcomes {
        // A producer starts with its own bindings, even when its consumer
        // is checking whether it needs a matrix row.
        self.needs_row = None;
        self.row = None;
        let site = self.site;
        let Some(job) = site.job() else {
            return run(eval, &mut self);
        };
        let Some(matrix) = job.matrix() else {
            return run(eval, &mut self);
        };

        // A large matrix must not consume the budget for an unrelated binding.
        // Follow aliases and short circuits normally until a read needs a row.
        let needed = Cell::new(false);
        let mut env = self.at(site);
        env.needs_row = Some(&needed);
        let values = run(eval, &mut env);
        if !needed.get() {
            return values;
        }

        if !self.cache.rows.contains_key(job.id()) {
            let mut env = self.at(Site::Matrix(job));
            let rows = matrix.rows(eval, |eval, text, location| {
                let values = eval.template(text, &mut env);
                located(values, env.evidence.record(location))
            });
            let rows = rows
                .into_iter()
                .enumerate()
                .map(|(index, row)| row.map(|value| (index, value)))
                .collect();
            self.cache.rows.insert(job.id().to_owned(), rows);
        }

        let rows = self.cache.rows[job.id()].clone();
        eval.flat_map(rows, |eval, row| {
            let mut env = self.at(site);
            env.row = Some(row);
            run(eval, &mut env)
        })
    }

    fn at<'a>(&'a mut self, site: Site<'a, 'doc>) -> Environment<'a, 'doc> {
        Environment {
            site,
            row: self.row,
            inputs: self.inputs,
            evidence: self.evidence,
            cache: self.cache,
            needs_row: self.needs_row,
        }
    }

    fn defer_until_row(&self) -> bool {
        if let Some(needed) = self.needs_row {
            needed.set(true);
            return true;
        }
        false
    }

    fn runtime(&self, path: &[Access]) -> Outcomes {
        let mut value = TrackedValue::unknown();
        let name = path.iter().map(Access::text).collect::<Vec<_>>().join(".");
        let mut source = Source::new(name);
        if let Some(job) = self.site.job()
            && !path[0].text().eq_ignore_ascii_case("inputs")
        {
            if self.defer_until_row() {
                return vec![];
            }
            source.scope = Some(match self.row {
                Some((row, _)) => format!("{}[{row}]", job.id()),
                None => job.id().to_owned(),
            });
        }
        value.provenance.sources.insert(source);
        vec![Outcome::new(value)]
    }

    fn input(&mut self, eval: &mut Evaluator, path: &[Access]) -> Outcomes {
        let [_, Access::Key(name), rest @ ..] = path else {
            return self.runtime(path);
        };
        let values = self
            .cache
            .inputs
            .entry(name.to_ascii_lowercase())
            .or_insert_with(|| {
                let Some(input) = self.inputs.get(name) else {
                    return vec![empty()];
                };
                let location = input
                    .location()
                    .annotated(format!("input {} declared here", input.name));
                located(input.values(eval), self.evidence.record(location))
            });
        values.clone().map(|value| value.apply_path(rest))
    }

    fn environment(&mut self, eval: &mut Evaluator, path: &[Access]) -> Outcomes {
        let site = self.site;
        let [_, Access::Key(name), rest @ ..] = path else {
            return self.runtime(path);
        };
        for scope in site.env_scopes() {
            let LoE::Literal(env) = scope.values else {
                return self.runtime(path);
            };
            let Some((name, value)) = env.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)) else {
                continue;
            };
            let location = scope
                .location
                .with_keys(["env".into(), name.clone().into()]);
            let overwrite = scope.may_be_overwritten.then(|| {
                self.evidence.record(
                    location
                        .clone()
                        .annotated(format!("an earlier step may overwrite {name}")),
                )
            });
            let id = self
                .evidence
                .record(location.annotated(format!("{name} is defined here")));
            let key = (
                id,
                site.job().map_or("", |j| j.id()).to_owned(),
                self.row.map(|(i, _)| *i),
                scope.may_be_overwritten,
            );
            let values = if let Some(cached) = self.cache.env.get(&key) {
                cached.clone()
            } else {
                let mut values = eval.template(&value.to_string(), &mut self.at(scope.declared_at));
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
                // A read deferred to the per-row pass has no value to cache yet.
                if !self.needs_row.is_some_and(Cell::get) {
                    self.cache.env.insert(key, values.clone());
                }
                values
            };
            return values.map(|value| value.apply_path(rest));
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
        let super::workflow::Job::NormalJob(producer) = self.site.job()?.dependency(id)? else {
            return Some(self.runtime(path));
        };
        let id = producer.id();
        let Some((name, value)) = producer
            .outputs
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
        else {
            return Some(vec![empty()]);
        };
        let key = (id.to_owned(), name.clone());
        if !self.cache.outputs.contains_key(&key) {
            let location = producer
                .location()
                .with_keys(["outputs".into(), name.as_str().into()])
                .annotated(format!("this job declares output {name}"));
            let text = value.to_string();
            let values = self
                .at(Site::JobOutput(&producer))
                .in_rows(eval, |eval, env| eval.template(&text, env));
            // Matrix jobs merge outputs by name. Each name can come from a
            // different row, but all reads of that name see the same value.
            let winner = eval.decision();
            let decision = *self
                .cache
                .status
                .entry(id.to_owned())
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
                .insert(key.clone(), located(values, self.evidence.record(location)));
        }
        Some(
            self.cache.outputs[&key]
                .clone()
                .map(|value| value.apply_path(rest)),
        )
    }
}

fn located(values: Outcomes, id: usize) -> Outcomes {
    values.map(|mut value| {
        value.provenance.evidence.insert(id);
        value
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        InputKey,
        models::workflow::{Job, Workflow},
    };

    #[test]
    fn large_matrix_preserves_an_unrelated_binding() -> anyhow::Result<()> {
        // All 128 rows run. Matching their include entries costs more than
        // the evaluator's work limit, but the title is independent of them.
        let rows: Vec<_> = (0..128).collect();
        let include: Vec<_> = rows
            .iter()
            .map(|i| serde_json::json!({"i": i, "tag": "stable"}))
            .collect();
        let workflow = serde_json::json!({
            "on": "issues",
            "jobs": {"build": {
                "runs-on": "ubuntu-latest",
                "strategy": {"matrix": {"i": rows, "include": include}},
                "env": {"TITLE": "${{ github.event.issue.title }}"},
                "steps": [{"run": "echo building"}],
            }},
        });
        let workflow = Workflow::from_string(
            workflow.to_string(),
            InputKey::local("test".into(), "build.yml", None, None),
        )?;
        let Job::NormalJob(job) = workflow.jobs().next().unwrap() else {
            panic!("expected a build job");
        };
        let step = job.steps().next().unwrap();
        let expr = Expr::parse("env.TITLE")?;
        let results = step.evaluate(&expr);
        let [title] = results.values.as_slice() else {
            panic!("expected one title shared by all rows");
        };
        assert!(
            title
                .dependencies()
                .sources
                .contains(&Source::new("github.event.issue.title"))
        );
        Ok(())
    }
}
