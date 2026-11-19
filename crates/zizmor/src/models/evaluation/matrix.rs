//! Instantiate a job's bindings once per matrix row.
use super::*;
use itertools::Itertools as _;
use std::sync::Arc;

type Row = BTreeMap<String, TrackedValue>;

impl<'doc> Environment<'_, 'doc> {
    pub(super) fn in_rows(
        &mut self,
        eval: &mut Evaluator,
        run: impl Fn(&mut Evaluator, &mut Environment<'_, 'doc>) -> Outcomes,
    ) -> Outcomes {
        let context = self.context;
        let Some(job) = &context.job else {
            return run(eval, self);
        };
        let Some(matrix) = job.strategy.as_ref().and_then(|s| s.matrix.as_ref()) else {
            return run(eval, self);
        };
        if !self.cache.rows.contains_key(job.id()) {
            let location = job
                .location()
                .with_keys(["strategy".into(), "matrix".into()])
                .annotated("matrix value defined here");
            let value = serde_json::to_value(matrix).expect("validated matrix");
            let child = Context {
                phase: Phase::Matrix,
                ..context.clone()
            };
            let definitions = self.at(&child).decode(eval, &value, location);
            let rows = eval.flat_map(definitions, |eval, value| {
                expand_rows(value, &mut eval.budget)
                    .into_iter()
                    .map(|row| Outcome::new(row.with_provenance(&value.provenance)))
                    .collect()
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
            let child = Context {
                row: Some(row.clone()),
                ..context.clone()
            };
            run(eval, &mut self.at(&child))
        })
    }

    fn decode(
        &mut self,
        eval: &mut Evaluator,
        value: &serde_json::Value,
        location: SymbolicLocation<'doc>,
    ) -> Outcomes {
        if !eval.budget.checkpoint() {
            return vec![];
        }
        let entries: Vec<_> = match value {
            serde_json::Value::String(text) => {
                let values = eval.template(text, self);
                return located(values, self.results.record(location));
            }
            serde_json::Value::Array(items) => items
                .iter()
                .enumerate()
                .map(|(i, item)| (item, location.with_keys([i.into()])))
                .collect(),
            serde_json::Value::Object(fields) => fields
                .iter()
                .map(|(k, item)| (item, location.with_keys([k.clone().into()])))
                .collect(),
            _ => {
                return vec![Outcome::known(
                    value.clone().try_into().expect("JSON scalar"),
                )];
            }
        };
        eval.sequence(entries, |eval, (item, location)| {
            self.decode(eval, item, location)
        })
        .map(|items| {
            TrackedValue::new(match value {
                serde_json::Value::Object(fields) => {
                    AbstractValue::Object(Arc::new(fields.keys().cloned().zip(items).collect()))
                }
                _ => AbstractValue::Array(Arc::new(items)),
            })
        })
    }
}

fn expand_rows(value: &TrackedValue, budget: &mut Budget) -> Vec<TrackedValue> {
    let mut definition = match &value.inner {
        AbstractValue::Object(fields) => fields.as_ref().clone(),
        AbstractValue::Unknown(_) | AbstractValue::Reference(_) => return vec![value.clone()],
        _ => return vec![],
    };

    let matches_row = |row: &Row, condition: &Row, allow_new_keys: bool| {
        condition.iter().all(|(key, expected)| {
            row.get(key).map_or(allow_new_keys, |value| {
                value
                    .concrete()
                    .is_some_and(|value| Some(value) == expected.concrete())
            })
        })
    };

    let mut unknown = vec![];
    let includes = definition.remove("include").map_or_else(Vec::new, |value| {
        value.elements().unwrap_or_else(|| {
            unknown.push(value);
            vec![]
        })
    });
    let excludes = definition
        .remove("exclude")
        .and_then(|value| value.elements())
        .unwrap_or_default();
    let has_dimensions = !definition.is_empty();
    let mut rows = vec![Row::new()];
    for (key, dimension) in definition {
        let Some(values) = dimension.elements() else {
            unknown.push(dimension);
            continue;
        };
        rows = budget.bound(
            rows.into_iter()
                .cartesian_product(&values)
                .map(|(mut row, value)| {
                    row.insert(key.clone(), value.clone());
                    row
                }),
        );
    }

    rows.retain(|row| {
        !excludes.iter().any(
            |value| matches!(&value.inner, AbstractValue::Object(fields) if matches_row(row, fields, false)),
        )
    });
    let originals = rows.clone();
    let mut additional = vec![];
    for include in includes {
        let AbstractValue::Object(fields) = include.inner else {
            unknown.push(include);
            continue;
        };
        let mut fields = fields.as_ref().clone();
        for value in fields.values_mut() {
            value.provenance.extend(&include.provenance);
        }
        let mut matched = false;
        for (index, original) in originals.iter().enumerate() {
            if !budget.checkpoint() {
                return vec![];
            }
            if has_dimensions && matches_row(original, &fields, true) {
                rows[index].extend(fields.clone());
                matched = true;
            }
        }
        if !matched {
            additional.push(fields);
        }
    }
    if !has_dimensions {
        rows.clear();
    }
    rows.extend(additional);
    let mut rows = rows
        .into_iter()
        .map(|row| TrackedValue::new(AbstractValue::Object(Arc::new(row))))
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        let mut provenance = Provenance::default();
        for value in unknown {
            provenance.extend(&value.dependencies());
        }
        rows.push(TrackedValue::unknown().with_provenance(&provenance));
    }
    budget.bound(rows)
}
