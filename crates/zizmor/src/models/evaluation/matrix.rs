//! Expand matrix rows independently of expression provenance and assumptions.

use super::*;
use itertools::Itertools as _;

type Row = BTreeMap<String, TrackedValue>;

impl<'doc> Bindings<'doc> {
    fn expand_rows(state: &mut State, mut definition: Row) -> Vec<TrackedValue> {
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
            rows = state.bound(rows.into_iter().cartesian_product(values).map(
                |(mut row, value)| {
                    row.insert(key.clone(), value);
                    row
                },
            ));
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
                if !state.checkpoint() {
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
        state.bound(rows)
    }

    pub(super) fn matrix(
        &mut self,
        state: &mut State,
        path: &[Access],
        context: &Context<'doc>,
    ) -> Outcomes {
        let Some(job) = context.job.clone() else {
            return self.runtime(path, context);
        };
        let Some(matrix) = job.strategy.as_ref().and_then(|s| s.matrix.as_ref()) else {
            return vec![Outcome::known(Evaluation::String(String::new()))];
        };
        let key = job.id().to_owned();
        if !self.matrices.contains_key(&key) {
            let child = Context {
                phase: Phase::Matrix,
                ..context.clone()
            };
            let location = job
                .location()
                .with_keys(["strategy".into(), "matrix".into()])
                .annotated("matrix value defined here");
            let value = serde_json::to_value(matrix).expect("validated matrix");
            let mut rows = vec![];
            for definition in self.decode(state, &value, location, &child) {
                let provenance = definition.value.provenance.clone();
                let values = match definition.value.inner {
                    AbstractValue::Object(fields) => {
                        Self::expand_rows(state, fields.as_ref().clone())
                    }
                    AbstractValue::Unknown(_) | AbstractValue::Reference(_) => {
                        vec![definition.value]
                    }
                    _ => vec![],
                };
                rows.extend(values.into_iter().map(|value| Outcome {
                    value: value.with_provenance(&provenance),
                    choices: definition.choices.clone(),
                }));
            }
            let decision = state.decision();
            self.matrices.insert(key.clone(), (decision, rows));
        }
        let (decision, rows) = &self.matrices[&key];
        let mut values = rows.to_vec();
        for (index, row) in values.iter_mut().enumerate() {
            row.choices.insert(*decision, AlternativeId::new(index));
            for access in &path[1..] {
                row.value = row.value.apply_access(access);
            }
        }
        state.bound(values)
    }
}
