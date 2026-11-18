//! Bind a job's matrix to a choice of rows. The definition captures the scope
//! available in `strategy.matrix`. Row expansion runs when the matrix is read.
use std::{collections::BTreeMap, sync::Arc};

use github_actions_expressions::evaluation::{
    AbstractValue, Budget, Definition, Provenance, Scope, TrackedValue,
};
use itertools::Itertools as _;

use super::{Builder, empty};
use crate::{
    finding::location::{Locatable as _, SymbolicLocation},
    models::workflow::NormalJob,
};

type Row = BTreeMap<String, TrackedValue>;

impl<'doc> Builder<'doc> {
    pub(super) fn matrix(&mut self, job: &NormalJob<'doc>, scope: &Scope) -> Definition {
        let Some(matrix) = job
            .strategy
            .as_ref()
            .and_then(|strategy| strategy.matrix.as_ref())
        else {
            return empty();
        };
        let location = job
            .location()
            .with_keys(["strategy".into(), "matrix".into()])
            .annotated("matrix value defined here");
        let value = serde_json::to_value(matrix).expect("validated matrix");
        self.matrix_value(&value, location, scope)
            .expand(expand_rows)
    }

    fn matrix_value(
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
                    .map(|(i, item)| self.matrix_value(item, location.with_keys([i.into()]), scope))
                    .collect(),
            ),
            serde_json::Value::Object(fields) => Definition::object(
                fields
                    .iter()
                    .map(|(key, item)| {
                        let child = location.with_keys([key.clone().into()]);
                        (key.clone(), self.matrix_value(item, child, scope))
                    })
                    .collect(),
            ),
            value => Definition::known(value.clone().try_into().expect("JSON scalar")),
        }
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
