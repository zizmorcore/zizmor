//! Expand a matrix into complete job rows, retaining the origin of each field.
use indexmap::IndexMap;
use std::sync::Arc;

use github_actions_expressions::evaluation::{
    AbstractValue, Budget, Evaluator, Outcome, Outcomes, OutcomesExt as _, Provenance, TrackedValue,
};
use itertools::Itertools as _;
use serde_json::Value;

use super::Matrix;
use crate::finding::location::{Locatable as _, SymbolicLocation};

type Row = IndexMap<String, TrackedValue>;

impl<'doc> Matrix<'doc> {
    /// Evaluate scalar leaves at their YAML locations and expand the resulting definitions.
    pub(crate) fn rows(
        &self,
        eval: &mut Evaluator,
        mut evaluate: impl FnMut(&mut Evaluator, &Value, SymbolicLocation<'doc>) -> Outcomes,
    ) -> Outcomes {
        let location = self.location().annotated("matrix value defined here");
        let value = serde_json::to_value(self.inner).expect("validated matrix");
        let definitions = Self::decode(eval, &value, location, &mut evaluate);
        eval.flat_map(definitions, |eval, value| {
            expand_rows(value, &mut eval.budget)
                .into_iter()
                .map(|row| Outcome::new(row.with_provenance(&value.provenance)))
                .collect()
        })
    }

    fn decode(
        eval: &mut Evaluator,
        value: &Value,
        location: SymbolicLocation<'doc>,
        evaluate: &mut impl FnMut(&mut Evaluator, &Value, SymbolicLocation<'doc>) -> Outcomes,
    ) -> Outcomes {
        if !eval.budget.checkpoint() {
            return vec![];
        }
        let entries: Vec<_> = match value {
            Value::Array(items) => items
                .iter()
                .enumerate()
                .map(|(i, item)| (item, location.with_keys([i.into()])))
                .collect(),
            Value::Object(fields) => fields
                .iter()
                .map(|(k, item)| (item, location.with_keys([k.clone().into()])))
                .collect(),
            _ => return evaluate(eval, value, location),
        };
        eval.sequence(entries, |eval, (item, location)| {
            Self::decode(eval, item, location, evaluate)
        })
        .map(|items| {
            TrackedValue::new(match value {
                Value::Object(fields) => {
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

    let mut includes = vec![];
    let mut unknown_include = None;
    if let Some(value) = definition.shift_remove("include") {
        for include in value.elements().unwrap_or_else(|| vec![value]) {
            let AbstractValue::Object(fields) = include.inner else {
                unknown_include
                    .get_or_insert_with(Provenance::default)
                    .extend(&include.dependencies());
                continue;
            };
            let mut fields = Arc::unwrap_or_clone(fields);
            for value in fields.values_mut() {
                value.provenance.extend(&include.provenance);
            }
            includes.push(Include {
                fields,
                standalone: true,
            });
        }
    }
    let excludes = definition
        .shift_remove("exclude")
        .and_then(|value| value.elements())
        .unwrap_or_default();

    let mut rows = if definition.is_empty() {
        vec![]
    } else {
        vec![Row::new()]
    };
    for (key, dimension) in definition {
        let values = match &dimension.inner {
            AbstractValue::Unknown(_) | AbstractValue::Reference(_) => {
                vec![TrackedValue::unknown().with_provenance(&dimension.dependencies())]
            }
            _ => match dimension.elements() {
                Some(values) => values,
                None => return vec![],
            },
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

    // Includes match against the original dimensions. Later includes may
    // overwrite fields added by an earlier include, but never an original axis.
    let mut results = vec![];
    'rows: for original in rows {
        for exclude in &excludes {
            if !budget.checkpoint() {
                return results;
            }
            if let AbstractValue::Object(fields) = &exclude.inner
                && matches_row(&original, fields, false) == Some(true)
            {
                continue 'rows;
            }
        }
        let mut variants = vec![original.clone()];
        for include in &mut includes {
            if !budget.checkpoint() {
                return results;
            }
            variants = include.apply(&original, variants, budget);
        }
        results.extend(variants.into_iter().map(row_value));
    }
    results.extend(
        includes
            .into_iter()
            .filter(|include| include.standalone)
            .map(|include| row_value(include.fields)),
    );
    if let Some(include) = unknown_include {
        // This include can add a standalone row or merge with an existing row.
        // Only the include's location is common to both possibilities.
        let mut possible = value.dependencies();
        possible.evidence = include.evidence;
        results.push(TrackedValue::unknown().with_provenance(&possible));
    }
    results
}

fn row_value(row: Row) -> TrackedValue {
    TrackedValue::new(AbstractValue::Object(Arc::new(row)))
}

struct Include {
    fields: Row,
    standalone: bool,
}

impl Include {
    fn apply(&mut self, original: &Row, mut variants: Vec<Row>, budget: &mut Budget) -> Vec<Row> {
        let matched = matches_row(original, &self.fields, true);
        if matched == Some(false) {
            return variants;
        }

        let mut control = Provenance::default();
        for (key, expected) in &self.fields {
            if let Some(axis) = original.get(key) {
                control.extend(&axis.dependencies());
                control.extend(&expected.dependencies());
            }
        }
        let control = control.controlled();
        let merge = |row: &mut Row| {
            row.extend(
                self.fields
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone().with_provenance(&control))),
            )
        };

        if matched == Some(true) {
            self.standalone = false;
            variants.iter_mut().for_each(merge);
            return variants;
        }

        // An unknown axis can either match or leave the original row alone.
        budget.bound(variants.into_iter().flat_map(|row| {
            let mut merged = row.clone();
            merge(&mut merged);
            [row, merged]
        }))
    }
}

/// An unresolved field may match. A single known mismatch rules out the row.
fn matches_row(original: &Row, fields: &Row, allow_new_keys: bool) -> Option<bool> {
    let mut matched = Some(true);
    for (key, expected) in fields {
        match original.get(key) {
            None if !allow_new_keys => return Some(false),
            None => continue,
            Some(value) => match (value.concrete(), expected.concrete()) {
                (Some(a), Some(b)) if a != b => return Some(false),
                (Some(_), Some(_)) => {}
                _ => matched = None,
            },
        }
    }
    matched
}
