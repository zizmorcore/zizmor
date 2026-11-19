//! Expand a matrix into complete job rows, retaining the origin of each field.
use indexmap::IndexMap;
use std::sync::Arc;

use github_actions_expressions::evaluation::{
    AbstractValue, Budget, Evaluator, Outcome, Outcomes, OutcomesExt as _, TrackedValue,
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

    let mut unknown_include = false;
    let includes = definition
        .shift_remove("include")
        .map_or_else(Vec::new, |value| {
            value.elements().unwrap_or_else(|| {
                unknown_include = true;
                vec![]
            })
        });
    let mut includes: Vec<_> = includes
        .into_iter()
        .filter_map(|include| {
            let AbstractValue::Object(fields) = include.inner else {
                unknown_include = true;
                return None;
            };
            let mut fields = Arc::unwrap_or_clone(fields);
            for value in fields.values_mut() {
                value.provenance.extend(&include.provenance);
            }
            Some((fields, true))
        })
        .collect();
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
        for (fields, standalone) in &mut includes {
            if !budget.checkpoint() {
                return results;
            }
            match matches_row(&original, fields, true) {
                Some(false) => continue,
                Some(true) => {
                    *standalone = false;
                    for row in &mut variants {
                        row.extend(fields.clone());
                    }
                }
                None => {
                    // The unknown axis may match. Preserve both outcomes,
                    // including any fields supplied by earlier includes.
                    variants = budget.bound(variants.into_iter().flat_map(|row| {
                        let mut merged = row.clone();
                        merged.extend(fields.clone());
                        [row, merged]
                    }));
                }
            }
        }
        results.extend(variants.into_iter().map(row_value));
    }
    results.extend(
        includes
            .into_iter()
            .filter(|(_, standalone)| *standalone)
            .map(|(fields, _)| row_value(fields)),
    );
    if unknown_include {
        results.push(TrackedValue::unknown().with_provenance(&value.dependencies()));
    }
    results
}

fn row_value(row: Row) -> TrackedValue {
    TrackedValue::new(AbstractValue::Object(Arc::new(row)))
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
