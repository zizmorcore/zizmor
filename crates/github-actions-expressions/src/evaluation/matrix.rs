//! Expand matrix rows independently of expression provenance and assumptions.

use super::*;
use std::{collections::BTreeMap, sync::Arc};

type Row = BTreeMap<String, TrackedValue>;

impl State {
    pub(super) fn matrix_rows(
        &mut self,
        decision: DecisionId,
        inner: &Definition,
        path: &[Access],
    ) -> Outcomes {
        let mut rows = vec![];
        for outcome in inner.read(self, path, &[]) {
            let expanded = match &outcome.value.inner {
                AbstractValue::Object(fields) => self.expand_rows(fields.as_ref().clone()),
                AbstractValue::Unknown(_) | AbstractValue::Reference(_) => {
                    vec![outcome.value.clone()]
                }
                _ => vec![],
            };
            for row in expanded {
                if !self.checkpoint() {
                    break;
                }
                let index = rows.len();
                let row = outcome
                    .clone()
                    .map(|value| row.with_provenance(&value.provenance));
                rows.extend(row.assume(decision, AlternativeId::new(index)));
            }
        }
        self.bound(rows)
    }

    fn expand_rows(&mut self, mut definition: Row) -> Vec<TrackedValue> {
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
            rows = self.bound(rows.into_iter().flat_map(|row| {
                values.iter().map({
                    let key = &key;
                    move |value| {
                        let mut row = row.clone();
                        row.insert(key.clone(), value.clone());
                        row
                    }
                })
            }));
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
                if !self.checkpoint() {
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
        self.bound(rows)
    }
}
