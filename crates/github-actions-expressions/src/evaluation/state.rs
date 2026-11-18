//! Shared decisions, work limits, and operations for combining outcomes.

use std::collections::{BTreeMap, BTreeSet};

use super::{DecisionId, Outcome, Outcomes, TrackedValue};

/// Tracks decisions and work limits for one evaluation.
///
/// When a context lookup evaluates another expression, pass it the same state.
/// Both expressions can then refer to the same decisions and draw on the same
/// work budget.
#[derive(Default)]
pub(super) struct State {
    pub(super) definitions: BTreeMap<usize, DecisionId>,
    pub(super) materialized: BTreeMap<(usize, Vec<String>), Outcomes>,
    depth: usize,
    pub(super) budget: Budget,
    next_decision: usize,
    predicates: BTreeMap<Predicate, DecisionId>,
}

/// Identifies a repeated predicate by its verbatim expression text and the
/// union of its source and control paths.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Predicate {
    expression: String,
    inputs: BTreeSet<String>,
}

const MAX_ALTERNATIVES: usize = 256;
const MAX_DEPTH: usize = 64;
const MAX_WORK: usize = 16_384;

/// The work and alternative limits shared by an expression and its bindings.
#[derive(Default)]
pub struct Budget {
    work: usize,
    incomplete: bool,
}

impl Budget {
    /// Collect alternatives up to the result and work limits. If either limit
    /// cuts the collection short, mark this evaluation incomplete.
    pub fn bound<T>(&mut self, values: impl IntoIterator<Item = T>) -> Vec<T> {
        let mut results = Vec::new();
        for value in values {
            if !self.checkpoint() {
                break;
            }
            if results.len() == MAX_ALTERNATIVES {
                self.incomplete = true;
                break;
            }
            results.push(value);
        }
        results
    }

    /// Charge one unit of work. A `false` result means this unit exceeds the
    /// budget and the caller should stop exploring.
    pub fn checkpoint(&mut self) -> bool {
        self.work += 1;
        let available = self.work <= MAX_WORK;
        self.incomplete |= !available;
        available
    }
}

impl State {
    /// Allocate a new decision ID in this state.
    ///
    /// Keep the ID if later lookups depend on the same choice. For example,
    /// all reads of a job's matrix fields depend on which row that job uses.
    /// They share a decision ID, with a different alternative for each row.
    pub(super) fn decision(&mut self) -> DecisionId {
        let id = DecisionId(self.next_decision);
        self.next_decision += 1;
        id
    }

    /// Find or allocate the decision for this predicate. Without a source or
    /// control path, we have no binding identity to associate with another read.
    pub(super) fn predicate(
        &mut self,
        expression: &str,
        value: &TrackedValue,
    ) -> Option<DecisionId> {
        let mut provenance = value.dependencies();
        provenance.sources.extend(provenance.controls);
        if provenance.sources.is_empty() {
            return None;
        }
        let predicate = Predicate {
            expression: expression.into(),
            inputs: provenance.sources,
        };
        if let Some(id) = self.predicates.get(&predicate) {
            return Some(*id);
        }
        let id = self.decision();
        self.predicates.insert(predicate, id);
        Some(id)
    }

    /// If a limit cut evaluation short, add one unknown outcome for the
    /// unexplored alternatives when the outermost evaluation finishes. This
    /// outcome is marked incomplete and counts toward the result limit.
    pub(super) fn finish(&self, mut values: Outcomes) -> Outcomes {
        if self.depth == 0 && self.budget.incomplete {
            values.truncate(MAX_ALTERNATIVES - 1);
            values.push(Outcome::new(TrackedValue::incomplete()));
        }
        values
    }

    /// Charge for visiting an expression and bound its outcomes. Only the
    /// outermost visit adds the unknown remainder if a limit was reached.
    pub(super) fn within_limits(&mut self, visit: impl FnOnce(&mut Self) -> Outcomes) -> Outcomes {
        if self.exhausted() {
            return self.finish(vec![]);
        }

        let values = self.nested(visit);
        let values = self.budget.bound(values);
        self.finish(values)
    }

    pub(super) fn nested<T>(&mut self, evaluate: impl FnOnce(&mut Self) -> T) -> T {
        self.depth += 1;
        let result = evaluate(self);
        self.depth -= 1;
        result
    }

    pub(super) fn exhausted(&mut self) -> bool {
        let exhausted = self.depth >= MAX_DEPTH || !self.budget.checkpoint();
        self.budget.incomplete |= exhausted;
        exhausted
    }

    /// Evaluate each part and collect one value per part, in input order, for
    /// each compatible combination. For example, a function call uses this to
    /// build its possible argument lists. Empty input yields one empty list.
    pub(super) fn sequence<T, U: Clone>(
        &mut self,
        parts: impl IntoIterator<Item = T>,
        mut evaluate: impl FnMut(&mut Self, T) -> Outcomes<U>,
    ) -> Outcomes<Vec<U>> {
        let mut combinations = vec![Outcome::new(vec![])];
        for part in parts {
            let values = evaluate(self, part);
            combinations = self.product(combinations, values, |mut items, value| {
                items.push(value);
                items
            });
            if combinations.is_empty() {
                break;
            }
        }
        combinations
    }

    /// Combine each left outcome with each compatible right outcome.
    ///
    /// Two outcomes are compatible if they agree on every decision present in
    /// both. Each result carries the union of their assumptions and the value
    /// returned by `value`. All decision IDs must belong to this state.
    pub(super) fn product<T: Clone, U: Clone, V>(
        &mut self,
        left: Outcomes<T>,
        right: Outcomes<U>,
        mut value: impl FnMut(T, U) -> V,
    ) -> Outcomes<V> {
        let mut results = vec![];
        for lhs in &left {
            for rhs in &right {
                if !self.budget.checkpoint() {
                    return results;
                }
                let Some(pair) = lhs.combine(rhs, &mut value) else {
                    continue;
                };
                results.push(pair);
                if results.len() > MAX_ALTERNATIVES {
                    return self.budget.bound(results);
                }
            }
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Expr;

    #[test]
    fn resource_limits_retain_an_unknown_remainder() {
        let mut analysis = State {
            budget: Budget {
                work: MAX_WORK,
                ..Budget::default()
            },
            ..State::default()
        };
        let parsed = Expr::parse("config.x").unwrap();
        let values = analysis.evaluate(&parsed, &super::super::Scope::default());
        assert_eq!(values.len(), 1);
        assert!(values[0].value.provenance.incomplete);

        let mut analysis = State::default();
        analysis.budget.bound(vec![(); MAX_ALTERNATIVES + 1]);
        let values = analysis.finish(Outcomes::default());
        assert_eq!(values.len(), 1);
        assert!(values[0].value.provenance.incomplete);
    }
}
