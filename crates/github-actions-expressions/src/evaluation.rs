//! Abstract interpretation and evaluation of Actions expressions.
//!
//! A [`Scope`] binds context names to [`Definition`]s. A template captures the
//! scope of its declaration, so reading it from a second scope still resolves
//! its names in the first. Each call to [`Scope::evaluate`] starts a fresh
//! evaluation and follows the definitions the expression reads.
//!
//! Expressions are evaluated into zero or more [`Outcome`]s, each of which contains
//! a value and the assumptions that the interpreter made to obtain it. Assumptions
//! are themselves a mapping of shared choices ([`DecisionId`]) to alternatives
//! taken ([`AlternativeId`]).
//!
//! The evaluator is responsible for identifying decisions. This is not as trivial as
//! assigning a fresh identifier for every predicate or similar. For example:
//!
//! ```text
//! format('{0}/{1}',
//!    case(inputs.enabled, 'a', 'b'),
//!    case(inputs.enabled, 'a', 'b'))
//! ```
//!
//! A naive decision allocation would assign a new decision identifier for each `inputs.enabled`
//! in the expression. However, doing that would allow for inconsistent alternatives/outcomes,
//! since each `inputs.enabled` would appear independent during analysis. This in turn would
//! result in imprecisions, since it would admit combinations like `a/b` when only `a/a`
//! and `b/b` are actually possible.
//!
//! An evaluation's decisions are managed internally. The evaluator
//! allocates new decisions and can also merge outcomes together when their
//! assumptions agree.
//!
//! Finally, each outcome of an evaluation comes with [`Provenance`], which
//! records the inputs and source locations used to obtain a value.
//! Callers can use this to explain the result in a human-friendly manner.

mod definitions;
mod matrix;
mod state;
mod template;
#[cfg(test)]
mod tests;
mod value;

pub use definitions::{Definition, Scope};
use state::State;
pub use template::fenced_span;
pub use value::*;

use crate::{
    Evaluation, Expr, SpannedExpr,
    call::{Call, Function, Function::*},
    op::{BinExpr, BinOp},
};

impl State {
    fn evaluate(&mut self, expr: &Expr<'_>, scope: &Scope) -> Outcomes {
        self.within_limits(|state| match expr {
            Expr::Literal(literal) => vec![Outcome::known(literal.consteval())],
            Expr::UnExpr { expr, .. } => state.evaluate(expr, scope).map(TrackedValue::negate),
            Expr::BinExpr(bin) if matches!(bin.op, BinOp::And | BinOp::Or) => {
                state.short_circuit(bin, scope)
            }
            Expr::BinExpr(bin) => {
                let lhs = state.evaluate(&bin.lhs, scope);
                let rhs = state.evaluate(&bin.rhs, scope);
                state.product(lhs, rhs, |lhs, rhs| lhs.compare(&bin.op, &rhs))
            }
            Expr::Context(reference) => state.context(&reference.parts, scope),
            Expr::Call(call) if call.func == Case => state.case(&call.args, scope),
            Expr::Call(call) => {
                let args = state.sequence(&call.args, |state, arg| state.evaluate(arg, scope));
                args.into_iter()
                    .filter_map(|args| args.evaluate_call(call.func))
                    .collect()
            }
            Expr::Identifier(_) | Expr::Index(_) | Expr::Star => Outcomes::default(),
        })
    }

    /// For each possible truth value of the left operand, return the operand
    /// selected by `&&` or `||`. Evaluate the right operand only on branches
    /// that reach it.
    fn short_circuit(&mut self, bin: &BinExpr<'_>, scope: &Scope) -> Outcomes {
        let left = self.evaluate(&bin.lhs, scope);
        let mut results = vec![];
        for (truth, condition) in self.conditions(bin.lhs.origin.raw, left) {
            match (&bin.op, truth) {
                (BinOp::Or, true) => results.push(condition),
                (BinOp::And, false) => results.push(condition.map(|value| {
                    // On this branch the left operand must be falsy.
                    if value.truth().is_some() {
                        value
                    } else {
                        TrackedValue::new(AbstractValue::Unknown(Shape::Falsy)).conditioned(&value)
                    }
                })),
                _ => {
                    let right = self.evaluate(&bin.rhs, scope);
                    results.extend(self.product(vec![condition], right, |predicate, value| {
                        value.conditioned(&predicate)
                    }));
                }
            }
        }
        self.bound(results)
    }

    /// Evaluate predicate/value pairs in order. A true branch selects its
    /// paired value. A false branch continues to the next pair or the fallback.
    fn case(&mut self, args: &[SpannedExpr<'_>], scope: &Scope) -> Outcomes {
        if self.exhausted() {
            return Outcomes::default();
        }
        let (predicate, selected, remaining) = match args {
            [fallback] => return self.evaluate(fallback, scope),
            [predicate, selected, remaining @ ..] => (predicate, selected, remaining),
            [] => unreachable!("a parsed case expression has a fallback"),
        };

        let predicates = self.evaluate(predicate, scope);
        let booleans = predicates.into_iter().filter(|p| p.value.can_be_boolean());
        let mut results = vec![];
        for (truth, condition) in self.conditions(predicate.origin.raw, booleans) {
            let values = self.nested(|state| {
                if truth {
                    state.evaluate(selected, scope)
                } else {
                    state.case(remaining, scope)
                }
            });
            results.extend(self.product(vec![condition], values, |condition, value| {
                value.conditioned(&condition)
            }));
        }
        self.bound(results)
    }

    /// Pair each possible truth value with the outcome and assumptions that permit it.
    fn conditions(
        &mut self,
        expression: &str,
        outcomes: impl IntoIterator<Item = Outcome>,
    ) -> Vec<(bool, Outcome)> {
        let mut conditions = vec![];
        for outcome in outcomes {
            let truths: &[bool] = match outcome.value.truth() {
                Some(true) => &[true],
                Some(false) => &[false],
                None => &[false, true],
            };
            let decision = self.predicate(expression, &outcome.value);
            for &truth in truths {
                let branch = match decision {
                    Some(id) => outcome
                        .clone()
                        .assume(id, AlternativeId::new(usize::from(truth))),
                    None => Some(outcome.clone()),
                };
                if let Some(branch) = branch {
                    conditions.push((truth, branch));
                }
            }
        }
        self.bound(conditions)
    }

    /// Look up a named context such as `env.NAME` using its full path. For
    /// `fromJSON(inputs.data).name`, evaluate the call first, then apply
    /// the field access to each value it returns.
    fn context(&mut self, parts: &[SpannedExpr<'_>], scope: &Scope) -> Outcomes {
        let (first, rest) = parts.split_first().expect("parsed context has a head");
        if matches!(first.inner, Expr::Identifier(_)) {
            let mut results = vec![];
            for path in self.paths(parts, scope) {
                let values = scope.read(self, &path.value.parts, &path.value.parts);
                results.extend(self.product(vec![path], values, |path, value| {
                    value.with_provenance(&path.provenance)
                }));
            }
            return self.bound(results);
        }

        let mut values = self.evaluate(first, scope);
        for part in rest {
            let keys = self.keys(part, scope);
            values = self.product(values, keys, |value, (key, provenance)| {
                value.apply_access(&key).with_provenance(&provenance)
            });
        }
        values
    }

    fn paths(&mut self, parts: &[SpannedExpr<'_>], scope: &Scope) -> Outcomes<Path> {
        let mut paths = vec![Outcome::new(Path::default())];
        for part in parts {
            let keys = self.keys(part, scope);
            paths = self.product(paths, keys, |mut path, (key, provenance)| {
                path.parts.push(key);
                path.provenance.extend(&provenance);
                path
            });
        }
        paths
    }

    /// Evaluate one path component. A computed index can produce several keys
    /// or an unknown key. Each carries the dependencies used to compute it.
    fn keys(&mut self, part: &SpannedExpr<'_>, scope: &Scope) -> Outcomes<(Access, Provenance)> {
        let access = match &part.inner {
            Expr::Identifier(key) => Access::Key(key.as_str().into()),
            Expr::Star => Access::Wildcard,
            Expr::Index(index) => return self.keys(index, scope),
            _ => {
                return self.evaluate(part, scope).map(|value| {
                    let key = value.concrete().map_or(Access::Unknown, |value| {
                        Access::Key(value.sema().to_string())
                    });
                    (key, value.dependencies().controlled())
                });
            }
        };
        vec![Outcome::new((access, Provenance::default()))]
    }
}

/// One possible context path, together with the provenance of its computed indices.
///
/// For `env[inputs.field]`, the index determines which field is read. Its
/// dependencies become control provenance on the value returned by the lookup.
#[derive(Clone, Default)]
struct Path {
    parts: Vec<Access>,
    provenance: Provenance,
}

impl Outcome<Vec<TrackedValue>> {
    /// Evaluate a function for one compatible argument list. For example,
    /// `hashFiles` needs the runner's files even if its patterns are known,
    /// so its result has shape [`Shape::Hash`].
    fn evaluate_call(self, function: Function) -> Option<Outcome> {
        let mut provenance = Provenance::default();
        for value in &self.value {
            provenance.extend(&value.dependencies());
        }

        let shape = match function {
            Contains | StartsWith | EndsWith | Success | Failure | Cancelled | Always => {
                Shape::Boolean
            }
            HashFiles => Shape::Hash,
            _ => Shape::Any,
        };
        if matches!(shape, Shape::Boolean | Shape::Hash) {
            provenance = provenance.controlled();
        }

        let unknown = TrackedValue::new(AbstractValue::Unknown(shape));
        let value = match function {
            Always => TrackedValue::known(Evaluation::Boolean(true)),
            Success | Failure | Cancelled | HashFiles => unknown,
            _ => {
                let args: Option<Vec<_>> = self.value.iter().map(TrackedValue::concrete).collect();
                match args {
                    Some(args) => TrackedValue::known(Call::evaluate(function, &args)?),
                    None => unknown,
                }
            }
        };
        Some(self.map(|_| value.with_provenance(&provenance)))
    }
}
