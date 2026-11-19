//! Abstract interpretation and evaluation of Actions expressions.
//!
//! [`Evaluator::evaluate`] interprets one expression against one [`Bindings`]
//! environment. When a binding is itself an expression, its provider evaluates
//! it in the declaring environment with the same evaluator.
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
//! The evaluator allocates decision IDs. A bindings provider can request one
//! with [`Evaluator::decision`] when it supplies alternatives of its own.
//! Outcomes can be combined when their assumptions agree.
//!
//! Finally, each outcome of an evaluation comes with [`Provenance`], which
//! records the inputs and source locations used to obtain a value.
//! Callers can use this to explain the result in a human-friendly manner.

mod state;
mod template;
#[cfg(test)]
mod tests;
mod value;

pub use state::{Budget, Evaluator};
pub use template::fenced_span;
pub use value::*;

use crate::{
    Evaluation, Expr, SpannedExpr,
    call::{Call, Function, Function::*},
    op::{BinExpr, BinOp},
};

/// The context values visible at one evaluation site.
pub trait Bindings {
    /// The first key names the context. Subsequent accesses have their
    /// computed indices already evaluated. Return an unknown value for a runtime input, null for a known missing
    /// property, or no outcomes for an evaluation that cannot succeed.
    fn lookup(&mut self, path: &[Access], evaluator: &mut Evaluator) -> Outcomes;
}

/// An object (or a runtime reference) can be used directly as an environment.
impl Bindings for TrackedValue {
    fn lookup(&mut self, path: &[Access], _: &mut Evaluator) -> Outcomes {
        vec![Outcome::new(self.clone().apply_path(path))]
    }
}

/// Context references cannot be resolved during constant evaluation.
pub(crate) struct Constants;

impl Bindings for Constants {
    fn lookup(&mut self, _: &[Access], _: &mut Evaluator) -> Outcomes {
        vec![]
    }
}

impl Evaluator {
    /// Evaluate an expression using the supplied bindings. Nested lookups share this evaluation's decisions and limits.
    pub fn evaluate(&mut self, expr: &Expr<'_>, bindings: &mut dyn Bindings) -> Outcomes {
        self.within_limits(|state| match expr {
            Expr::Literal(literal) => vec![Outcome::known(literal.consteval())],
            Expr::UnExpr { expr, .. } => state.evaluate(expr, bindings).map(TrackedValue::negate),
            Expr::BinExpr(bin) if matches!(bin.op, BinOp::And | BinOp::Or) => {
                state.short_circuit(bin, bindings)
            }
            Expr::BinExpr(bin) => {
                let lhs = state.evaluate(&bin.lhs, bindings);
                let rhs = state.evaluate(&bin.rhs, bindings);
                state.product(lhs, rhs, |lhs, rhs| lhs.compare(&bin.op, &rhs))
            }
            Expr::Context(reference) => state.context(&reference.parts, bindings),
            Expr::Call(call) if call.func == Format => state.format(&call.args, bindings),
            Expr::Call(call) if call.func == Case => state.case(&call.args, bindings),
            Expr::Call(call) => {
                let args = state.sequence(&call.args, |state, arg| state.evaluate(arg, bindings));
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
    fn short_circuit(&mut self, bin: &BinExpr<'_>, bindings: &mut dyn Bindings) -> Outcomes {
        let left = self.evaluate(&bin.lhs, bindings);
        let (falsy, truthy) = self.conditions(bin.lhs.origin.raw, left);
        let (mut results, continued) = match bin.op {
            BinOp::Or => (truthy, falsy),
            BinOp::And => (
                falsy.map(|value| {
                    if value.truth().is_some() {
                        value
                    } else {
                        TrackedValue::new(AbstractValue::Unknown(Shape::Falsy)).conditioned(&value)
                    }
                }),
                truthy,
            ),
            _ => unreachable!("short-circuit operator"),
        };
        if !continued.is_empty() {
            let right = self.evaluate(&bin.rhs, bindings);
            results.extend(self.product(continued, right, |condition, value| {
                value.conditioned(&condition)
            }));
        }
        results
    }

    /// Evaluate each reachable arm once, then attach the assumptions that reach it.
    fn case(&mut self, args: &[SpannedExpr<'_>], bindings: &mut dyn Bindings) -> Outcomes {
        if self.exhausted() {
            return vec![];
        }
        let (predicate, selected, remaining) = match args {
            [fallback] => return self.evaluate(fallback, bindings),
            [predicate, selected, remaining @ ..] => (predicate, selected, remaining),
            [] => return vec![],
        };

        let predicates = self.evaluate(predicate, bindings);
        let booleans = predicates.into_iter().filter(|p| p.value.can_be_boolean());
        let (falsy, truthy) = self.conditions(predicate.origin.raw, booleans);
        let mut results = vec![];
        if !falsy.is_empty() {
            let fallback = self.nested(|state| state.case(remaining, bindings));
            results = self.product(falsy, fallback, |condition, value| {
                value.conditioned(&condition)
            });
        }
        if !truthy.is_empty() {
            let selected = self.evaluate(selected, bindings);
            results.extend(self.product(truthy, selected, |condition, value| {
                value.conditioned(&condition)
            }));
        }
        self.budget.limit(results)
    }

    /// Separate false and true branches. A known truth value already carries
    /// its binding's choices. Only an unresolved predicate needs a new assumption.
    fn conditions(
        &mut self,
        expression: &str,
        outcomes: impl IntoIterator<Item = Outcome>,
    ) -> (Outcomes, Outcomes) {
        let mut falsy = vec![];
        let mut truthy = vec![];
        for outcome in outcomes {
            match outcome.value.truth() {
                Some(false) => falsy.push(outcome),
                Some(true) => truthy.push(outcome),
                None => {
                    if let Some(id) = self.predicate(expression, &outcome.value) {
                        falsy.extend(outcome.clone().assume(id, AlternativeId::new(0)));
                        truthy.extend(outcome.assume(id, AlternativeId::new(1)));
                    } else {
                        falsy.push(outcome.clone());
                        truthy.push(outcome);
                    }
                }
            }
        }
        (falsy, truthy)
    }

    /// Look up a named context such as `env.NAME` using its full path. For
    /// `fromJSON(inputs.data).name`, evaluate the call first, then apply
    /// the field access to each value it returns.
    fn context(&mut self, parts: &[SpannedExpr<'_>], bindings: &mut dyn Bindings) -> Outcomes {
        let (first, rest) = parts.split_first().expect("parsed context has a head");
        if matches!(first.inner, Expr::Identifier(_)) {
            let paths = self.paths(parts, bindings);
            return self.flat_map(paths, |state, path| {
                bindings
                    .lookup(&path.parts, state)
                    .map(|value| value.with_provenance(&path.provenance))
            });
        }

        let mut values = self.evaluate(first, bindings);
        for part in rest {
            let keys = self.keys(part, bindings);
            values = self.product(values, keys, |value, (key, provenance)| {
                value.apply_access(&key).with_provenance(&provenance)
            });
        }
        values
    }

    fn paths(&mut self, parts: &[SpannedExpr<'_>], bindings: &mut dyn Bindings) -> Outcomes<Path> {
        let mut paths = vec![Outcome::new(Path::default())];
        for part in parts {
            let keys = self.keys(part, bindings);
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
    fn keys(
        &mut self,
        part: &SpannedExpr<'_>,
        bindings: &mut dyn Bindings,
    ) -> Outcomes<(Access, Provenance)> {
        let access = match &part.inner {
            Expr::Identifier(key) => Access::from(key.as_str()),
            Expr::Star => Access::Wildcard,
            Expr::Index(index) => return self.keys(index, bindings),
            _ => {
                return self.evaluate(part, bindings).map(|value| {
                    let key = value.concrete().map_or(Access::Unknown, Access::from_value);
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
            Contains
                if let [haystack, needle] = self.value.as_slice()
                    && let Some(items) = haystack.elements() =>
            {
                // Compare tracked elements before converting to JSON loses object identity.
                let mut found = Some(false);
                for item in items {
                    match item.compare(&BinOp::Eq, needle).truth() {
                        Some(true) => {
                            found = Some(true);
                            break;
                        }
                        None => found = None,
                        Some(false) => {}
                    }
                }
                found.map_or(unknown, |value| {
                    TrackedValue::known(Evaluation::Boolean(value))
                })
            }
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
