//! Evaluate expressions under caller-supplied bindings, retaining alternatives and provenance.
//!
//! Each [`Outcome`] contains a value and the assumptions needed to obtain it.
//! Assumptions associate a [`DecisionId`] (a shared choice) with an [`AlternativeId`]
//! (the alternative selected for that choice). Reusing a decision across reads
//! keeps their possible values correlated. [`State::product`] combines outcomes
//! only when their assumptions agree.
//!
//! [`Provenance`] records the inputs and source locations used to obtain a value.
//! Callers can use this to explain the result, while decisions determine which
//! results can occur together.

mod value;
pub use value::*;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use crate::{
    Evaluation, Expr, SpannedExpr,
    call::{Call, Function, Function::*},
    op::BinOp,
};

/// Bindings and shared evaluation state. Recursive resolution must reuse this state.
pub trait Resolver {
    /// The caller's lexical scope.
    type Scope;
    /// The budget shared by expression evaluation and binding resolution.
    fn state(&mut self) -> &mut State;
    /// Resolve an evaluated context path within a scope.
    fn resolve(&mut self, path: &[Access], scope: &Self::Scope) -> Outcomes;

    /// Evaluate parts and assemble compatible combinations in order.
    fn sequence<T, U: Clone>(
        &mut self,
        parts: impl IntoIterator<Item = T>,
        mut evaluate: impl FnMut(&mut Self, T) -> Outcomes<U>,
    ) -> Outcomes<Vec<U>>
    where
        Self: Sized,
    {
        let mut combinations = vec![Outcome::new(vec![])];
        for part in parts {
            let values = evaluate(self, part);
            combinations = self
                .state()
                .product(combinations, values, |mut items, value| {
                    items.push(value);
                    items
                });
            if combinations.is_empty() {
                break;
            }
        }
        combinations
    }
}

/// Decisions and work limits shared by an evaluation and its resolved definitions.
#[derive(Default)]
pub struct State {
    depth: usize,
    work: usize,
    incomplete: bool,
    next_decision: usize,
    predicates: BTreeMap<Predicate, DecisionId>,
}

impl Resolver for State {
    type Scope = Option<Value>;

    fn state(&mut self) -> &mut State {
        self
    }

    fn resolve(&mut self, path: &[Access], root: &Self::Scope) -> Outcomes {
        let Some(root) = root else {
            return vec![];
        };
        let value = path
            .iter()
            .fold(root.clone(), |value, access| value.project(access));
        vec![Outcome::new(value)]
    }
}

#[derive(Clone, Default)]
struct Path {
    parts: Vec<Access>,
    provenance: Provenance,
}

/// Cache key for recognizing a repeated predicate.
///
/// Expression text is compared verbatim. Input identities distinguish the same
/// expression evaluated against different bindings.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Predicate {
    expression: String,
    inputs: BTreeSet<String>,
}

const MAX_ALTERNATIVES: usize = 256;
const MAX_DEPTH: usize = 64;
const MAX_WORK: usize = 16_384;

impl State {
    /// Allocate a fresh ID for a choice with mutually exclusive alternatives.
    ///
    /// Call this once per independent choice and retain the ID for subsequent
    /// reads. Every call allocates a different decision, even if the underlying
    /// expressions or values happen to be equal.
    ///
    /// The evaluator reuses predicate IDs by matching expression text and input
    /// identities. Resolvers must retain their own IDs for choices such as a
    /// matrix's row or a job's execution status.
    pub fn decision(&mut self) -> DecisionId {
        let id = DecisionId(self.next_decision);
        self.next_decision += 1;
        id
    }

    fn predicate(&mut self, expression: &str, value: &Value) -> Option<DecisionId> {
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

    /// Retain an unknown remainder when the outermost evaluation hits a limit.
    pub fn finish(&self, mut values: Outcomes) -> Outcomes {
        if self.depth == 0 && self.incomplete {
            values.truncate(MAX_ALTERNATIVES - 1);
            values.push(Outcome::new(Value::incomplete()));
        }
        values
    }

    /// Limit alternatives and charge their evaluation work.
    pub fn bound<T>(&mut self, values: impl IntoIterator<Item = T>) -> Vec<T> {
        let mut values: Vec<_> = values
            .into_iter()
            .take(MAX_ALTERNATIVES + 1)
            .take_while(|_| self.checkpoint())
            .collect();
        self.incomplete |= values.len() > MAX_ALTERNATIVES;
        values.truncate(MAX_ALTERNATIVES);
        values
    }

    /// Charge one unit of work, returning false when the budget is exhausted.
    pub fn checkpoint(&mut self) -> bool {
        self.work += 1;
        let available = self.work <= MAX_WORK;
        self.incomplete |= !available;
        available
    }

    fn exhausted(&mut self) -> bool {
        let exhausted = self.depth >= MAX_DEPTH || !self.checkpoint();
        self.incomplete |= exhausted;
        exhausted
    }

    /// Form pairs of outcomes whose assumptions can hold together.
    ///
    /// Outcomes with no shared decisions can be paired freely. For a shared
    /// decision, both outcomes must name the same alternative. The result combines
    /// their choice maps and uses `value` to combine their payloads.
    ///
    /// Two reads of the same choice produce pairs with matching alternatives:
    ///
    /// ```
    /// use github_actions_expressions::evaluation::{AlternativeId, Outcome, State};
    ///
    /// let mut state = State::default();
    /// let decision = state.decision();
    /// let enabled = Outcome::new("enabled")
    ///     .assume(decision, AlternativeId::new(1))
    ///     .unwrap();
    /// let disabled = Outcome::new("disabled")
    ///     .assume(decision, AlternativeId::new(0))
    ///     .unwrap();
    ///
    /// let pairs = state.product(
    ///     vec![enabled.clone(), disabled.clone()],
    ///     vec![enabled, disabled],
    ///     |left, right| (left, right),
    /// );
    /// let values: Vec<_> = pairs.into_iter().map(|outcome| outcome.value).collect();
    /// assert_eq!(values, [("enabled", "enabled"), ("disabled", "disabled")]);
    /// ```
    ///
    /// All decision IDs must have been allocated by this state.
    pub fn product<T: Clone, U: Clone, V>(
        &mut self,
        left: Outcomes<T>,
        right: Outcomes<U>,
        mut value: impl FnMut(T, U) -> V,
    ) -> Outcomes<V> {
        let mut results = vec![];
        for lhs in &left {
            for rhs in &right {
                if !self.checkpoint() {
                    return results;
                }
                if lhs
                    .choices
                    .iter()
                    .any(|(key, value)| rhs.choices.get(key).is_some_and(|other| other != value))
                {
                    continue;
                }
                let mut choices = lhs.choices.clone();
                choices.extend(rhs.choices.clone());
                results.push(Outcome {
                    value: value(lhs.value.clone(), rhs.value.clone()),
                    choices,
                });
                if results.len() > MAX_ALTERNATIVES {
                    return self.bound(results);
                }
            }
        }
        results
    }
}

pub(crate) struct Run<'a, R: Resolver> {
    pub(crate) resolver: &'a mut R,
    pub(crate) scope: &'a R::Scope,
}

impl<R: Resolver> Run<'_, R> {
    fn state(&mut self) -> &mut State {
        self.resolver.state()
    }

    pub(super) fn evaluate(&mut self, expr: &Expr<'_>) -> Outcomes {
        let values = if self.state().exhausted() {
            vec![]
        } else {
            self.state().depth += 1;
            let values = self.evaluate_inner(expr);
            self.state().depth -= 1;
            self.state().bound(values)
        };
        self.state().finish(values)
    }

    fn conditions(
        &mut self,
        predicate: &SpannedExpr<'_>,
        boolean_only: bool,
    ) -> Vec<(bool, Outcome)> {
        let mut conditions = vec![];
        for value in self.evaluate(predicate) {
            if boolean_only
                && matches!(
                    &value.value.kind,
                    Kind::Known(Evaluation::String(_) | Evaluation::Number(_) | Evaluation::Null)
                        | Kind::Array(_)
                        | Kind::Object(_)
                        | Kind::Unknown(Shape::Hash)
                )
            {
                continue;
            }
            let truths = value
                .value
                .truth()
                .map_or(vec![false, true], |truth| vec![truth]);
            let decision = self.state().predicate(predicate.origin.raw, &value.value);
            for truth in truths {
                let condition = match decision {
                    Some(id) => value
                        .clone()
                        .assume(id, AlternativeId::new(usize::from(truth))),
                    None => Some(value.clone()),
                };
                if let Some(condition) = condition {
                    conditions.push((truth, condition));
                }
            }
        }
        self.state().bound(conditions)
    }

    fn keys(&mut self, part: &SpannedExpr<'_>) -> Outcomes<Path> {
        let access = match &part.inner {
            Expr::Identifier(key) => Access::Key(key.as_str().into()),
            Expr::Star => Access::Wildcard,
            Expr::Index(index) => return self.keys(index),
            _ => {
                return self.evaluate(part).map(|value| Path {
                    parts: vec![
                        value
                            .concrete()
                            .map_or(Access::Unknown, |v| Access::Key(v.sema().to_string())),
                    ],
                    provenance: value.dependencies().controlled(),
                });
            }
        };
        vec![Outcome::new(Path {
            parts: vec![access],
            ..Path::default()
        })]
    }

    fn paths(&mut self, parts: &[SpannedExpr<'_>]) -> Outcomes<Path> {
        let mut paths = vec![Outcome::new(Path::default())];
        for part in parts {
            let keys = self.keys(part);
            paths = self.state().product(paths, keys, |mut path, key| {
                path.parts.extend(key.parts);
                path.provenance.extend(&key.provenance);
                path
            });
        }
        paths
    }

    fn evaluate_inner(&mut self, expr: &Expr<'_>) -> Outcomes {
        match expr {
            Expr::Literal(literal) => vec![Outcome::known(literal.consteval())],
            Expr::UnExpr { expr, .. } => self.evaluate(expr).map(|value| {
                let kind = value
                    .truth()
                    .map_or(Kind::Unknown(Shape::Boolean), |truth| {
                        Kind::Known(Evaluation::Boolean(!truth))
                    });
                Value::new(kind).with_provenance(&value.dependencies().controlled())
            }),
            Expr::BinExpr(bin) if matches!(bin.op, BinOp::And | BinOp::Or) => {
                let mut results = vec![];
                for (truth, condition) in self.conditions(&bin.lhs, false) {
                    if truth == matches!(bin.op, BinOp::Or) {
                        results.push(condition.map(|value| {
                            if !truth && value.truth().is_none() {
                                Value::new(Kind::Unknown(Shape::Falsy)).conditioned(&value)
                            } else {
                                value
                            }
                        }));
                    } else {
                        let rhs = self.evaluate(&bin.rhs);
                        results.extend(self.state().product(
                            vec![condition],
                            rhs,
                            |condition, value| value.conditioned(&condition),
                        ));
                    }
                }
                self.state().bound(results)
            }
            Expr::BinExpr(bin) => {
                let lhs = self.evaluate(&bin.lhs);
                let rhs = self.evaluate(&bin.rhs);
                self.state().product(lhs, rhs, |lhs, rhs| {
                    let identity = match (&lhs.kind, &rhs.kind) {
                        (Kind::Array(a), Kind::Array(b)) => Some(Arc::ptr_eq(a, b)),
                        (Kind::Object(a), Kind::Object(b)) => Some(Arc::ptr_eq(a, b)),
                        _ => None,
                    };
                    let kind = match (identity, lhs.concrete(), rhs.concrete()) {
                        (Some(equal), _, _) => Kind::Known(Evaluation::Boolean(match bin.op {
                            BinOp::Eq => equal,
                            BinOp::Neq => !equal,
                            _ => false,
                        })),
                        (_, Some(a), Some(b)) => Kind::Known(bin.op.evaluate(a, b)),
                        _ => Kind::Unknown(Shape::Boolean),
                    };
                    Value::new(kind).conditioned(&lhs).conditioned(&rhs)
                })
            }
            Expr::Context(reference) => {
                let first = reference.parts.first().expect("parsed context has a head");
                if matches!(first.inner, Expr::Identifier(_)) {
                    let mut results = vec![];
                    for path in self.paths(&reference.parts) {
                        let values = self.resolver.resolve(&path.value.parts, self.scope);
                        results.extend(self.state().product(vec![path], values, |path, value| {
                            value.with_provenance(&path.provenance)
                        }));
                    }
                    return self.state().bound(results);
                }
                let mut values = self.evaluate(first);
                for part in &reference.parts[1..] {
                    let keys = self.keys(part);
                    values = self.state().product(values, keys, |value, key| {
                        value
                            .project(&key.parts[0])
                            .with_provenance(&key.provenance)
                    });
                }
                values
            }
            Expr::Call(call) if call.func == Case => self.case(&call.args),
            Expr::Call(call) => {
                let args = self.resolver.sequence(&call.args, |resolver, arg| {
                    arg.evaluate(resolver, self.scope)
                });
                args.into_iter()
                    .filter_map(|args| args.evaluate_call(call.func))
                    .collect()
            }
            Expr::Identifier(_) | Expr::Index(_) | Expr::Star => Outcomes::default(),
        }
    }

    fn case(&mut self, args: &[SpannedExpr<'_>]) -> Outcomes {
        if self.state().exhausted() {
            return Outcomes::default();
        }
        if args.len() == 1 {
            return self.evaluate(&args[0]);
        }
        let mut results = vec![];
        for (truth, condition) in self.conditions(&args[0], true) {
            self.state().depth += 1;
            let values = if truth {
                self.evaluate(&args[1])
            } else {
                self.case(&args[2..])
            };
            self.state().depth -= 1;
            results.extend(
                self.state()
                    .product(vec![condition], values, |condition, value| {
                        value.conditioned(&condition)
                    }),
            );
        }
        self.state().bound(results)
    }
}

impl Outcome<Vec<Value>> {
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
        let kind = match function {
            Always => Kind::Known(Evaluation::Boolean(true)),
            Success | Failure | Cancelled | HashFiles => Kind::Unknown(shape),
            _ => match self
                .value
                .iter()
                .map(Value::concrete)
                .collect::<Option<Vec<_>>>()
            {
                Some(args) => Value::known(Call::evaluate(function, &args)?).kind,
                None => Kind::Unknown(shape),
            },
        };
        if matches!(shape, Shape::Boolean | Shape::Hash) {
            provenance = provenance.controlled();
        }
        Some(self.map(|_| Value::new(kind).with_provenance(&provenance)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_limits_retain_an_unknown_remainder() {
        let mut analysis = State {
            work: MAX_WORK,
            ..State::default()
        };
        let parsed = Expr::parse("config.x").unwrap();
        let values = parsed.evaluate(&mut analysis, &None);
        assert_eq!(values.len(), 1);
        assert!(values[0].value.provenance.incomplete);

        let mut analysis = State::default();
        analysis.bound(vec![(); MAX_ALTERNATIVES + 1]);
        let values = analysis.finish(Outcomes::default());
        assert_eq!(values.len(), 1);
        assert!(values[0].value.provenance.incomplete);
    }

    #[test]
    fn independent_choices_preserve_the_last_alternative() {
        let context = Some(Value::new(Kind::Reference(vec![])));
        for branch in [
            "case(flags.b{index}, '1', '0')",
            "(flags.b{index} && '1' || '0')",
        ] {
            let args = (0..8)
                .map(|index| branch.replace("{index}", &index.to_string()))
                .collect::<Vec<_>>()
                .join(", ");
            let source = format!(
                "format('{{0}}{{1}}{{2}}{{3}}{{4}}{{5}}{{6}}{{7}}', {args}) == '11111111' && payload.text"
            );
            let parsed = Expr::parse(&source).expect("valid expression");
            let mut analysis = State::default();
            let values = parsed.evaluate(&mut analysis, &context);
            assert_eq!(values.len(), MAX_ALTERNATIVES);
            assert!(
                values
                    .iter()
                    .all(|value| !value.value.provenance.incomplete)
            );
            assert!(
                values.iter().any(|value| value
                    .value
                    .dependencies()
                    .sources
                    .contains("payload.text"))
            );
        }
    }

    #[test]
    fn bindings_preserve_typed_values_and_provenance() {
        let mut root = Value::new(Kind::Reference(vec![]));
        root.provenance.evidence.insert(7);
        let scope = Some(root);
        let parsed =
            Expr::parse(r#"case(flags.enabled, fromJSON('{"n":20}'), fromJSON('{"n":1}')).n"#)
                .unwrap();
        let values = parsed.evaluate(&mut State::default(), &scope);
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].value.concrete(), Some(Evaluation::Number(1.0)));
        assert_eq!(values[1].value.concrete(), Some(Evaluation::Number(20.0)));
        assert_ne!(values[0].choices, values[1].choices);
        for value in values {
            let provenance = value.value.dependencies();
            assert!(provenance.sources.is_empty());
            assert!(provenance.controls.contains("flags.enabled"));
            assert!(provenance.evidence.contains(&7));
        }

        let data = serde_json::json!({"config": {"n": 20}, "list": []});
        let scope = Some(Value::known(data.try_into().unwrap()));
        for source in [
            "config == config",
            "list == list",
            "config.n == 20",
            "list != fromJSON('[]')",
        ] {
            let parsed = Expr::parse(source).unwrap();
            let values = parsed.evaluate(&mut State::default(), &scope);
            assert_eq!(values[0].value.concrete(), Some(Evaluation::Boolean(true)));
        }
    }

    #[test]
    fn decisions_are_stable_across_reads_and_distinct_across_scopes() {
        let mut state = State::default();
        let external = state.decision();
        let parsed = Expr::parse("case(config.enabled, 1, 2)").unwrap();
        let scope = Some(Value::new(Kind::Reference(vec![])));
        let first = parsed.evaluate(&mut state, &scope);
        let repeated = parsed.evaluate(&mut state, &scope);
        assert!(!first[0].choices.contains_key(&external));
        assert_eq!(state.product(first.clone(), repeated, |a, _| a).len(), 2);

        let scope = Some(Value::new(Kind::Reference(vec![Access::Key(
            "other".into(),
        )])));
        let other = parsed.evaluate(&mut state, &scope);
        assert_eq!(state.product(first, other, |a, _| a).len(), 4);
    }
}
