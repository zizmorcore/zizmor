//! Abstract interpretation and evaluation of Actions expressions.
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
//! An evaluation's decisions are managed through its [`State`]. The [`State`]
//! allocates new decisions and can also merge outcomes together when their
//! assumptions agree.
//!
//! Finally, each outcome of an evaluation comes with [`Provenance`], which
//! records the inputs and source locations used to obtain a value.
//! Callers can use this to explain the result in a human-friendly manner.

mod value;
pub use value::*;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use crate::{
    Evaluation, Expr, SpannedExpr,
    call::{Call, Function, Function::*},
    op::{BinExpr, BinOp},
};

/// Tracks decisions and work limits for one evaluation.
///
/// When a context lookup evaluates another expression, pass it the same state.
/// Both expressions can then refer to the same decisions and draw on the same
/// work budget.
#[derive(Default)]
pub struct State {
    depth: usize,
    work: usize,
    incomplete: bool,
    next_decision: usize,
    predicates: BTreeMap<Predicate, DecisionId>,
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

/// Looks up an evaluated context path in the caller's bindings. A binding may
/// itself contain an expression, so the callback receives the current state.
type Lookup<'a> = dyn FnMut(&mut State, &[Access]) -> Outcomes + 'a;

impl State {
    /// Allocate a new decision ID in this state.
    ///
    /// Keep the ID if later lookups depend on the same choice. For example,
    /// all reads of a job's matrix fields depend on which row that job uses.
    /// They share a decision ID, with a different alternative for each row.
    pub fn decision(&mut self) -> DecisionId {
        let id = DecisionId(self.next_decision);
        self.next_decision += 1;
        id
    }

    /// Find or allocate the decision for this predicate. Without a source or
    /// control path, we have no binding identity to associate with another read.
    fn predicate(&mut self, expression: &str, value: &TrackedValue) -> Option<DecisionId> {
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
    pub fn finish(&self, mut values: Outcomes) -> Outcomes {
        if self.depth == 0 && self.incomplete {
            values.truncate(MAX_ALTERNATIVES - 1);
            values.push(Outcome::new(TrackedValue::incomplete()));
        }
        values
    }

    /// Collect alternatives up to the result and work limits. If either limit
    /// cuts the collection short, mark this evaluation incomplete.
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

    /// Charge one unit of work. A `false` result means this unit exceeds the
    /// budget and the caller should stop exploring.
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

    /// Evaluate each part and collect one value per part, in input order, for
    /// each compatible combination. For example, a function call uses this to
    /// build its possible argument lists. Empty input yields one empty list.
    pub fn sequence<T, U: Clone>(
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
    ///
    /// In this example, both operands depend on the same decision.
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

    pub(super) fn evaluate(&mut self, expr: &Expr<'_>, lookup: &mut Lookup<'_>) -> Outcomes {
        let values = if self.exhausted() {
            vec![]
        } else {
            self.depth += 1;
            let values = self.evaluate_inner(expr, lookup);
            self.depth -= 1;
            self.bound(values)
        };
        self.finish(values)
    }

    /// Pair each possible truth value with the outcome that permits it. An
    /// unknown truth value can yield both branches. `case` requires a boolean
    /// predicate, while `&&` and `||` use Actions truthiness.
    fn conditions(
        &mut self,
        predicate: &SpannedExpr<'_>,
        boolean_only: bool,
        lookup: &mut Lookup<'_>,
    ) -> Vec<(bool, Outcome)> {
        let mut conditions = vec![];
        for value in self.evaluate(predicate, lookup) {
            if boolean_only
                && matches!(
                    &value.value.inner,
                    AbstractValue::Known(
                        Evaluation::String(_) | Evaluation::Number(_) | Evaluation::Null
                    ) | AbstractValue::Array(_)
                        | AbstractValue::Object(_)
                        | AbstractValue::Unknown(Shape::Hash)
                )
            {
                continue;
            }
            let truths = value
                .value
                .truth()
                .map_or(vec![false, true], |truth| vec![truth]);
            let decision = self.predicate(predicate.origin.raw, &value.value);
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
        self.bound(conditions)
    }

    /// Evaluate one path component. A computed index can produce several keys
    /// or an unknown key. Each carries the dependencies used to compute it.
    fn keys(
        &mut self,
        part: &SpannedExpr<'_>,
        lookup: &mut Lookup<'_>,
    ) -> Outcomes<(Access, Provenance)> {
        let access = match &part.inner {
            Expr::Identifier(key) => Access::Key(key.as_str().into()),
            Expr::Star => Access::Wildcard,
            Expr::Index(index) => return self.keys(index, lookup),
            _ => {
                return self.evaluate(part, lookup).map(|value| {
                    let key = value.concrete().map_or(Access::Unknown, |value| {
                        Access::Key(value.sema().to_string())
                    });
                    (key, value.dependencies().controlled())
                });
            }
        };
        vec![Outcome::new((access, Provenance::default()))]
    }

    fn paths(&mut self, parts: &[SpannedExpr<'_>], lookup: &mut Lookup<'_>) -> Outcomes<Path> {
        let mut paths = vec![Outcome::new(Path::default())];
        for part in parts {
            let keys = self.keys(part, lookup);
            paths = self.product(paths, keys, |mut path, (key, provenance)| {
                path.parts.push(key);
                path.provenance.extend(&provenance);
                path
            });
        }
        paths
    }

    fn evaluate_inner(&mut self, expr: &Expr<'_>, lookup: &mut Lookup<'_>) -> Outcomes {
        match expr {
            Expr::Literal(literal) => vec![Outcome::known(literal.consteval())],
            Expr::UnExpr { expr, .. } => self.evaluate(expr, lookup).map(|value| {
                let inner = value
                    .truth()
                    .map_or(AbstractValue::Unknown(Shape::Boolean), |truth| {
                        AbstractValue::Known(Evaluation::Boolean(!truth))
                    });
                TrackedValue::new(inner).with_provenance(&value.dependencies().controlled())
            }),
            Expr::BinExpr(bin) if matches!(bin.op, BinOp::And | BinOp::Or) => {
                self.short_circuit(bin, lookup)
            }
            Expr::BinExpr(bin) => {
                let lhs = self.evaluate(&bin.lhs, lookup);
                let rhs = self.evaluate(&bin.rhs, lookup);
                self.product(lhs, rhs, |lhs, rhs| lhs.compare(&bin.op, &rhs))
            }
            Expr::Context(reference) => self.context(&reference.parts, lookup),
            Expr::Call(call) if call.func == Case => self.case(&call.args, lookup),
            Expr::Call(call) => {
                let args = self.sequence(&call.args, |state, arg| state.evaluate(arg, lookup));
                args.into_iter()
                    .filter_map(|args| args.evaluate_call(call.func))
                    .collect()
            }
            Expr::Identifier(_) | Expr::Index(_) | Expr::Star => Outcomes::default(),
        }
    }

    /// For each possible truth value of the left operand, return the operand
    /// selected by `&&` or `||`. Evaluate the right operand only on branches
    /// that reach it.
    fn short_circuit(&mut self, bin: &BinExpr<'_>, lookup: &mut Lookup<'_>) -> Outcomes {
        let mut results = vec![];
        for (truth, condition) in self.conditions(&bin.lhs, false, lookup) {
            let use_left = matches!((&bin.op, truth), (BinOp::And, false) | (BinOp::Or, true));
            if use_left {
                results.push(condition.map(|value| {
                    if !truth && value.truth().is_none() {
                        // This branch returns the left operand of `&&`. Its
                        // exact value is unknown, but it must be falsy here.
                        TrackedValue::new(AbstractValue::Unknown(Shape::Falsy)).conditioned(&value)
                    } else {
                        value
                    }
                }));
            } else {
                let rhs = self.evaluate(&bin.rhs, lookup);
                results.extend(self.product(vec![condition], rhs, |condition, value| {
                    value.conditioned(&condition)
                }));
            }
        }
        self.bound(results)
    }

    /// Look up a named context such as `env.NAME` using its full path. For
    /// `fromJSON(inputs.data).name`, evaluate the call first, then apply
    /// the field access to each value it returns.
    fn context(&mut self, parts: &[SpannedExpr<'_>], lookup: &mut Lookup<'_>) -> Outcomes {
        let (first, rest) = parts.split_first().expect("parsed context has a head");
        if matches!(first.inner, Expr::Identifier(_)) {
            let mut results = vec![];
            for path in self.paths(parts, lookup) {
                let values = lookup(self, &path.value.parts);
                results.extend(self.product(vec![path], values, |path, value| {
                    value.with_provenance(&path.provenance)
                }));
            }
            return self.bound(results);
        }
        let mut values = self.evaluate(first, lookup);
        for part in rest {
            let keys = self.keys(part, lookup);
            values = self.product(values, keys, |value, (key, provenance)| {
                value.apply_access(&key).with_provenance(&provenance)
            });
        }
        values
    }

    /// Evaluate predicate/value pairs in order. A true branch selects its
    /// paired value. A false branch continues to the next pair or the fallback.
    fn case(&mut self, args: &[SpannedExpr<'_>], lookup: &mut Lookup<'_>) -> Outcomes {
        if self.exhausted() {
            return Outcomes::default();
        }
        if args.len() == 1 {
            return self.evaluate(&args[0], lookup);
        }
        let mut results = vec![];
        for (truth, condition) in self.conditions(&args[0], true, lookup) {
            self.depth += 1;
            let values = if truth {
                self.evaluate(&args[1], lookup)
            } else {
                self.case(&args[2..], lookup)
            };
            self.depth -= 1;
            results.extend(self.product(vec![condition], values, |condition, value| {
                value.conditioned(&condition)
            }));
        }
        self.bound(results)
    }
}

impl TrackedValue {
    fn compare(&self, op: &BinOp, rhs: &Self) -> Self {
        // Actions compares arrays and objects by identity.
        let same_instance = match (&self.inner, &rhs.inner) {
            (AbstractValue::Array(a), AbstractValue::Array(b)) => Some(Arc::ptr_eq(a, b)),
            (AbstractValue::Object(a), AbstractValue::Object(b)) => Some(Arc::ptr_eq(a, b)),
            _ => None,
        };
        let inner = if let Some(same) = same_instance {
            AbstractValue::Known(Evaluation::Boolean(match op {
                BinOp::Eq => same,
                BinOp::Neq => !same,
                _ => false,
            }))
        } else if let (Some(a), Some(b)) = (self.concrete(), rhs.concrete()) {
            AbstractValue::Known(op.evaluate(a, b))
        } else {
            AbstractValue::Unknown(Shape::Boolean)
        };
        Self::new(inner).conditioned(self).conditioned(rhs)
    }
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
        let inner = match function {
            Always => AbstractValue::Known(Evaluation::Boolean(true)),
            Success | Failure | Cancelled | HashFiles => AbstractValue::Unknown(shape),
            _ => match self
                .value
                .iter()
                .map(TrackedValue::concrete)
                .collect::<Option<Vec<_>>>()
            {
                Some(args) => TrackedValue::known(Call::evaluate(function, &args)?).inner,
                None => AbstractValue::Unknown(shape),
            },
        };
        if matches!(shape, Shape::Boolean | Shape::Hash) {
            provenance = provenance.controlled();
        }
        Some(self.map(|_| TrackedValue::new(inner).with_provenance(&provenance)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bindings(root: &TrackedValue) -> impl FnMut(&mut State, &[Access]) -> Outcomes {
        |_, path| {
            let value = path
                .iter()
                .fold(root.clone(), |value, key| value.apply_access(key));
            vec![Outcome::new(value)]
        }
    }

    #[test]
    fn resource_limits_retain_an_unknown_remainder() {
        let mut analysis = State {
            work: MAX_WORK,
            ..State::default()
        };
        let parsed = Expr::parse("config.x").unwrap();
        let values = parsed.evaluate(&mut analysis, |_, _| vec![]);
        assert_eq!(values.len(), 1);
        assert!(values[0].value.provenance.incomplete);

        let mut analysis = State::default();
        analysis.bound(vec![(); MAX_ALTERNATIVES + 1]);
        let values = analysis.finish(Outcomes::default());
        assert_eq!(values.len(), 1);
        assert!(values[0].value.provenance.incomplete);
    }

    #[test]
    fn incomplete_control_dependencies_remain_incomplete() {
        let mut root = TrackedValue::new(AbstractValue::Reference(vec![]));
        root.provenance.incomplete = true;

        for source in [
            "case(inputs.value, 'a', 'b')",
            "!inputs.value",
            "inputs.value == 'expected'",
            "contains(inputs.value, 'expected')",
            "hashFiles(inputs.value)",
            r#"fromJSON('{"key":"fixed"}')[inputs.value]"#,
        ] {
            let parsed = Expr::parse(source).expect("valid expression");
            let values = parsed.evaluate(&mut State::default(), bindings(&root));
            assert!(!values.is_empty(), "{source}");
            assert!(
                values
                    .iter()
                    .all(|outcome| outcome.value.dependencies().incomplete),
                "{source}"
            );
        }
    }

    #[test]
    fn independent_choices_preserve_the_last_alternative() {
        let context = TrackedValue::new(AbstractValue::Reference(vec![]));
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
            let values = parsed.evaluate(&mut analysis, bindings(&context));
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
        let mut root = TrackedValue::new(AbstractValue::Reference(vec![]));
        root.provenance.evidence.insert(7);
        let parsed =
            Expr::parse(r#"case(flags.enabled, fromJSON('{"n":20}'), fromJSON('{"n":1}')).n"#)
                .unwrap();
        let values = parsed.evaluate(&mut State::default(), bindings(&root));
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
        let root = TrackedValue::known(data.try_into().unwrap());
        for source in [
            "config == config",
            "list == list",
            "config.n == 20",
            "list != fromJSON('[]')",
        ] {
            let parsed = Expr::parse(source).unwrap();
            let values = parsed.evaluate(&mut State::default(), bindings(&root));
            assert_eq!(values[0].value.concrete(), Some(Evaluation::Boolean(true)));
        }
    }

    #[test]
    fn decisions_are_stable_across_reads_and_distinct_across_scopes() {
        let mut state = State::default();
        let external = state.decision();
        let parsed = Expr::parse("case(config.enabled, 1, 2)").unwrap();
        let scope = TrackedValue::new(AbstractValue::Reference(vec![]));
        let first = parsed.evaluate(&mut state, bindings(&scope));
        let repeated = parsed.evaluate(&mut state, bindings(&scope));
        assert!(!first[0].choices.contains_key(&external));
        assert_eq!(state.product(first.clone(), repeated, |a, _| a).len(), 2);

        let scope = TrackedValue::new(AbstractValue::Reference(vec![Access::Key("other".into())]));
        let other = parsed.evaluate(&mut state, bindings(&scope));
        assert_eq!(state.product(first, other, |a, _| a).len(), 4);
    }
}
