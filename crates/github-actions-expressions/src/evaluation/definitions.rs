//! Definitions describe where context values come from. Evaluating a scope
//! follows only the definitions reached by the expression.
use super::*;
use std::{collections::BTreeMap, sync::Arc};

/// Named definitions visible to an expression or below a context path.
/// Clones share their bindings until one scope adds or replaces a name.
#[derive(Clone)]
pub struct Scope {
    names: Arc<BTreeMap<String, Definition>>,
    fallback: Definition,
    missing: Option<Definition>,
}

impl Default for Scope {
    fn default() -> Self {
        Self::new(Definition::new(Node::Unavailable))
    }
}

impl Scope {
    /// Use `fallback` for paths without an explicit binding.
    pub fn new(fallback: Definition) -> Self {
        Self {
            names: Default::default(),
            fallback,
            missing: None,
        }
    }

    /// Bind a missing named field separately from a bare or computed access.
    pub fn with_missing(mut self, missing: Definition) -> Self {
        self.missing = Some(missing);
        self
    }

    /// Define a case-insensitive name in this scope.
    pub fn bind(&mut self, name: &str, value: Definition) {
        Arc::make_mut(&mut self.names).insert(name.to_ascii_lowercase(), value);
    }

    /// Evaluate an expression with a fresh set of decisions and work limits.
    pub fn evaluate(&self, expr: &Expr<'_>) -> Outcomes {
        State::default().evaluate(expr, self)
    }

    /// Evaluate a YAML string, preserving the type of a single fenced expression.
    pub fn evaluate_template(&self, text: &str) -> Outcomes {
        State::default().template(text, self)
    }

    pub(super) fn read(&self, state: &mut State, path: &[Access], rest: &[Access]) -> Outcomes {
        if let [Access::Key(name), tail @ ..] = rest
            && let Some(def) = self
                .names
                .get(&name.to_ascii_lowercase())
                .or(self.missing.as_ref())
        {
            return def.read(state, path, tail);
        }
        self.fallback.read(state, path, rest)
    }
}

/// A value definition. Cloning a choice or matrix keeps its identity, so two
/// reads in one evaluation select the same alternative or row.
#[derive(Clone)]
pub struct Definition(Arc<Node>);

enum Node {
    Value(TrackedValue),
    Unavailable,
    Runtime(String),
    Namespace(Scope),
    Template(String, Scope),
    Array(Vec<Definition>),
    Object(BTreeMap<String, Definition>),
    Choice(Vec<Definition>),
    Matrix(Definition),
    Located(Definition, usize),
}

impl Definition {
    fn new(node: Node) -> Self {
        Self(Arc::new(node))
    }

    /// Bind a value with its existing provenance.
    pub fn value(value: TrackedValue) -> Self {
        Self::new(Node::Value(value))
    }

    /// Bind a concrete Actions value.
    pub fn known(value: Evaluation) -> Self {
        Self::value(TrackedValue::known(value))
    }

    /// An unknown value whose source is the prefix followed by the full access path.
    pub fn runtime(prefix: String) -> Self {
        Self::new(Node::Runtime(prefix))
    }

    /// Look up subsequent path components in this scope.
    pub fn namespace(scope: Scope) -> Self {
        Self::new(Node::Namespace(scope))
    }

    /// Capture the scope in which the template was written.
    pub fn template(text: String, scope: Scope) -> Self {
        Self::new(Node::Template(text, scope))
    }

    /// Evaluate the elements to form an array.
    pub fn array(items: Vec<Self>) -> Self {
        Self::new(Node::Array(items))
    }

    /// Evaluate the fields to form an object.
    pub fn object(fields: BTreeMap<String, Self>) -> Self {
        Self::new(Node::Object(fields))
    }

    /// Select one alternative consistently throughout an evaluation.
    pub fn choice(values: Vec<Self>) -> Self {
        Self::new(Node::Choice(values))
    }

    /// Expand the definition into matrix rows when a consumer first reads it.
    pub fn matrix(definition: Self) -> Self {
        Self::new(Node::Matrix(definition))
    }

    /// Attach the caller’s source location to each result.
    pub fn located(self, evidence: usize) -> Self {
        Self::new(Node::Located(self, evidence))
    }

    pub(super) fn read(&self, state: &mut State, path: &[Access], rest: &[Access]) -> Outcomes {
        if state.exhausted() {
            return vec![];
        }
        state.nested(|state| self.read_inner(state, path, rest))
    }

    fn read_inner(&self, state: &mut State, path: &[Access], rest: &[Access]) -> Outcomes {
        let values =
            match self.0.as_ref() {
                Node::Value(value) => vec![Outcome::new(value.clone())],
                Node::Unavailable => return vec![],
                Node::Runtime(prefix) => {
                    let mut value = TrackedValue::unknown();
                    let name = path.iter().map(Access::text).collect::<Vec<_>>().join(".");
                    value.provenance.sources.insert(format!("{prefix}{name}"));
                    return vec![Outcome::new(value)];
                }
                Node::Namespace(scope) => return scope.read(state, path, rest),
                Node::Located(inner, evidence) => {
                    return inner.read(state, path, rest).map(|mut value| {
                        value.provenance.evidence.insert(*evidence);
                        value
                    });
                }
                Node::Choice(options) => {
                    let decision = state.definition_decision(self);
                    let mut results = vec![];
                    for (index, option) in options.iter().enumerate() {
                        if !state.checkpoint() {
                            break;
                        }
                        results.extend(option.read(state, path, rest).into_iter().filter_map(
                            |outcome| outcome.assume(decision, AlternativeId::new(index)),
                        ));
                    }
                    return state.bound(results);
                }
                Node::Matrix(inner) => {
                    let decision = state.definition_decision(self);
                    state.matrix_rows(decision, inner, path)
                }
                Node::Template(text, scope) => state.template(text, scope),
                Node::Array(items) => state
                    .sequence(items, |state, item| item.read(state, path, &[]))
                    .map(|items| TrackedValue::new(AbstractValue::Array(Arc::new(items)))),
                Node::Object(fields) => state
                    .sequence(fields.values(), |state, item| item.read(state, path, &[]))
                    .map(|items| {
                        TrackedValue::new(AbstractValue::Object(Arc::new(
                            fields.keys().cloned().zip(items).collect(),
                        )))
                    }),
            };
        values.map(|value| {
            rest.iter()
                .fold(value, |value, access| value.apply_access(access))
        })
    }
}

impl State {
    fn definition_decision(&mut self, definition: &Definition) -> DecisionId {
        // All nodes belong to the scope borrowed for this evaluation.
        let key = Arc::as_ptr(&definition.0) as usize;
        if let Some(decision) = self.definitions.get(&key) {
            return *decision;
        }
        let decision = self.decision();
        self.definitions.insert(key, decision);
        decision
    }
}
