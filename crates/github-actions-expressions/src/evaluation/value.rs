//! Abstract interpretation values, their sources, and assumptions when selecting an outcome.
//!
//! Our abstract interpretation has "decisions" and "alternatives," each of which has an
//! identifier. A [`DecisionId`] identifies a shared choice during an evaluation, while
//! an [`AlternativeId`] identifies which alternative an outcome assumes.
//!
//! For example, consider the following expression:
//!
//! ```text
//! case(inputs.enabled, 'a', 'b')
//! ```
//!
//! In this case, `inputs.enabled` drives a decision (D0). Its two alternatives
//! lead to two possible outcomes:
//!
//! - inputs.enabled == true --> 'a' (A1)
//! - inputs.enabled == false --> 'b' (A0)
//!
//! Note that `inputs.enabled` can be an unknown boolean, in which case both outcomes
//! are possible.
//!
//! One or more decisions can lead into an [`Outcome`] which tracks (by default)
//! a [`TrackedValue`]. Each [`TrackedValue`] in turn has an [`AbstractValue`] and [`Provenance`],
//! where [`AbstractValue`] conveys the actual value (which may be abstract or concrete)
//! and [`Provenance`] records the inputs that contribute to the value.
//!
//! Expressing the case above, the outcomes would be:
//!
//! ```text
//! Outcome { value: 'a', choices: {D0: A1} }
//! Outcome { value: 'b', choices: {D0: A0} }
//! ```

use crate::{Evaluation, op::BinOp};
use indexmap::IndexMap;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// Identifies a decision.
///
/// A decision can represent a predicate or the choice between values supplied by a binding.
/// Decisions appear as the keys in an outcome's choice map, where each decision
/// is associated with the alternative (as [`AlternativeId`]) that's assumed
/// by the overall outcome.
///
/// In plain English, if an outcome's choice map has `{D0: A1}`, then
/// the outcome assumes that decision D0 selects alternative A1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DecisionId(pub(super) usize);

/// Identifies one alternative (of potentially many) from a decision.
///
/// [`AlternativeId`]s are unique per-[`DecisionId`], not globally unique.
///
/// Different kinds of decisions may use different conventions for the meanings
/// of their alternative IDs. For example, for predicate decisions, our convention
/// is to use `0` for a false alternative and `1` for a true alternative.
///
/// Alternatives are computed during evaluation and can be derived either from
/// expression semantics (e.g. predicate semantics) or workflow definitions (e.g.
/// whether the job that supplies an output ran or was skipped).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlternativeId(usize);

impl AlternativeId {
    /// Identify a new alternative (relative to some [`DecisionId`]).
    pub const fn new(index: usize) -> Self {
        Self(index)
    }
}

/// Partial restrictions on an otherwise unknown value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// Any runtime value.
    Any,
    /// A string whose contents are unknown.
    String,
    /// A number whose value is unknown.
    Number,
    /// A boolean whose value is unknown.
    Boolean,
    /// Null, false, zero, or the empty string.
    Falsy,
    /// An empty string or hexadecimal file hash.
    ///
    /// Note that this can be an empty string because it models the result of the `hashFiles` function,
    /// which can return an empty string when no files match the given pattern(s).
    Hash,
}

/// A property access within an Actions expression context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Access {
    /// A primitive key. Objects use its string form and arrays use its numeric form.
    Key {
        /// The property name when indexing an object.
        name: String,
        /// The nonnegative, floored index when indexing an array.
        index: Option<usize>,
    },
    /// A collection used as an index. It cannot select a property or element.
    Invalid,
    /// An explicit `*`, e.g. `inputs.*`. Subsequent accesses apply to each match.
    Wildcard,
    /// A computed index or access whose value is unknown.
    /// For example, `github.event[inputs.field]` if `inputs.field`
    /// could not be resolved during analysis.
    Unknown,
}

impl From<&str> for Access {
    fn from(name: &str) -> Self {
        Self::from_value(Evaluation::String(name.into()))
    }
}

impl Access {
    pub(super) fn from_value(value: Evaluation) -> Self {
        if matches!(value, Evaluation::Array(_) | Evaluation::Object(_)) {
            return Self::Invalid;
        }
        let index = value.as_number().floor();
        Self::Key {
            name: value.sema().to_string(),
            index: (0.0..=f64::from(i32::MAX))
                .contains(&index)
                .then_some(index as usize),
        }
    }

    /// Render a path component for source identities.
    pub fn text(&self) -> &str {
        match self {
            Self::Key { name, .. } => name,
            Self::Invalid => "?",
            Self::Wildcard => "*",
            Self::Unknown => "?",
        }
    }
}

/// A runtime context path and the scope in which it was read.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Source {
    /// The context path, for example `steps.build.outputs.image`.
    pub path: String,
    /// Supplied by the bindings when the same path names independent values
    /// in different environments.
    pub scope: Option<String>,
}

impl Source {
    /// A path shared across the evaluation.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            scope: None,
        }
    }
}

/// Provenance for the inputs and source locations that contribute to a value.
///
/// Provenance includes both "source" and "control" provenance, tracking dataflow
/// and control-flow (and dependencies) respectively. The two are not mutually exclusive
/// either, e.g. `case(inputs.name != '', inputs.name, 'anonymous')` would track the
/// provenance of `inputs.name` as both for the outcome that actually produces
/// `inputs.name`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Provenance {
    /// Context paths whose contents may flow into the result.
    ///
    /// For example, `format('{0}', inputs.name)` would have `inputs.name` as a source,
    /// since the contents of that context flow into the result.
    pub sources: BTreeSet<Source>,
    /// Context paths used to select or index a value, or compute a boolean or hash.
    ///
    /// For example, `case(inputs.enabled, 'a', 'b')` would have `inputs.enabled` in controls,
    /// as it selects a literal.
    pub controls: BTreeSet<Source>,
    /// Indices into source locations stored by the caller, used for breadcrumbs.
    pub evidence: BTreeSet<usize>,
    /// A definition could not be resolved, or we couldn't fully explore all
    /// possibilities given our evaluation limits.
    ///
    /// Unknown inputs do not themselves necessarily make a value's provenance incomplete.
    pub incomplete: bool,
}

impl Provenance {
    /// Merge `other`'s provenance into this provenance.
    pub fn extend(&mut self, other: &Self) {
        self.sources.extend(other.sources.iter().cloned());
        self.controls.extend(other.controls.iter().cloned());
        self.evidence.extend(&other.evidence);
        self.incomplete |= other.incomplete;
    }

    /// Re-assign this provenance's source contexts as control contexts.
    ///
    /// For example, for `case(inputs.enabled, 'a', 'b')`, this would transform:
    ///
    /// ```text
    /// sources = {"inputs.enabled"}, controls = {}
    /// ```
    ///
    /// into:
    ///
    /// ```text
    /// sources = {}, controls = {"inputs.enabled"}
    /// ```
    pub fn controlled(mut self) -> Self {
        self.controls.extend(std::mem::take(&mut self.sources));
        self
    }
}

/// An Actions value.
///
/// Note: the [`Self::Array`] and [`Self::Object`] variants are wrapped in an [`Arc`] to preserve
/// container identity, matching GitHub's own comparison semantics. More precisely, GitHub compares
/// arrays and objects by identity, and our evaluator matches this by comparing them with
/// [`Arc::ptr_eq`].
#[derive(Clone, Debug, PartialEq)]
pub enum AbstractValue {
    /// A known scalar.
    ///
    /// For example, we might know that a given expression evaluates to a literal string `'foo'`.
    Known(Evaluation),

    /// An unknown evaluation, but with a possible shape restriction.
    ///
    /// For example, we might not know an expression's ultimate evaluation, but we might
    /// know that it produces a boolean.
    Unknown(Shape),

    /// A runtime value represented by its context path.
    ///
    /// Subsequent property access extends this path while
    /// its evaluation remains unknown.
    Reference(Vec<Access>),

    /// An evaluation of array elements, each with their individual provenance.
    ///
    /// This is distinct from [`Evaluation::Array`] because each element here
    /// may not be fully concrete or known. For example, an array might
    /// contain both a scalar literal `'foo'` and a reference `inputs.foo`.
    ///
    /// This represents a single array value, not multiple possible outcomes.
    Array(Arc<Vec<TrackedValue>>),

    /// A wildcard result. Further accesses select from each member and skip misses.
    FilteredArray(Arc<Vec<TrackedValue>>),

    /// An evaluation of object fields, each with their individual provenance.
    ///
    /// Like [`Self::Array`] each element may not be fully concrete or known.
    Object(Arc<IndexMap<String, TrackedValue>>),
}

/// A "tracked" value, i.e. an [`AbstractValue`] with its associated [`Provenance`].
#[derive(Clone, Debug, PartialEq)]
pub struct TrackedValue {
    /// The value or its known properties.
    pub inner: AbstractValue,
    /// Sources and definitions contributing to this value.
    pub provenance: Provenance,
}

impl TrackedValue {
    /// Construct a tracked value without provenance.
    pub fn new(inner: AbstractValue) -> Self {
        Self {
            inner,
            provenance: Provenance::default(),
        }
    }

    /// Convert a concrete [`Evaluation`] into a [`TrackedValue`], without provenance.
    ///
    /// This recursively turns concrete arrays and objects into [`AbstractValue::Array`]
    /// and [`AbstractValue::Object`] respectively. All other concrete evaluations
    /// become [`AbstractValue::Known`].
    pub fn known(value: Evaluation) -> Self {
        Self::new(match value {
            Evaluation::Array(values) => {
                AbstractValue::Array(Arc::new(values.into_iter().map(Self::known).collect()))
            }
            Evaluation::Object(fields) => AbstractValue::Object(Arc::new(
                fields
                    .into_iter()
                    .map(|(k, v)| (k, Self::known(v)))
                    .collect(),
            )),
            value => AbstractValue::Known(value),
        })
    }

    /// Creates an unknown abstract value.
    pub fn unknown() -> Self {
        Self::new(AbstractValue::Unknown(Shape::Any))
    }

    /// Creates a new unknown abstract value with incomplete provenance.
    pub fn incomplete() -> Self {
        let mut value = Self::unknown();
        value.provenance.incomplete = true;
        value
    }

    /// Attach the given provenance to this tracked value.
    pub fn with_provenance(mut self, provenance: &Provenance) -> Self {
        self.provenance.extend(provenance);
        self
    }

    /// Add the given predicate's dependencies to this tracked value,
    /// as control provenance.
    pub fn conditioned(self, predicate: &Self) -> Self {
        self.with_provenance(&predicate.dependencies().controlled())
    }

    /// Returns this tracked value's provenance, recursively merged with the provenance
    /// of array elements and object fields. For tracked values that are references,
    /// the context path is also included in the provenance.
    pub fn dependencies(&self) -> Provenance {
        let mut provenance = self.provenance.clone();
        match &self.inner {
            AbstractValue::Reference(path) => {
                provenance.sources.insert(Source::new(
                    path.iter().map(Access::text).collect::<Vec<_>>().join("."),
                ));
            }
            AbstractValue::Array(values) | AbstractValue::FilteredArray(values) => {
                for value in values.iter() {
                    provenance.extend(&value.dependencies());
                }
            }
            AbstractValue::Object(fields) => {
                for value in fields.values() {
                    provenance.extend(&value.dependencies());
                }
            }
            _ => (),
        }
        provenance
    }

    /// Coerce a scalar for a string-valued YAML field such as an environment
    /// variable. Collections are invalid in those fields.
    pub fn into_string(self) -> Option<Self> {
        let inner = match &self.inner {
            AbstractValue::Known(Evaluation::String(_))
            | AbstractValue::Unknown(Shape::Hash | Shape::String) => return Some(self),
            AbstractValue::Known(value) => {
                AbstractValue::Known(Evaluation::String(value.sema().to_string()))
            }
            AbstractValue::Unknown(_) | AbstractValue::Reference(_) => {
                AbstractValue::Unknown(Shape::String)
            }
            AbstractValue::Array(_)
            | AbstractValue::FilteredArray(_)
            | AbstractValue::Object(_) => return None,
        };
        Some(Self::new(inner).with_provenance(&self.dependencies()))
    }

    /// `format` renders a collection's type name regardless of its members.
    pub(super) fn formatted(self) -> Self {
        let name = match self.inner {
            AbstractValue::Array(_) | AbstractValue::FilteredArray(_) => "Array",
            AbstractValue::Object(_) => "Object",
            _ => return self.into_string().expect("scalar"),
        };
        Self::known(Evaluation::String(name.into())).with_provenance(&self.provenance.controlled())
    }

    /// Return this tracked value's truthiness, if it can be determined.
    pub fn truth(&self) -> Option<bool> {
        match &self.inner {
            AbstractValue::Known(value) => Some(value.as_boolean()),
            AbstractValue::Array(_)
            | AbstractValue::FilteredArray(_)
            | AbstractValue::Object(_) => Some(true),
            AbstractValue::Unknown(Shape::Falsy) => Some(false),
            _ => None,
        }
    }

    pub(super) fn negate(self) -> Self {
        let inner = match self.truth() {
            Some(truth) => AbstractValue::Known(Evaluation::Boolean(!truth)),
            None => AbstractValue::Unknown(Shape::Boolean),
        };
        Self::new(inner).conditioned(&self)
    }

    /// Whether this value could be a boolean, as required by `case`.
    /// A value of unknown type that is known to be falsy could be `false`.
    pub(super) fn can_be_boolean(&self) -> bool {
        matches!(
            self.inner,
            AbstractValue::Known(Evaluation::Boolean(_))
                | AbstractValue::Unknown(Shape::Any | Shape::Boolean | Shape::Falsy)
                | AbstractValue::Reference(_)
        )
    }

    pub(super) fn compare(&self, op: &BinOp, rhs: &Self) -> Self {
        // Actions compares arrays and objects by identity.
        let same_instance = match (&self.inner, &rhs.inner) {
            (AbstractValue::Array(a), AbstractValue::Array(b))
            | (AbstractValue::FilteredArray(a), AbstractValue::FilteredArray(b)) => {
                Some(Arc::ptr_eq(a, b))
            }
            (AbstractValue::Object(a), AbstractValue::Object(b)) => Some(Arc::ptr_eq(a, b)),
            _ => None,
        };
        let inner = if let Some(same) = same_instance {
            AbstractValue::Known(Evaluation::Boolean(match op {
                BinOp::Eq | BinOp::Ge | BinOp::Le => same,
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

    /// Return this tracked value's elements, with the value's
    /// own provenance attached, if the tracked value is an array.
    pub fn elements(&self) -> Option<Vec<Self>> {
        let (AbstractValue::Array(values) | AbstractValue::FilteredArray(values)) = &self.inner
        else {
            return None;
        };
        Some(
            values
                .iter()
                .cloned()
                .map(|value| value.with_provenance(&self.provenance))
                .collect(),
        )
    }

    /// Return a concrete Actions evaluation for this tracked value, if the underlying
    /// value is fully concrete.
    pub fn concrete(&self) -> Option<Evaluation> {
        match &self.inner {
            AbstractValue::Known(value) => Some(value.clone()),
            AbstractValue::Array(values) | AbstractValue::FilteredArray(values) => Some(
                Evaluation::Array(values.iter().map(Self::concrete).collect::<Option<_>>()?),
            ),
            AbstractValue::Object(fields) => Some(Evaluation::Object(
                fields
                    .iter()
                    .map(|(key, value)| Some((key.clone(), value.concrete()?)))
                    .collect::<Option<_>>()?,
            )),
            _ => None,
        }
    }

    /// Follow a field or index path from this value. An empty path returns the value itself.
    pub fn apply_path(self, path: &[Access]) -> Self {
        path.iter().fold(self, |value, key| value.apply_access(key))
    }

    /// Applies a single access to this tracked value, returning
    /// a new tracked value with updated provenance.
    pub fn apply_access(&self, access: &Access) -> Self {
        let mut matches = Vec::new();
        match (&self.inner, access) {
            (AbstractValue::FilteredArray(items), _) => {
                for item in items.iter() {
                    item.collect_matches(access, &mut matches);
                }
            }
            (_, Access::Wildcard)
                if !matches!(
                    self.inner,
                    AbstractValue::Reference(_) | AbstractValue::Unknown(Shape::Any)
                ) =>
            {
                self.collect_matches(access, &mut matches);
            }
            _ => {
                return match self.member(access) {
                    Some(value) => value.with_provenance(&self.provenance),
                    None => Self::known(Evaluation::Null)
                        .with_provenance(&self.provenance.clone().controlled()),
                };
            }
        }
        Self::new(AbstractValue::FilteredArray(Arc::new(matches))).with_provenance(&self.provenance)
    }

    /// A missing member is skipped by a filter, while a member containing null is retained.
    fn collect_matches(&self, access: &Access, matches: &mut Vec<Self>) {
        let push = |value: &Self| matches.push(value.clone().with_provenance(&self.provenance));
        match (&self.inner, access) {
            (
                AbstractValue::Array(items) | AbstractValue::FilteredArray(items),
                Access::Wildcard,
            ) => items.iter().for_each(push),
            (AbstractValue::Object(fields), Access::Wildcard) => fields.values().for_each(push),
            _ => matches.extend(
                self.member(access)
                    .map(|value| value.with_provenance(&self.provenance)),
            ),
        }
    }

    fn member(&self, access: &Access) -> Option<Self> {
        match (&self.inner, access) {
            (_, Access::Invalid) => None,
            (AbstractValue::Object(fields), Access::Key { name, .. }) => fields
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.clone()),
            (
                AbstractValue::Array(items) | AbstractValue::FilteredArray(items),
                Access::Key { index: Some(i), .. },
            ) => items.get(*i).cloned(),
            (AbstractValue::Reference(path), _) => {
                let mut path = path.clone();
                path.push(access.clone());
                Some(Self::new(AbstractValue::Reference(path)))
            }
            (AbstractValue::Unknown(Shape::Any), _) => Some(Self::unknown()),
            (
                AbstractValue::Array(_)
                | AbstractValue::Object(_)
                | AbstractValue::FilteredArray(_),
                Access::Unknown,
            ) => Some(Self::unknown().with_provenance(&self.dependencies())),
            _ => None,
        }
    }
}

/// A single possible outcome from an evaluation, along with the choices
/// that must hold for it.
#[derive(Clone, Debug, PartialEq)]
pub struct Outcome<T = TrackedValue> {
    /// The value selected by the outcome's assumptions.
    pub value: T,

    /// Alternatives assumed by this outcome, keyed by their decisions.
    ///
    /// An entry `{D0: A1}` means that this outcome assumes that decision D0
    /// selects alternative A1. A missing entry means an unconstrained decision.
    ///
    /// Only outcomes that agree on their shared decisions can be combined.
    pub(super) choices: BTreeMap<DecisionId, AlternativeId>,
}

/// Zero or more possible outcomes.
pub type Outcomes<T = TrackedValue> = Vec<Outcome<T>>;

/// Operations on collections of outcomes.
pub trait OutcomesExt<T> {
    /// Transform payloads while preserving choice constraints.
    fn map<U>(self, apply: impl FnMut(T) -> U) -> Outcomes<U>;
}

impl<T> OutcomesExt<T> for Outcomes<T> {
    fn map<U>(self, mut apply: impl FnMut(T) -> U) -> Outcomes<U> {
        self.into_iter()
            .map(|outcome| outcome.map(&mut apply))
            .collect()
    }
}

impl<T> Outcome<T> {
    /// Construct an outcome without any additional choice constraints.
    pub fn new(value: T) -> Self {
        Self {
            value,
            choices: BTreeMap::new(),
        }
    }

    /// Transform the payload while preserving choice constraints.
    pub fn map<U>(self, apply: impl FnOnce(T) -> U) -> Outcome<U> {
        Outcome {
            value: apply(self.value),
            choices: self.choices,
        }
    }

    /// Combine two outcomes if their assumptions agree on every shared decision.
    pub(super) fn combine<U, V>(
        &self,
        other: &Outcome<U>,
        value: impl FnOnce(T, U) -> V,
    ) -> Option<Outcome<V>>
    where
        T: Clone,
        U: Clone,
    {
        for (decision, alternative) in &self.choices {
            if other
                .choices
                .get(decision)
                .is_some_and(|a| a != alternative)
            {
                return None;
            }
        }

        let mut choices = self.choices.clone();
        choices.extend(&other.choices);
        Some(Outcome {
            value: value(self.value.clone(), other.value.clone()),
            choices,
        })
    }

    /// Add a choice constraint to this outcome, returning the updated outcome.
    ///
    /// Return `None` if this outcome already assumes a different alternative for
    /// the same decision.
    pub fn assume(mut self, decision: DecisionId, alternative: AlternativeId) -> Option<Self> {
        if self
            .choices
            .get(&decision)
            .is_some_and(|prior| *prior != alternative)
        {
            // This outcome already assumes a different alternative for the given decision,
            // meaning the assumptions contradict.
            return None;
        }

        self.choices.insert(decision, alternative);
        Some(self)
    }
}

impl Outcome {
    /// Construct a concrete outcome.
    pub fn known(value: Evaluation) -> Self {
        Self::new(TrackedValue::known(value))
    }
}
