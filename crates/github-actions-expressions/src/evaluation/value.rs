//! Abstract interpretation values, their sources, and assumptions when selecting an alternative.
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
//! In this case, `inputs.enabled` drives a decision (D0), and has two alternatives:
//!
//! - inputs.enabled == true --> 'a' (A1)
//! - inputs.enabled == false --> 'b' (A0)
//!
//! Note that `inputs.enabled` can be an unknown boolean, in which case both alternatives
//! are possible.
//!
//! One or more decisions can lead into an [`Outcome`] which tracks (by default)
//! a [`Value`]. Each [`Value`] in turn has a [`Kind`] and [`Provenance`],
//! where [`Kind`] conveys the actual value (which may be abstract or concrete)
//! and [`Provenance`] records the inputs that contribute to the value.
//!
//! Expressing the case above, the outcomes would be:
//!
//! ```text
//! Outcome { value: 'a', choices: {D0: A1} }
//! Outcome { value: 'b', choices: {D0: A0} }
//! ```

use crate::Evaluation;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// Identifies a decision.
///
/// Decisions can be things like predicates, or the selection of a row from a matrix.
/// Decisions appear as the keys in [`Outcome::choices`], where each decision
/// is associated with the alternative (as [`AlternativeId`]) that's assumed
/// by the overall outcome.
///
/// In plain English, if [`Outcome::choices`] has `{D0: A1}`, then
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
/// expression semantics (e.g. predicate semantics) or resolver states (e.g.
/// matrix row alternatives or skipped/executed job alternatives).
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
    /// A named property or numeric index, e.g. `inputs.key`.
    Key(String),
    /// An explicit `*`, e.g. `inputs.*`.
    ///
    /// Note that this produces an array (which is truthy)
    /// when "projecting" an object or array, e.g. when
    /// `inputs` of `inputs.*` is an array or object.
    /// However, if `inputs` is a known scalar, then this
    /// produces an empty string.
    Wildcard,
    /// A computed index or access whose value is unknown.
    /// For example, `github.event[inputs.field]` if `inputs.field`
    /// could not be resolved during analysis.
    Unknown,
}

impl Access {
    /// Render a path component for source identities.
    pub fn text(&self) -> &str {
        match self {
            Self::Key(key) => key,
            Self::Wildcard => "*",
            Self::Unknown => "?",
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
    pub sources: BTreeSet<String>,
    /// Context paths used to select or index a value, or compute a boolean or hash.
    ///
    /// For example, `case(inputs.enabled, 'a', 'b')` would have `inputs.enabled` in controls,
    /// as it selects a literal.
    pub controls: BTreeSet<String>,
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
        self.incomplete = false;
        self
    }
}

/// An Actions value. Array elements are values, not alternative evaluations.
#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    /// A known scalar.
    Known(Evaluation),
    /// A runtime value with a known restriction.
    Unknown(Shape),
    /// An opaque runtime context path supporting further property access.
    Reference(Vec<Access>),
    /// Array elements with their individual provenance.
    Array(Arc<Vec<Value>>),
    /// Object fields with their individual provenance.
    Object(Arc<BTreeMap<String, Value>>),
}

/// A value with its provenance; branch assumptions belong to `Outcome`.
#[derive(Clone, Debug, PartialEq)]
pub struct Value {
    /// The value or its known properties.
    pub kind: Kind,
    /// Sources and definitions contributing to this value.
    pub provenance: Provenance,
}

impl Value {
    /// Construct a value without provenance.
    pub fn new(kind: Kind) -> Self {
        Self {
            kind,
            provenance: Provenance::default(),
        }
    }

    /// Preserve concrete container structure for subsequent property access.
    pub fn known(value: Evaluation) -> Self {
        Self::new(match value {
            Evaluation::Array(values) => {
                Kind::Array(Arc::new(values.into_iter().map(Self::known).collect()))
            }
            Evaluation::Object(fields) => Kind::Object(Arc::new(
                fields
                    .into_iter()
                    .map(|(k, v)| (k, Self::known(v)))
                    .collect(),
            )),
            value => Kind::Known(value),
        })
    }

    /// An unconstrained runtime value.
    pub fn unknown() -> Self {
        Self::new(Kind::Unknown(Shape::Any))
    }

    /// Mark an unresolved definition or an omitted evaluation.
    pub fn incomplete() -> Self {
        let mut value = Self::unknown();
        value.provenance.incomplete = true;
        value
    }

    /// Attach additional sources and definitions.
    pub fn with_provenance(mut self, provenance: &Provenance) -> Self {
        self.provenance.extend(provenance);
        self
    }

    /// Record the predicate selecting this value.
    pub fn conditioned(self, predicate: &Self) -> Self {
        self.with_provenance(&predicate.dependencies().controlled())
    }

    /// Collect inputs and locations, including those inside containers.
    pub fn dependencies(&self) -> Provenance {
        let mut provenance = self.provenance.clone();
        match &self.kind {
            Kind::Reference(path) => {
                provenance
                    .sources
                    .insert(path.iter().map(Access::text).collect::<Vec<_>>().join("."));
            }
            Kind::Array(values) => {
                for value in values.iter() {
                    provenance.extend(&value.dependencies());
                }
            }
            Kind::Object(fields) => {
                for value in fields.values() {
                    provenance.extend(&value.dependencies());
                }
            }
            _ => (),
        }
        provenance
    }

    /// Return truthiness when the value constrains it.
    pub fn truth(&self) -> Option<bool> {
        match &self.kind {
            Kind::Known(value) => Some(value.as_boolean()),
            Kind::Array(_) | Kind::Object(_) => Some(true),
            Kind::Unknown(Shape::Falsy) => Some(false),
            _ => None,
        }
    }

    /// Return array elements with the array's provenance attached.
    pub fn elements(&self) -> Option<Vec<Self>> {
        let Kind::Array(values) = &self.kind else {
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

    /// Convert a fully known value into a concrete Actions value.
    pub fn concrete(&self) -> Option<Evaluation> {
        match &self.kind {
            Kind::Known(value) => Some(value.clone()),
            Kind::Array(values) => Some(Evaluation::Array(
                values.iter().map(Self::concrete).collect::<Option<_>>()?,
            )),
            Kind::Object(fields) => Some(Evaluation::Object(
                fields
                    .iter()
                    .map(|(key, value)| Some((key.clone(), value.concrete()?)))
                    .collect::<Option<_>>()?,
            )),
            _ => None,
        }
    }

    /// Look up a property without changing branch assumptions.
    pub fn project(&self, access: &Access) -> Self {
        let empty = || Self::known(Evaluation::String(String::new()));
        let value = match (&self.kind, access) {
            (Kind::Reference(path), _) => {
                let mut path = path.clone();
                path.push(access.clone());
                Self::new(Kind::Reference(path))
            }
            (Kind::Known(_) | Kind::Unknown(Shape::Boolean | Shape::Falsy | Shape::Hash), _) => {
                empty()
            }
            (_, Access::Unknown) => Self::unknown().with_provenance(&self.dependencies()),
            (Kind::Object(fields), Access::Key(key)) => fields
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                .map_or_else(empty, |(_, value)| value.clone()),
            (Kind::Object(fields), Access::Wildcard) => {
                Self::new(Kind::Array(Arc::new(fields.values().cloned().collect())))
            }
            (Kind::Array(values), Access::Key(key)) => match key.parse::<usize>() {
                Ok(index) => values.get(index).cloned().unwrap_or_else(empty),
                Err(_) => Self::new(Kind::Array(Arc::new(
                    values.iter().map(|v| v.project(access)).collect(),
                ))),
            },
            (Kind::Array(values), Access::Wildcard) => {
                Self::new(Kind::Array(Arc::new(values.as_ref().clone())))
            }
            (Kind::Unknown(_), _) => Self::unknown(),
        };
        value.with_provenance(&self.provenance)
    }
}

/// One possible evaluation and the choices that must hold for it.
#[derive(Clone, Debug, PartialEq)]
pub struct Outcome<T = Value> {
    /// The value selected by these assumptions.
    pub value: T,
    /// Assumptions required for this outcome, keyed by the shared choice.
    ///
    /// A missing entry leaves that decision unconstrained. To combine two
    /// outcomes, [`State::product`](super::State::product) requires the same
    /// alternative for every decision present in both maps. Its result carries
    /// the union of their assumptions.
    pub choices: BTreeMap<DecisionId, AlternativeId>,
}

/// Alternatives, distinct from the elements of a single array.
pub type Outcomes<T = Value> = Vec<Outcome<T>>;

/// Payload operations on collections of outcomes.
pub trait OutcomesExt<T> {
    /// Transform payloads while preserving branch assumptions.
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
    /// Construct an alternative without branch assumptions.
    pub fn new(value: T) -> Self {
        Self {
            value,
            choices: BTreeMap::new(),
        }
    }

    /// Transform the payload while preserving branch assumptions.
    pub fn map<U>(self, apply: impl FnOnce(T) -> U) -> Outcome<U> {
        Outcome {
            value: apply(self.value),
            choices: self.choices,
        }
    }

    /// Select an alternative, rejecting a conflicting assumption about this decision.
    pub fn assume(mut self, decision: DecisionId, alternative: AlternativeId) -> Option<Self> {
        if self
            .choices
            .get(&decision)
            .is_some_and(|prior| *prior != alternative)
        {
            return None;
        }
        self.choices.insert(decision, alternative);
        Some(self)
    }
}

impl Outcome {
    /// Construct a concrete alternative.
    pub fn known(value: Evaluation) -> Self {
        Self::new(Value::known(value))
    }
}
