//! Functionality for describing and matching `uses:` "coordinates."
//!
//! A "coordinate" is a set of conditions which a `uses:` step can match.
//! These conditions can be non-trivial, such as "match `actions/checkout`,
//! but only if `persist-credentials: false`" is present.
//!
//! Coordinates are useful building blocks for audits like `cache-poisoning`,
//! which need to check a diversity of different step "shapes" to accurately
//! flag potential cache poisoning patterns.

// TODO: We would ideally be even more expressive here and allow basic
// sentential logic and in-field matching. For example, we would ideally be
// able to express things like
// "match foo/bar if foo: A and not bar: B and baz: /abcd/"

use super::Uses;

pub(crate) enum UsesCoordinate<'w> {
    Configurable {
        /// The `uses:` clause of the coordinate
        uses: Uses<'w>,
        /// The input that controls the coordinate
        control: Control,
        /// Whether or not the behavior is the default
        enabled_by_default: bool,
    },
    NotConfigurable(Uses<'w>),
}

impl UsesCoordinate<'_> {
    pub(crate) fn uses(&self) -> Uses {
        match self {
            UsesCoordinate::Configurable { uses, .. } => *uses,
            UsesCoordinate::NotConfigurable(inner) => *inner,
        }
    }
}

pub(crate) enum Toggle {
    /// Opt-in means that cache is **enabled** when the control value matches.
    OptIn,
    /// Opt-out means that cache is **disabled** when the control value matches.
    OptOut,
}

/// The value type that controls the activation/deactivation of caching
#[derive(PartialEq)]
pub(crate) enum ControlFieldType {
    /// The caching behavior is controlled by a boolean field, e.g. `cache: true`.
    Boolean,
    /// The caching behavior is controlled by a string field, e.g. `cache: "pip"`.
    String,
}

/// The input that controls the behavior of a configurable action.
pub(crate) struct Control {
    /// What kind of toggle the input is.
    pub(crate) toggle: Toggle,
    /// The field that controls the action's behavior.
    pub(crate) field_name: &'static str,
    /// The type of the field that controls the action's behavior.
    pub(crate) field_type: ControlFieldType,
}

impl Control {
    pub(crate) fn new(
        toggle: Toggle,
        field_name: &'static str,
        field_type: ControlFieldType,
    ) -> Self {
        Self {
            toggle,
            field_name,
            field_type,
        }
    }
}

#[derive(PartialEq)]
pub(crate) enum Usage {
    ConditionalOptIn,
    DirectOptIn,
    DefaultActionBehaviour,
    Always,
}
