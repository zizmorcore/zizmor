//! Common interfaces for modeling inputs across both workflows and actions.

/// Represents the "capability" of an (input) value, i.e. how it expands.
///
/// This is shared by both inputs and contexts more generally, the latter
/// in the setting of the `template-injection` audit.
#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum Capability {
    /// The value's expansion is fully arbitrary, e.g. arbitrary code.
    Arbitrary,
    /// The value's expansion is structured, i.e. partially controlled
    /// by the user, but fully controlled.
    ///
    /// An example of a structured value would be one with a fixed prefix:
    /// the value might be `prefix-${{ foo }}`, where the user can control
    /// the `${{ foo }}` part, but not the `prefix-` part.
    Structured,
    /// The value's expansion is fully fixed, i.e. not controlled by the user.
    ///
    /// The user might control the *choice* of the value, but not its
    /// contents. For example, a choice-style input has multiple chooseable
    /// values, but the user cannot control the contents of those values.
    Fixed,
}

impl Capability {
    /// Unify two capabilities in favor of the more permissive one.
    pub(crate) fn unify(self, other: Self) -> Self {
        match (self, other) {
            (Capability::Arbitrary, _) | (_, Capability::Arbitrary) => Capability::Arbitrary,
            (Capability::Structured, _) | (_, Capability::Structured) => Capability::Structured,
            _ => self,
        }
    }
}

/// A trait for types that have inputs, such as workflows and actions.
pub(crate) trait HasInputs {
    fn get_input(&self, name: &str) -> Option<Capability>;
}
