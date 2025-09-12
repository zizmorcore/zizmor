//! Identifiers.

/// Represents a single identifier in a GitHub Actions expression,
/// i.e. a single context component.
///
/// Identifiers are case-insensitive.
#[derive(Debug)]
pub struct Identifier<'src>(pub(crate) &'src str);

impl Identifier<'_> {
    /// Returns the identifier as a string slice, as it appears in the
    /// expression.
    ///
    /// Important: identifiers are case-insensitive, so this should not
    /// be used for comparisons.
    pub fn as_str(&self) -> &str {
        self.0
    }
}

impl PartialEq for Identifier<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(other.0)
    }
}

impl PartialEq<str> for Identifier<'_> {
    fn eq(&self, other: &str) -> bool {
        self.0.eq_ignore_ascii_case(other)
    }
}
