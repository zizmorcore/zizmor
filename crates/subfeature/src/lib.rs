//! Subfeature handling and manipulation APIs.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::sync::LazyLock;

use serde::Serialize;

/// Represent's a subfeature's fragment.
///
/// This is used to locate a subfeature's exact location within a surrounding
/// feature.
#[derive(Serialize, Clone, Debug)]
pub enum Fragment<'a> {
    /// A raw subfeature fragment.
    ///
    /// This is useful primarily for matching an exact fragment within
    /// a larger feature, e.g. a string literal.
    ///
    /// It *shouldn't* be used to match things like expressions, since they
    /// might contain whitespace that won't exactly match the surrounding
    /// feature. For that, [`Fragment::Regex`] is appropriate.
    Raw(&'a str),
    /// A regular expression for matching a subfeature.
    ///
    /// This is useful primarily for matching any kind of subfeature that
    /// might contain multiple lines, e.g. a multi-line GitHub Actions
    /// expression, since the subfeature's indentation won't necessarily match
    /// the surrounding feature's YAML-level indentation.
    Regex(#[serde(serialize_with = "Fragment::serialize_regex")] regex::bytes::Regex),
}

impl<'a> Fragment<'a> {
    fn serialize_regex<S>(regex: &regex::bytes::Regex, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let pattern = regex.as_str();
        serializer.serialize_str(pattern)
    }

    /// Create a new [`Fragment`] from the given string.
    ///
    /// The created fragment's behavior depends on whether the input
    /// contains newlines or not: if there are no newlines then the fragment
    /// is a "raw" fragment that gets matched verbatim. If there are newlines,
    /// then the fragment is a "regex" fragment that allows a degree of
    /// whitespace malleability to allow for matching against a YAML feature
    /// with its own syntactically relevant whitespace.
    pub fn new(fragment: &'a str) -> Self {
        if !fragment.contains('\n') {
            // Silly optimization: we don't need to build up a pattern for this
            // expression if it doesn't have any newlines.
            Fragment::Raw(fragment)
        } else {
            // We turn a spanned expression into a regular expression by
            // replacing all whitespace with `\\s+`.
            //
            // This is a ridiculous overapproximation of the actual difference
            // in expected whitespace, but it works well enough and saves
            // us having to walk the expression's nodes and build up a more
            // precise pattern manually (which ends up being nontrivial,
            // since our current AST doesn't preserve parentheses).
            //
            // This approach is not strictly correct, since it doesn't distinguish
            // between syntactical whitespace and whitespace within e.g.
            // string literals.
            let escaped = regex::escape(fragment);

            static WHITESPACE: LazyLock<regex::Regex> =
                LazyLock::new(|| regex::Regex::new(r"\s+").unwrap());
            let regex = WHITESPACE.replace_all(&escaped, "\\s+");

            Fragment::Regex(regex::bytes::Regex::new(&regex).unwrap())
        }
    }
}

impl<'doc> From<&'doc str> for Fragment<'doc> {
    fn from(fragment: &'doc str) -> Self {
        Self::new(fragment)
    }
}

/// Represents a `[start, end)` byte span for a source expression.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Span {
    /// The start of the span, inclusive.
    pub start: usize,
    /// The end of the span, exclusive.
    pub end: usize,
}

impl Span {
    /// Adjust this span by the given bias.
    pub fn adjust(self, bias: usize) -> Self {
        Self {
            start: self.start + bias,
            end: self.end + bias,
        }
    }

    /// Returns the span as a range.
    pub fn as_range(&self) -> std::ops::Range<usize> {
        self.start..self.end
    }
}

impl From<std::ops::Range<usize>> for Span {
    fn from(range: std::ops::Range<usize>) -> Self {
        Self {
            start: range.start,
            end: range.end,
        }
    }
}

/// Represents a "subfeature" of a symbolic location, such as a substring
/// within a YAML string.
#[derive(Serialize, Clone, Debug)]
pub struct Subfeature<'a> {
    /// A byte index after which the subfeature starts.
    ///
    /// This is a fuzzy anchor: we know our subfeature starts
    /// *somewhere* after this index, but we don't know exactly where it is
    /// in the original feature due to parsed whitespace.
    pub after: usize,
    /// The fragment of the subfeature.
    pub fragment: Fragment<'a>,
}

impl<'a> Subfeature<'a> {
    /// Create a new subfeature with the given `after` index and `fragment`.
    pub fn new(after: usize, fragment: impl Into<Fragment<'a>>) -> Self {
        Self {
            after,
            fragment: fragment.into(),
        }
    }

    /// Locate this subfeature within the given feature.
    ///
    /// Returns the subfeature's span within the feature, or `None` if it
    /// can't be found. The returned span is relative to the feature's
    /// start.
    pub fn locate_within(&self, feature: &str) -> Option<Span> {
        // NOTE: Our inputs are always valid UTF-8 but `after` may not
        // be a valid UTF-8 codepoint index, so everything below operates
        // on a byte slice.
        // Why, you might ask, might `after` not be a valid codepoint index?
        // Because `after` is a fuzzy anchor: we know our subfeature starts
        // *somewhere* after `after`, but we don't know exactly where.
        // This happens because we have a rough sense of where the subfeature
        // is *after* YAML parsing, but we don't know exactly where it is
        // in the original YAML feature due to significant whitespace.
        let feature = feature.as_bytes();
        let bias = self.after;
        let focus = &feature[bias..];

        match &self.fragment {
            Fragment::Raw(fragment) => {
                memchr::memmem::find(focus, fragment.as_bytes()).map(|start| {
                    let end = start + fragment.len();
                    Span::from(start..end).adjust(bias)
                })
            }
            Fragment::Regex(regex) => regex
                .find(focus)
                .map(|m| Span::from(m.range()).adjust(bias)),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Fragment;

    #[test]
    fn test_fragment_from_context() {
        for (ctx, expected) in &[
            ("foo.bar", "foo.bar"),
            ("foo . bar", "foo . bar"),
            ("foo['bar']", "foo['bar']"),
            ("foo [\n'bar'\n]", r"foo\s+\[\s+'bar'\s+\]"),
        ] {
            match Fragment::from(*ctx) {
                Fragment::Raw(actual) => assert_eq!(actual, *expected),
                Fragment::Regex(actual) => assert_eq!(actual.as_str(), *expected),
            }
        }
    }
}
