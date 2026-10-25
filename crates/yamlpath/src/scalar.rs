//! Scalar text and its corresponding YAML source locations.

use std::{borrow::Cow, ops::Range};

use tree_sitter::Node;

use crate::NodeExt as _;

/// The presentation style of a YAML scalar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarStyle {
    /// An unquoted scalar.
    Plain,
    /// A scalar delimited by single quotes.
    SingleQuoted,
    /// A scalar delimited by double quotes.
    DoubleQuoted,
    /// A literal or folded block scalar.
    Block,
}

/// A source-oriented view of a YAML scalar.
///
/// Outer quotes are removed and doubled single quotes are decoded. Other
/// escapes and whitespace are preserved, including block indentation and folding.
/// This is not a fully deserialized YAML value.
///
/// All spans accepted by this type refer to byte offsets in [`Self::text`];
/// the returned source spans are absolute offsets in the original document.
pub struct Scalar<'doc> {
    source: &'doc str,
    text: Cow<'doc, str>,
    start: usize,
    offsets: Vec<usize>,
    style: ScalarStyle,
}

impl<'doc> Scalar<'doc> {
    pub(super) fn new(source: &'doc str, node: Node<'_>) -> Self {
        let style = match () {
            _ if node.is_single_quote_scalar() => ScalarStyle::SingleQuoted,
            _ if node.is_double_quote_scalar() => ScalarStyle::DoubleQuoted,
            _ if node.is_block_scalar() => ScalarStyle::Block,
            _ => ScalarStyle::Plain,
        };
        let quoted = usize::from(node.is_quoted_scalar());
        let start = if style == ScalarStyle::Block {
            let raw = &source[node.byte_range()];
            node.start_byte() + raw.find('\n').map_or(raw.len(), |newline| newline + 1)
        } else {
            node.start_byte() + quoted
        };
        let raw = &source[start..node.end_byte() - quoted];
        let mut text = Cow::Borrowed(raw);
        let mut offsets = vec![];

        if style == ScalarStyle::SingleQuoted && raw.contains("''") {
            let mut decoded = String::with_capacity(raw.len());
            let mut cursor = 0;
            for (escape, _) in raw.match_indices("''") {
                // Keep the first quote and omit the second. Record where each
                // retained byte came from, including the final end boundary.
                decoded.push_str(&raw[cursor..escape + 1]);
                offsets.extend(cursor..escape + 1);
                cursor = escape + 2;
            }
            decoded.push_str(&raw[cursor..]);
            offsets.extend(cursor..=raw.len());
            text = Cow::Owned(decoded);
        }

        Self {
            source,
            text,
            start,
            offsets,
            style,
        }
    }

    /// Returns the scalar's text, with single-quote escaping decoded.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Returns a view of part of this scalar, retaining its source mapping.
    pub fn slice(&self, span: Range<usize>) -> Self {
        let text = match &self.text {
            Cow::Borrowed(text) => Cow::Borrowed(&text[span.clone()]),
            Cow::Owned(text) => Cow::Owned(text[span.clone()].to_owned()),
        };
        let (start, offsets) = if self.offsets.is_empty() {
            (self.start + span.start, vec![])
        } else {
            (self.start, self.offsets[span.start..=span.end].to_vec())
        };
        Self {
            source: self.source,
            text,
            start,
            offsets,
            style: self.style,
        }
    }

    /// Returns the scalar's YAML presentation style.
    pub fn style(&self) -> ScalarStyle {
        self.style
    }

    /// Maps a span in [`Self::text`] to its original document span.
    ///
    /// The input must be within the text and lie on UTF-8 character boundaries.
    pub fn source_span(&self, span: Range<usize>) -> Range<usize> {
        let offset = |offset| {
            self.start
                + if self.offsets.is_empty() {
                    offset
                } else {
                    self.offsets[offset]
                }
        };
        offset(span.start)..offset(span.end)
    }

    /// Returns the original YAML spelling of a span in [`Self::text`].
    pub fn source_text(&self, span: Range<usize>) -> &'doc str {
        &self.source[self.source_span(span)]
    }
}

#[cfg(test)]
mod tests {
    use crate::{Document, route};

    #[test]
    fn scalar_text_and_spans() {
        let doc = Document::new(
            "before: untouched\nfoo: {bar: &anchor 'é it''s quoted'} # ignored\nafter: untouched",
        )
        .unwrap();
        let scalars = doc.scalars(&route!("foo")).unwrap().collect::<Vec<_>>();
        assert_eq!(
            scalars.iter().map(|s| s.text()).collect::<Vec<_>>(),
            ["foo", "bar", "é it's quoted"]
        );
        let scalar = &scalars[2];
        let start = scalar.text().find("it's").unwrap();
        assert_eq!(scalar.source_text(start..start + 4), "it''s");
        assert_eq!(&doc.source()[scalar.source_span(start..start + 4)], "it''s");
        let slice = scalar.slice(start..start + 4);
        assert_eq!(slice.text(), "it's");
        assert_eq!(slice.slice(2..3).source_text(0..1), "''");
        assert_eq!(scalars[1].slice(1..3).source_text(0..2), "ar");
        let quote = doc.source().find("''").unwrap();
        assert_eq!(doc.scalar_at(quote + 1).unwrap().text(), scalar.text());
        assert!(doc.scalar_at(doc.source().find('#').unwrap()).is_none());
    }
}
