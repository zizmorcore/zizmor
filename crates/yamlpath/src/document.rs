//! Locate YAML syntax in the original UTF-8 input.

use std::ops::Range;

use astral_yaml::{Comment, Node, NodeId, NodeKind, Span, Stream};
use line_index::LineIndex;
use thiserror::Error;

use crate::{Component, Route};

self_cell::self_cell! {
    struct Parsed {
        owner: String,
        #[covariant]
        dependent: Stream,
    }
    impl {Debug}
}

/// Errors following a route in a YAML input.
#[derive(Debug, Error)]
pub enum QueryError {
    /// A route needs a single document to start from.
    #[error("expected exactly one YAML document")]
    DocumentCount,
    /// A mapping key or sequence index was absent.
    #[error("no such YAML path component: {0:?}")]
    Missing(Component<'static>),
    /// The route does not select a mapping entry.
    #[error("route must end in a mapping key")]
    ExpectedKey,
}

/// Parsed YAML and a line index into its original source.
#[derive(Debug)]
pub struct Document {
    parsed: Parsed,
    lines: LineIndex,
}

impl Document {
    /// Parse UTF-8 input. Routes and typed deserialization require a single document.
    pub fn new(source: impl Into<String>) -> Result<Self, astral_yaml::Error> {
        let parsed = Parsed::try_new(source.into(), |source| astral_yaml::parse(source))?;
        let source = parsed.borrow_owner();
        // line-index recognizes LF. Preserve the byte positions of mixed and bare CRs.
        let lines = if source
            .match_indices('\r')
            .any(|(i, _)| source.as_bytes().get(i + 1) != Some(&b'\n'))
        {
            LineIndex::new(&source.replace("\r\n", " \n").replace('\r', "\n"))
        } else {
            LineIndex::new(source)
        };
        Ok(Self { parsed, lines })
    }

    /// The same stream used for route queries can be deserialized with Astral Serde.
    pub fn stream(&self) -> &Stream<'_> {
        self.parsed.borrow_dependent()
    }

    /// Original text, including line endings.
    pub fn source(&self) -> &str {
        self.stream().source()
    }

    /// Original-source line and column lookup.
    pub fn line_index(&self) -> &LineIndex {
        &self.lines
    }

    /// Whether any node introduces an anchor.
    pub fn has_anchors(&self) -> bool {
        self.stream()
            .nodes()
            .iter()
            .any(|node| node.anchor.is_some())
    }

    fn node(&self, id: NodeId) -> &Node<'_> {
        &self.stream().nodes()[id.index()]
    }

    fn resolved(&self, id: NodeId) -> &Node<'_> {
        let node = self.node(id);
        match node.kind {
            NodeKind::Alias { target, .. } => self.node(target),
            _ => node,
        }
    }

    fn lookup(&self, route: &Route) -> Result<Selection, QueryError> {
        let [doc] = self.stream().documents() else {
            return Err(QueryError::DocumentCount);
        };
        let mut selected = Selection {
            id: doc.root,
            key: None,
            span: self.node(doc.root).span,
        };
        for component in &route.route {
            selected = match (&self.resolved(selected.id).kind, component) {
                (NodeKind::Mapping { entries, .. }, Component::Key(name)) => {
                    entries.iter().find_map(|entry| {
                        let NodeKind::Scalar(key) = &self.resolved(entry.key).kind else {
                            return None;
                        };
                        (key.value == *name).then_some(Selection {
                            id: entry.value,
                            key: Some(entry.key),
                            span: entry.span,
                        })
                    })
                }
                (NodeKind::Sequence { items, .. }, Component::Index(index)) => {
                    items.get(*index).map(|&id| Selection {
                        id,
                        key: None,
                        span: self.node(id).span,
                    })
                }
                _ => None,
            }
            .ok_or_else(|| {
                QueryError::Missing(match component {
                    Component::Key(key) => Component::Key(key.to_string().into()),
                    Component::Index(i) => Component::Index(*i),
                })
            })?;
        }
        Ok(selected)
    }

    /// Original span of the mapping entry or sequence item, including a terminal alias use.
    pub fn entry_range(&self, route: &Route) -> Result<Range<usize>, QueryError> {
        Ok(range(self.lookup(route)?.span))
    }

    /// Original span of the selected mapping key.
    pub fn key_range(&self, route: &Route) -> Result<Range<usize>, QueryError> {
        let key = self.lookup(route)?.key.ok_or(QueryError::ExpectedKey)?;
        Ok(range(self.node(key).span))
    }

    /// Resolved value span. Scalar spans exclude tag and anchor properties.
    /// An omitted mapping value has no source text.
    pub fn value_range(&self, route: &Route) -> Result<Option<Range<usize>>, QueryError> {
        let node = self.resolved(self.lookup(route)?.id);
        let span = match &node.kind {
            NodeKind::Scalar(scalar) => scalar.span,
            _ => node.span,
        };
        Ok((!span.is_empty()).then(|| range(span)))
    }

    /// YAML comments on the lines occupied by a finding, in source order.
    pub fn comments(&self, range: Range<usize>) -> &[Comment<'_>] {
        let source = self.source();
        let start = source[..range.start]
            .rfind(['\r', '\n'])
            .map_or(0, |i| i + 1);
        let end = if range.end > range.start && source[..range.end].ends_with(['\r', '\n']) {
            range.end
        } else {
            range.end
                + source[range.end..]
                    .find(['\r', '\n'])
                    .unwrap_or(source.len() - range.end)
        };
        let comments = self.stream().comments();
        &comments[comments.partition_point(|c| c.span.start() < start)
            ..comments.partition_point(|c| c.span.start() < end)]
    }

    /// Whether an original byte offset falls inside a YAML comment.
    pub fn offset_inside_comment(&self, offset: usize) -> bool {
        let comments = self.stream().comments();
        let i = comments.partition_point(|c| c.span.end() <= offset);
        comments.get(i).is_some_and(|c| c.span.start() <= offset)
    }
}

struct Selection {
    id: NodeId,
    key: Option<NodeId>,
    span: Span,
}

fn range(span: Span) -> Range<usize> {
    span.start()..span.end()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route;

    #[test]
    fn original_byte_offsets() {
        let source = "é: &v 'a\u{80}b' # first\r\ncopy: *v # second\rnext: é\n";
        let doc = Document::new(source).unwrap();
        for key in ["é", "copy"] {
            let range = doc.value_range(&route!(key)).unwrap().unwrap();
            assert_eq!(&source[range], "'a\u{80}b'");
        }
        let entry = doc.entry_range(&route!("copy")).unwrap();
        assert_eq!(&source[entry.clone()], "copy: *v");
        let [comment] = doc.comments(entry) else {
            panic!("one inline comment")
        };
        assert_eq!(comment.span.slice(source), Some("# second"));
        assert!(doc.offset_inside_comment(comment.span.start()));
        assert!(!doc.offset_inside_comment(comment.span.end()));
        let key = doc.key_range(&route!("next")).unwrap();
        assert_eq!(doc.line_index().line_col((key.start as u32).into()).line, 2);
    }

    #[test]
    fn absent_omitted_and_null() {
        let doc = Document::new("{empty, explicit: null, quoted: ''}").unwrap();
        assert!(doc.value_range(&route!("missing")).is_err());
        assert_eq!(doc.value_range(&route!("empty")).unwrap(), None);
        for (key, expected) in [("explicit", "null"), ("quoted", "''")] {
            assert_eq!(
                &doc.source()[doc.value_range(&route!(key)).unwrap().unwrap()],
                expected
            );
        }
    }
}
