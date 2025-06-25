//! Comment and format-preserving YAML path queries.
//!
//! This is **not** "XPath but for YAML". If you need a generic object
//! query language that **doesn't** capture exact parse spans or comments,
//! then you probably want an implementation of [JSONPath] or something
//! like [jq].
//!
//! [JSONPath]: https://en.wikipedia.org/wiki/JSONPath
//! [jq]: https://jqlang.github.io/jq/

#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![allow(clippy::redundant_field_names)]
#![forbid(unsafe_code)]

use line_index::LineIndex;
use thiserror::Error;
use tree_sitter::{Language, Node, Parser, Tree};

/// Possible errors when performing YAML path queries.
#[derive(Error, Debug)]
pub enum QueryError {
    /// The tree-sitter backend couldn't accept the YAML grammar.
    #[error("malformed or unsupported tree-sitter grammar")]
    InvalidLanguage(#[from] tree_sitter::LanguageError),
    /// The user's input YAML is malformed.
    #[error("input is not valid YAML")]
    InvalidInput,
    /// The query expects a key at a given point, but the input isn't a mapping.
    #[error("expected mapping containing key `{0}`")]
    ExpectedMapping(String),
    /// The query expects a list index at a given point, but the input isn't a list.
    #[error("expected list for index `[{0}]`")]
    ExpectedList(usize),
    /// The query expects the given key in a mapping, but the mapping doesn't have that key.
    #[error("mapping has no key `{0}`")]
    ExhaustedMapping(String),
    /// The query expects the given list index, but the list isn't the right size.
    #[error("index `[{0}]` exceeds list size ({1})")]
    ExhaustedList(usize, usize),
    /// The YAML syntax tree wasn't structured the way we expect.
    #[error("unexpected node: `{0}`")]
    UnexpectedNode(String),
    /// The YAML syntax tree is missing an expected named child node.
    #[error("syntax node `{0}` is missing named child `{1}`")]
    MissingChild(String, String),
    /// The YAML syntax tree is missing an expected named child node with
    /// the given field name.
    #[error("syntax node `{0}` is missing child field `{1}`")]
    MissingChildField(String, &'static str),
    /// Any other query error that doesn't fit cleanly above.
    #[error("query error: {0}")]
    Other(String),
}

/// A query into some YAML document.
///
/// Internally, a query is one or more "component" selectors, each of which
/// is either a mapping key or list index to descend through.
///
/// For example, with the following YAML document:
///
/// ```yaml
/// foo:
///   bar:
///     baz:
///       - [a, b, c]
///       - [d, e, f]
/// ```
///
/// The sub-list member `e` would be identified via the path
/// `foo`, `bar`, `baz`, `1`, `1`.
#[derive(Debug)]
pub struct Query<'a> {
    /// The individual top-down components of this query.
    route: Vec<Component<'a>>,
}

impl<'a> Query<'a> {
    /// Constructs a new query from the given path components.
    ///
    /// Returns `None` if the component list is empty.
    pub fn new(route: Vec<Component<'a>>) -> Option<Self> {
        if route.is_empty() {
            None
        } else {
            Some(Self { route })
        }
    }

    /// Returns a query for the "parent" path of the query's current path,
    /// or `None` the current query has no parent.
    pub fn parent(&self) -> Option<Self> {
        let mut route = self.route.clone();
        route.truncate(self.route.len() - 1);
        Self::new(route)
    }
}

/// A builder for [`Query`] objects.
#[derive(Clone, Debug)]
pub struct QueryBuilder<'a> {
    route: Vec<Component<'a>>,
}

impl Default for QueryBuilder<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> QueryBuilder<'a> {
    /// Starts a new `QueryBuilder`.
    pub fn new() -> Self {
        Self { route: vec![] }
    }

    /// Adds a new key to the query being built.
    pub fn key(mut self, key: &'a str) -> Self {
        self.route.push(Component::Key(key));
        self
    }

    /// Adds multiple new keys to the query being built.
    pub fn keys(mut self, keys: impl Iterator<Item = &'a str>) -> Self {
        for key in keys {
            self = self.key(key)
        }

        self
    }

    /// Adds a new index to the query being built.
    pub fn index(mut self, index: usize) -> Self {
        self.route.push(Component::Index(index));
        self
    }

    /// Construct this `QueryBuilder` into a [`Query`], consuming
    /// it in the process.
    ///
    /// Panics unless at least one component has been added.
    pub fn build(self) -> Query<'a> {
        Query::new(self.route).expect("API misuse: must add at least one component")
    }
}

/// A single `Query` component.
#[derive(Clone, Debug, PartialEq)]
pub enum Component<'a> {
    /// A YAML key.
    Key(&'a str),

    /// An index into a YAML array.
    Index(usize),
}

/// Represents the concrete location of some YAML syntax.
#[derive(Debug)]
pub struct Location {
    /// The byte span at which the query's result appears.
    pub byte_span: (usize, usize),
    /// The "point" (i.e., line/column) span at which the query's result appears.
    pub point_span: ((usize, usize), (usize, usize)),
}

impl From<Node<'_>> for Location {
    fn from(node: Node<'_>) -> Self {
        let start_point = node.start_position();
        let end_point = node.end_position();

        Self {
            byte_span: (node.start_byte(), node.end_byte()),
            point_span: (
                (start_point.row, start_point.column),
                (end_point.row, end_point.column),
            ),
        }
    }
}

/// Describes the feature's kind, i.e. whether it's a block/flow aggregate
/// or a scalar value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FeatureKind {
    /// A block-style mapping, e.g. `foo: bar`.
    BlockMapping,
    /// A block-style sequence, e.g. `- foo`.
    BlockSequence,
    /// A flow-style mapping, e.g. `{foo: bar}`.
    FlowMapping,
    /// A flow-style sequence, e.g. `[foo, bar]`.
    FlowSequence,
    /// Any sort of scalar value.
    Scalar,
}

/// Represents the result of a successful query.
#[derive(Debug)]
pub struct Feature<'tree> {
    /// The tree-sitter node that this feature was extracted from.
    _node: Node<'tree>,

    /// The exact location of the query result.
    pub location: Location,

    /// The "context" location for the query result.
    /// This is typically the surrounding mapping or list structure.
    pub context: Option<Location>,
}

impl Feature<'_> {
    /// Return this feature's parent feature, if it has one.
    pub fn parent(&self) -> Option<Feature<'_>> {
        self._node.parent().map(Feature::from)
    }

    /// Return this feature's [`FeatureKind`].
    pub fn kind(&self) -> FeatureKind {
        // TODO: Use node kind IDs instead of string matching.

        // Our feature's underlying node is often a
        // `block_node` or `flow_node`, which is a container
        // for the real kind of node we're interested in.
        let node = match self._node.kind() {
            "block_node" | "flow_node" => self._node.child(0).unwrap(),
            _ => self._node,
        };

        match node.kind() {
            "block_mapping" => FeatureKind::BlockMapping,
            "block_sequence" => FeatureKind::BlockSequence,
            "flow_mapping" => FeatureKind::FlowMapping,
            "flow_sequence" => FeatureKind::FlowSequence,
            "plain_scalar" | "single_quote_scalar" | "double_quote_scalar" | "block_scalar" => {
                FeatureKind::Scalar
            }
            kind => unreachable!("unexpected feature kind: {kind}"),
        }
    }
}

impl<'tree> From<Node<'tree>> for Feature<'tree> {
    fn from(node: Node<'tree>) -> Self {
        Feature {
            _node: node,
            location: Location::from(node),
            context: node.parent().map(Location::from),
        }
    }
}

/// Configures how features are extracted from a YAML document
/// during queries.
#[derive(Copy, Clone, Debug)]
enum QueryMode {
    /// Make extracted features as "pretty" as possible, e.g. by
    /// including components that humans subjectively consider relevant.
    ///
    /// For example, querying `foo: bar` for `foo` will return
    /// `foo: bar` instead of just `bar`.
    Pretty,
    /// For queries that terminate in a key, make the extracted
    /// feature only that key, rather than both the key and value ("pretty"),
    /// or just the value ("exact").
    ///
    /// For example, querying `foo: bar` for `foo` will return `foo`.
    KeyOnly,
    /// Make extracted features as "exact" as possible, e.g. by
    /// including only the exact span of the query result.
    Exact,
}

/// Represents a queryable YAML document.
#[derive(Clone)]
pub struct Document {
    source: String,
    tree: Tree,
    line_index: LineIndex,
    document_id: u16,
    block_node_id: u16,
    flow_node_id: u16,
    // A "block" sequence, i.e. a YAML-style array (`- foo\n-bar`)
    block_sequence_id: u16,
    // A "flow" sequence, i.e. a JSON-style array (`[foo, bar]`)
    flow_sequence_id: u16,
    // A "block" mapping, i.e. a YAML-style map (`foo: bar`)
    block_mapping_id: u16,
    // A "flow" mapping, i.e. a JSON-style map (`{foo: bar}`)
    flow_mapping_id: u16,
    block_mapping_pair_id: u16,
    flow_pair_id: u16,
    block_sequence_item_id: u16,
    comment_id: u16,
}

impl Document {
    /// Construct a new `Document` from the given YAML.
    pub fn new(source: impl Into<String>) -> Result<Self, QueryError> {
        let source = source.into();

        let mut parser = Parser::new();
        let language: Language = tree_sitter_yaml::LANGUAGE.into();
        parser.set_language(&language)?;

        // NOTE: Infallible, assuming `language` is correctly constructed above.
        let tree = parser.parse(&source, None).unwrap();

        if tree.root_node().has_error() {
            return Err(QueryError::InvalidInput);
        }

        let line_index = LineIndex::new(&source);

        Ok(Self {
            source,
            tree,
            line_index,
            document_id: language.id_for_node_kind("document", true),
            block_node_id: language.id_for_node_kind("block_node", true),
            flow_node_id: language.id_for_node_kind("flow_node", true),
            block_sequence_id: language.id_for_node_kind("block_sequence", true),
            flow_sequence_id: language.id_for_node_kind("flow_sequence", true),
            block_mapping_id: language.id_for_node_kind("block_mapping", true),
            flow_mapping_id: language.id_for_node_kind("flow_mapping", true),
            block_mapping_pair_id: language.id_for_node_kind("block_mapping_pair", true),
            flow_pair_id: language.id_for_node_kind("flow_pair", true),
            block_sequence_item_id: language.id_for_node_kind("block_sequence_item", true),
            comment_id: language.id_for_node_kind("comment", true),
        })
    }

    /// Returns a [`LineIndex`] for this document, which can be used
    /// to efficiently map between byte offsets and line coordinates.
    pub fn line_index(&self) -> &LineIndex {
        &self.line_index
    }

    /// Return a view of the original YAML source that this document was
    /// loaded from.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns a `Feature` for this document's root node.
    ///
    /// This is typically useful as a "fallback" feature, e.g. for capturing
    /// a span of the entire document.
    pub fn root(&self) -> Feature {
        self.tree.root_node().into()
    }

    /// Returns a [`Feature`] for the topmost semantic object in this document.
    ///
    /// This is typically useful as a "fallback" feature, e.g. for positioning
    /// relative to the "top" of the document.
    pub fn top_feature(&self) -> Result<Feature, QueryError> {
        let top_node = self.top_object()?;
        Ok(top_node.into())
    }

    /// Returns whether the given range is spanned by a comment node.
    ///
    /// The comment node must fully span the range; a range that ends
    /// after the comment or starts before it will not be considered
    /// spanned.
    pub fn range_spanned_by_comment(&self, start: usize, end: usize) -> bool {
        let root = self.tree.root_node();

        match root.named_descendant_for_byte_range(start, end) {
            Some(child) => child.kind_id() == self.comment_id,
            None => false,
        }
    }

    /// Returns whether the given offset is within a comment node's span.
    pub fn offset_inside_comment(&self, offset: usize) -> bool {
        self.range_spanned_by_comment(offset, offset)
    }

    /// Perform a query on the current document, returning `true`
    /// if the query succeeds (i.e. references an existing feature).
    ///
    /// All errors become `false`.
    pub fn query_exists(&self, query: &Query) -> bool {
        self.query_node(query, QueryMode::Exact).is_ok()
    }

    /// Perform a query on the current document, returning a `Feature`
    /// if the query succeeds.
    ///
    /// The feature is extracted in "pretty" mode, meaning that it'll
    /// contain a subjectively relevant "pretty" span rather than the
    /// exact span of the query result.
    ///
    /// For example, querying `foo: bar` for `foo` will return
    /// `foo: bar` instead of just `bar`.
    pub fn query_pretty(&self, query: &Query) -> Result<Feature, QueryError> {
        self.query_node(query, QueryMode::Pretty).map(|n| n.into())
    }

    /// Perform a query on the current document, returning a `Feature`
    /// if the query succeeds. Returns `None` if the query
    /// succeeds, but matches an absent value (e.g. `foo:`).
    ///
    /// The feature is extracted in "exact" mode, meaning that it'll
    /// contain the exact span of the query result.
    ///
    /// For example, querying `foo: bar` for `foo` will return
    /// just `bar` instead of `foo: bar`.
    pub fn query_exact(&self, query: &Query) -> Result<Option<Feature>, QueryError> {
        let node = self.query_node(query, QueryMode::Exact)?;

        if node.kind_id() == self.block_mapping_pair_id || node.kind_id() == self.flow_pair_id {
            // If the query matches a mapping pair, we return None,
            // since this indicates an absent value.
            Ok(None)
        } else {
            // Otherwise, we return the node as a feature.
            Ok(Some(node.into()))
        }
    }

    /// Perform a query on the current document, returning a `Feature`
    /// if the query succeeds.
    ///
    /// The feature is extracted in "key only" mode, meaning that it'll
    /// contain only the key of a mapping, rather than the
    /// key and value ("pretty") or just the value ("exact").
    ///
    /// For example, querying `foo: bar` for `foo` will return
    /// just `foo` instead of `foo: bar` or `bar`.
    pub fn query_key_only(&self, query: &Query) -> Result<Feature, QueryError> {
        if !matches!(query.route.last(), Some(Component::Key(_))) {
            return Err(QueryError::Other(
                "query must end with a key component for key-only queries".into(),
            ));
        }

        self.query_node(query, QueryMode::KeyOnly).map(|n| n.into())
    }

    /// Returns a string slice of the original document corresponding to
    /// the given [`Feature`].
    ///
    /// This function returns a slice corresponding to the [`Feature`]'s exact
    /// span, meaning that leading whitespace for the start point is not
    /// necessarily captured. See [`Self::extract_with_leading_whitespace`]
    /// for feature extraction with rudimentary whitespace handling.
    ///
    /// Panics if the feature's span is invalid.
    pub fn extract(&self, feature: &Feature) -> &str {
        &self.source[feature.location.byte_span.0..feature.location.byte_span.1]
    }

    /// Returns a string slice of the original document corresponding to the given
    /// [`Feature`], along with any leading (indentation-semantic) whitespace.
    ///
    /// **Important**: The returned string here can be longer than the span
    /// identified in the [`Feature`]. In particular, this API will return a
    /// longer string if it identifies leading non-newline whitespace
    /// ahead of the captured [`Feature`], since this indicates indentation
    /// not encapsulated by the feature itself.
    ///
    /// Panics if the feature's span is invalid.
    pub fn extract_with_leading_whitespace<'a>(&'a self, feature: &Feature) -> &'a str {
        let mut start_idx = feature.location.byte_span.0;
        let pre_slice = &self.source[0..start_idx];
        if let Some(last_newline) = pre_slice.rfind('\n') {
            // If everything between the last newline and the start_index
            // is ASCII spaces, then we include it.
            if self.source[last_newline + 1..start_idx]
                .bytes()
                .all(|b| b == b' ')
            {
                start_idx = last_newline + 1
            }
        }

        &self.source[start_idx..feature.location.byte_span.1]
    }

    /// Given a [`Feature`], return all comments that span the same range
    /// as the feature does.
    pub fn feature_comments<'tree>(&'tree self, feature: &Feature<'tree>) -> Vec<&'tree str> {
        // To extract all comments for a feature, we trawl the entire tree's
        // nodes and extract all comment nodes in the line range for the
        // feature.
        // This isn't the fastest way to do things, since we end up
        // visiting a lot of (top-level) nodes that aren't in the feature's
        // range.
        // The alternative to this approach would be to find the feature's
        // spanning parent and only trawl that subset of the tree; the main
        // annoyance with doing things that way is the AST can look like this:
        //
        // top
        // |
        // |------ parent
        // |       |
        // |       |____ child
        // |
        // |______ comment
        //
        // With this AST the spanning parent is 'parent', but the 'comment'
        // node is actually *adjacent* to 'parent' rather than enclosed in it.

        let start_line = feature.location.point_span.0.0;
        let end_line = feature.location.point_span.1.0;

        fn trawl<'tree>(
            node: &Node<'tree>,
            source: &'tree str,
            comment_id: u16,
            start_line: usize,
            end_line: usize,
        ) -> Vec<&'tree str> {
            let mut comments = vec![];
            let mut cur = node.walk();

            // If this node ends before our span or starts after it, there's
            // no point in recursing through it.
            if node.end_position().row < start_line || node.start_position().row > end_line {
                return comments;
            }

            // Find any comments among the current children.
            comments.extend(
                node.named_children(&mut cur)
                    .filter(|c| {
                        c.kind_id() == comment_id
                            && c.start_position().row >= start_line
                            && c.end_position().row <= end_line
                    })
                    .map(|c| c.utf8_text(source.as_bytes()).unwrap()),
            );

            for child in node.children(&mut cur) {
                comments.extend(trawl(&child, source, comment_id, start_line, end_line));
            }

            comments
        }

        trawl(
            &self.tree.root_node(),
            &self.source,
            self.comment_id,
            start_line,
            end_line,
        )
    }

    /// Returns the topmost semantic object in the YAML document,
    /// i.e. the node corresponding to the first block or flow feature.
    fn top_object(&self) -> Result<Node, QueryError> {
        // All tree-sitter-yaml trees start with a `stream` node.
        let stream = self.tree.root_node();

        // The `document` child is the "body" of the YAML document; it
        // might not be the first node in the `stream` if there are comments.
        let mut cur = stream.walk();
        let document = stream
            .named_children(&mut cur)
            .find(|c| c.kind_id() == self.document_id)
            .ok_or_else(|| QueryError::MissingChild(stream.kind().into(), "document".into()))?;

        // The document might have a directives section, which we need to
        // skip over. We do this by finding the top-level `block_node`
        // or `flow_node`, of which one will be present depending on how
        // the top-level document value is expressed.
        let top_node = document
            .named_children(&mut cur)
            .find(|c| c.kind_id() == self.block_node_id || c.kind_id() == self.flow_node_id)
            .ok_or_else(|| QueryError::Other("document has no block_node or flow_node".into()))?;

        Ok(top_node)
    }

    fn query_node(&self, query: &Query, mode: QueryMode) -> Result<Node, QueryError> {
        let mut focus_node = self.top_object()?;
        for component in &query.route {
            match self.descend(&focus_node, component) {
                Ok(next) => focus_node = next,
                Err(e) => return Err(e),
            }
        }

        focus_node = match mode {
            QueryMode::Pretty => {
                // If we're in "pretty" mode, we want to return the
                // block/flow pair node that contains the key.
                // This results in a (subjectively) more intuitive extracted feature,
                // since `foo: bar` gets extracted for `foo` instead of just `bar`.
                //
                // NOTE: We might already be on the block/flow pair if we terminated
                // with an absent value, in which case we don't need to do this cleanup.
                if matches!(query.route.last(), Some(Component::Key(_)))
                    && focus_node.kind_id() != self.block_mapping_pair_id
                    && focus_node.kind_id() != self.flow_pair_id
                {
                    focus_node.parent().unwrap()
                } else {
                    focus_node
                }
            }
            QueryMode::KeyOnly => {
                // If we're in "key only" mode, we need to walk back up to
                // the parent block/flow pair node that contains the key,
                // and isolate on the key child instead.

                // If we're already on block/flow pair, then we're already
                // the key's parent.
                let parent_node = if focus_node.kind_id() == self.block_mapping_pair_id
                    || focus_node.kind_id() == self.flow_pair_id
                {
                    focus_node
                } else {
                    focus_node.parent().unwrap()
                };

                if parent_node.kind_id() == self.flow_mapping_id {
                    // Handle the annoying `foo: { key }` case, where our "parent"
                    // is actually a `flow_mapping` instead of a proper block/flow pair.
                    // To handle this, we get the first `flow_node` child of the
                    // flow_mapping, which is the "key".
                    let mut cur = parent_node.walk();
                    parent_node
                        .named_children(&mut cur)
                        .find(|n| n.kind_id() == self.flow_node_id)
                        .ok_or_else(|| {
                            QueryError::MissingChildField(parent_node.kind().into(), "flow_node")
                        })?
                } else {
                    parent_node.child_by_field_name("key").ok_or_else(|| {
                        QueryError::MissingChildField(parent_node.kind().into(), "key")
                    })?
                }
            }
            // Nothing special to do in exact mode.
            QueryMode::Exact => focus_node,
        };

        // If we're extracting "pretty" features, we clean up the final
        // node a bit to have it point to the parent `block_mapping_pair`.
        // This results in a (subjectively) more intuitive extracted feature,
        // since `foo: bar` gets extracted for `foo` instead of just `bar`.
        //
        // NOTE: We might already be on the block_mapping_pair if we terminated
        // with an absent value, in which case we don't need to do this cleanup.
        if matches!(mode, QueryMode::Pretty)
            && matches!(query.route.last(), Some(Component::Key(_)))
            && focus_node.kind_id() != self.block_mapping_pair_id
        {
            focus_node = focus_node.parent().unwrap()
        }

        Ok(focus_node)
    }

    fn descend<'b>(&self, node: &Node<'b>, component: &Component) -> Result<Node<'b>, QueryError> {
        // The cursor is assumed to start on a block_node or flow_node,
        // which has a single child containing the inner scalar/vector
        // type we're descending through.
        let child = node.child(0).unwrap();

        // We expect the child to be a sequence or mapping of either
        // flow or block type.
        if child.kind_id() == self.block_mapping_id || child.kind_id() == self.flow_mapping_id {
            match component {
                Component::Key(key) => self.descend_mapping(&child, key),
                Component::Index(idx) => Err(QueryError::ExpectedList(*idx)),
            }
        } else if child.kind_id() == self.block_sequence_id
            || child.kind_id() == self.flow_sequence_id
        {
            match component {
                Component::Index(idx) => self.descend_sequence(&child, *idx),
                Component::Key(key) => Err(QueryError::ExpectedMapping(key.to_string())),
            }
        } else {
            Err(QueryError::UnexpectedNode(child.kind().into()))
        }
    }

    fn descend_mapping<'b>(&self, node: &Node<'b>, expected: &str) -> Result<Node<'b>, QueryError> {
        let mut cur = node.walk();
        for child in node.named_children(&mut cur) {
            let key = match child.kind_id() {
                // If we're on a `flow_pair` or `block_mapping_pair`, we
                // need to get the `key` child.
                id if id == self.flow_pair_id || id == self.block_mapping_pair_id => child
                    .child_by_field_name("key")
                    .ok_or_else(|| QueryError::MissingChildField(child.kind().into(), "key"))?,
                // NOTE: Annoying edge case: if we have a flow mapping
                // like `{ foo }`, then `foo` is a `flow_node` instead
                // of a `flow_pair`.
                id if id == self.flow_node_id => child,
                _ => continue,
            };

            // NOTE: To get the key's actual value, we need to get down to its
            // inner scalar. This is slightly annoying, since keys can be
            // quoted strings with no interior unquoted child. In those cases,
            // we need to manually unquote them.
            //
            // NOTE: text unwraps are infallible, since our document is UTF-8.
            let key_value = match key.named_child(0) {
                Some(scalar) => {
                    let key_value = scalar.utf8_text(self.source.as_bytes()).unwrap();

                    match scalar.kind() {
                        "single_quote_scalar" | "double_quote_scalar" => {
                            let mut chars = key_value.chars();
                            chars.next();
                            chars.next_back();
                            chars.as_str()
                        }
                        _ => key_value,
                    }
                }
                None => key.utf8_text(self.source.as_bytes()).unwrap(),
            };

            if key_value == expected {
                // HACK: a mapping key might not have a corresponding value,
                // in which case we fall back and return the `block_mapping_pair`
                // itself here. This technically breaks our contract of returning
                // only block_node/flow_node nodes during descent, but not
                // in a way that matters (since an empty value is terminal anyways).
                return Ok(child.child_by_field_name("value").unwrap_or(child));
            }
        }

        // None of the keys in the mapping matched.
        Err(QueryError::ExhaustedMapping(expected.into()))
    }

    fn descend_sequence<'b>(&self, node: &Node<'b>, idx: usize) -> Result<Node<'b>, QueryError> {
        let mut cur = node.walk();
        // TODO: Optimize; we shouldn't collect the entire child set just to extract one.
        let children = node
            .named_children(&mut cur)
            .filter(|n| {
                n.kind_id() == self.block_sequence_item_id
                    || n.kind_id() == self.flow_node_id
                    || n.kind_id() == self.flow_pair_id
            })
            .collect::<Vec<_>>();
        let Some(child) = children.get(idx) else {
            return Err(QueryError::ExhaustedList(idx, children.len()));
        };

        // If we're in a block_sequence, there's an intervening `block_sequence_item`
        // getting in the way of our `block_node`/`flow_node`.
        if child.kind_id() == self.block_sequence_item_id {
            // NOTE: We can't just get the first named child here, since there might
            // be interceding comments.
            return child
                .named_children(&mut cur)
                .find(|c| c.kind_id() == self.block_node_id || c.kind_id() == self.flow_node_id)
                .ok_or_else(|| {
                    QueryError::MissingChild(child.kind().into(), "block_sequence_item".into())
                });
        } else if child.kind_id() == self.flow_pair_id {
            // Similarly, if our index happens to be a `flow_pair`, we need to
            // get the `value` child to get the next `flow_node`.
            // The `value` might not be present (e.g. `{foo: }`), in which case
            // we treat the `flow_pair` itself as terminal like with the mapping hack.
            return Ok(child.child_by_field_name("value").unwrap_or(*child));
        }

        Ok(*child)
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use crate::{Component, Document, FeatureKind, Query, QueryBuilder};

    #[test]
    fn test_query_parent() {
        let query = QueryBuilder::new()
            .keys(["foo", "bar", "baz"].into_iter())
            .build();
        assert_eq!(
            query.parent().unwrap().route,
            [Component::Key("foo"), Component::Key("bar")]
        );

        let query = QueryBuilder::new().keys(["foo"].into_iter()).build();
        assert!(query.parent().is_none());
    }

    #[test]
    fn test_location_spanned_by_comment() {
        let doc = Document::new(
            r#"
foo: bar
# comment
baz: quux
        "#,
        )
        .unwrap();

        // Before the comment.
        assert!(!doc.range_spanned_by_comment(1, 4));
        // Single point within the comment's span.
        assert!(doc.range_spanned_by_comment(13, 13));
        // Within the comment's span.
        assert!(doc.range_spanned_by_comment(13, 15));
        // Starts inside the comment, ends outside.
        assert!(!doc.range_spanned_by_comment(13, 21));
    }

    #[test]
    fn test_offset_inside_comment() {
        let doc = Document::new("foo: bar # abc def").unwrap();

        let comment = doc.source().find('#').unwrap();
        for idx in 0..doc.source().len() {
            if idx < comment {
                assert!(!doc.offset_inside_comment(idx));
            } else {
                assert!(doc.offset_inside_comment(idx));
            }
        }
    }

    #[test]
    fn test_query_builder() {
        let query = QueryBuilder::new()
            .key("foo")
            .key("bar")
            .index(1)
            .index(123)
            .key("lol")
            .build();

        assert_eq!(
            query.route,
            [
                Component::Key("foo"),
                Component::Key("bar"),
                Component::Index(1),
                Component::Index(123),
                Component::Key("lol"),
            ]
        )
    }

    #[test]
    fn test_basic() {
        let doc = r#"
foo: bar
baz:
  sub:
    keys:
      abc:
        - 123
        - 456
        - [a, b, c, {d: e}]
        "#;

        let doc = Document::new(doc).unwrap();
        let query = Query {
            route: vec![
                Component::Key("baz"),
                Component::Key("sub"),
                Component::Key("keys"),
                Component::Key("abc"),
                Component::Index(2),
                Component::Index(3),
            ],
        };

        assert_eq!(
            doc.extract_with_leading_whitespace(&doc.query_pretty(&query).unwrap()),
            "{d: e}"
        );
    }

    #[test]
    fn test_feature_comments() {
        let doc = r#"
root: # rootlevel
  a: 1 # foo
  b: 2 # bar
  c: 3
  d: 4 # baz
  e: [1, 2, {nested: key}] # quux

bar: # outside
# outside too
        "#;

        let doc = Document::new(doc).unwrap();

        // Querying the root gives us all comments underneath it.
        let query = Query {
            route: vec![Component::Key("root")],
        };
        let feature = doc.query_pretty(&query).unwrap();
        assert_eq!(
            doc.feature_comments(&feature),
            &["# rootlevel", "# foo", "# bar", "# baz", "# quux"]
        );

        // Querying a nested key gives us its adjacent comment,
        // even though it's above it on the AST.
        let query = Query {
            route: vec![
                Component::Key("root"),
                Component::Key("e"),
                Component::Index(1),
            ],
        };
        let feature = doc.query_pretty(&query).unwrap();
        assert_eq!(doc.feature_comments(&feature), &["# quux"]);
    }

    #[test]
    fn test_feature_kind() {
        let doc = r#"
block-mapping:
  foo: bar

"block-mapping-quoted":
  foo: bar

block-sequence:
  - foo
  - bar

"block-sequence-quoted":
  - foo
  - bar

flow-mapping: {foo: bar}

flow-sequence: [foo, bar]

scalars:
  - abc
  - 'abc'
  - "abc"
  - 123
  - -123
  - 123.456
  - true
  - false
  - null
  - |
    multiline
    text
  - >
    folded
    text

nested:
  foo:
    - bar
    - baz
    - { a: b }
    - { c: }
"#;
        let doc = Document::new(doc).unwrap();

        for (query, expected_kind) in &[
            (
                vec![Component::Key("block-mapping")],
                FeatureKind::BlockMapping,
            ),
            (
                vec![Component::Key("block-mapping-quoted")],
                FeatureKind::BlockMapping,
            ),
            (
                vec![Component::Key("block-sequence")],
                FeatureKind::BlockSequence,
            ),
            (
                vec![Component::Key("block-sequence-quoted")],
                FeatureKind::BlockSequence,
            ),
            (
                vec![Component::Key("flow-mapping")],
                FeatureKind::FlowMapping,
            ),
            (
                vec![Component::Key("flow-sequence")],
                FeatureKind::FlowSequence,
            ),
            (
                vec![Component::Key("scalars"), Component::Index(0)],
                FeatureKind::Scalar,
            ),
            (
                vec![Component::Key("scalars"), Component::Index(1)],
                FeatureKind::Scalar,
            ),
            (
                vec![Component::Key("scalars"), Component::Index(2)],
                FeatureKind::Scalar,
            ),
            (
                vec![Component::Key("scalars"), Component::Index(3)],
                FeatureKind::Scalar,
            ),
            (
                vec![Component::Key("scalars"), Component::Index(4)],
                FeatureKind::Scalar,
            ),
            (
                vec![Component::Key("scalars"), Component::Index(5)],
                FeatureKind::Scalar,
            ),
            (
                vec![Component::Key("scalars"), Component::Index(6)],
                FeatureKind::Scalar,
            ),
            (
                vec![Component::Key("scalars"), Component::Index(7)],
                FeatureKind::Scalar,
            ),
            (
                vec![Component::Key("scalars"), Component::Index(8)],
                FeatureKind::Scalar,
            ),
            (
                vec![Component::Key("scalars"), Component::Index(9)],
                FeatureKind::Scalar,
            ),
            (
                vec![Component::Key("scalars"), Component::Index(10)],
                FeatureKind::Scalar,
            ),
            (
                vec![
                    Component::Key("nested"),
                    Component::Key("foo"),
                    Component::Index(2),
                ],
                FeatureKind::FlowMapping,
            ),
            (
                vec![
                    Component::Key("nested"),
                    Component::Key("foo"),
                    Component::Index(3),
                ],
                FeatureKind::FlowMapping,
            ),
        ] {
            let query = Query::new(query.clone()).unwrap();
            let feature = doc.query_exact(&query).unwrap().unwrap();
            assert_eq!(feature.kind(), *expected_kind);
        }
    }
}
