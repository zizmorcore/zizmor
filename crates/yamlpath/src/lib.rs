//! Comment and format-preserving YAML path routes.
//!
//! This is **not** "XPath but for YAML". If you need a generic object
//! route language that **doesn't** capture exact parse spans or comments,
//! then you probably want an implementation of [JSONPath] or something
//! like [jq].
//!
//! [JSONPath]: https://en.wikipedia.org/wiki/JSONPath
//! [jq]: https://jqlang.github.io/jq/

#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![allow(clippy::redundant_field_names)]

use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    ops::{Deref, RangeBounds},
};

use line_index::{LineIndex, TextSize};
use serde::Serialize;
use thiserror::Error;
use tree_sitter::{Language, Node, Parser};
use tree_sitter_iter::TreeIter;

/// Extension trait for tree-sitter `Node` to provide fluent node kind checks.
/// The complete list of node type is available at https://github.com/tree-sitter-grammars/tree-sitter-yaml/blob/master/src/node-types.json
/// but only the one used in this crate are implemented below.
trait NodeExt {
    /// Returns true if this node is an anchor node.
    fn is_anchor(&self) -> bool;

    /// Returns true if this node is an alias node.
    fn is_alias(&self) -> bool;

    /// Returns true if this node is a comment node.
    fn is_comment(&self) -> bool;

    /// Returns true if this node is a block_node.
    fn is_block_node(&self) -> bool;

    /// Returns true if this node is a flow_node.
    fn is_flow_node(&self) -> bool;

    /// Returns true if this node is either a block_node or flow_node.
    fn is_block_or_flow_node(&self) -> bool;

    /// Returns true if this node is a block_mapping.
    fn is_block_mapping(&self) -> bool;

    /// Returns true if this node is a flow_mapping.
    fn is_flow_mapping(&self) -> bool;

    /// Returns true if this node is either a block_mapping or flow_mapping.
    fn is_mapping(&self) -> bool;

    /// Returns true if this node is a block_mapping_pair.
    fn is_block_mapping_pair(&self) -> bool;

    /// Returns true if this node is a flow_pair.
    fn is_flow_pair(&self) -> bool;

    /// Returns true if this node is either a block_mapping_pair or flow_pair.
    fn is_pair(&self) -> bool;

    /// Returns true if this node is a block_sequence.
    fn is_block_sequence(&self) -> bool;

    /// Returns true if this node is a flow_sequence.
    fn is_flow_sequence(&self) -> bool;

    /// Returns true if this node is either a block_sequence or flow_sequence.
    fn is_sequence(&self) -> bool;

    /// Returns true if this node is a block_sequence_item.
    fn is_block_sequence_item(&self) -> bool;

    /// Returns true if this node is a block_scalar.
    fn is_block_scalar(&self) -> bool;

    /// Returns true if this node is a document node.
    fn is_document(&self) -> bool;

    /// Returns true if this node is a plain_scalar.
    fn is_plain_scalar(&self) -> bool;

    /// Returns true if this node is a single_quote_scalar.
    fn is_single_quote_scalar(&self) -> bool;

    /// Returns true if this node is a double_quote_scalar.
    fn is_double_quote_scalar(&self) -> bool;

    /// Returns true if this node is a quoted scalar.
    fn is_quoted_scalar(&self) -> bool;

    /// Returns true if this node is any kind of scalar.
    fn is_scalar(&self) -> bool;
}

impl NodeExt for Node<'_> {
    fn is_anchor(&self) -> bool {
        self.kind() == "anchor"
    }

    fn is_alias(&self) -> bool {
        self.kind() == "alias"
    }

    fn is_comment(&self) -> bool {
        self.kind() == "comment"
    }

    fn is_block_node(&self) -> bool {
        self.kind() == "block_node"
    }

    fn is_flow_node(&self) -> bool {
        self.kind() == "flow_node"
    }

    fn is_block_or_flow_node(&self) -> bool {
        self.is_block_node() || self.is_flow_node()
    }

    fn is_block_mapping(&self) -> bool {
        self.kind() == "block_mapping"
    }

    fn is_flow_mapping(&self) -> bool {
        self.kind() == "flow_mapping"
    }

    fn is_mapping(&self) -> bool {
        self.is_block_mapping() || self.is_flow_mapping()
    }

    fn is_block_mapping_pair(&self) -> bool {
        self.kind() == "block_mapping_pair"
    }

    fn is_flow_pair(&self) -> bool {
        self.kind() == "flow_pair"
    }

    fn is_pair(&self) -> bool {
        self.is_block_mapping_pair() || self.is_flow_pair()
    }

    fn is_block_sequence(&self) -> bool {
        self.kind() == "block_sequence"
    }

    fn is_flow_sequence(&self) -> bool {
        self.kind() == "flow_sequence"
    }

    fn is_sequence(&self) -> bool {
        self.is_block_sequence() || self.is_flow_sequence()
    }

    fn is_block_sequence_item(&self) -> bool {
        self.kind() == "block_sequence_item"
    }

    fn is_block_scalar(&self) -> bool {
        self.kind() == "block_scalar"
    }

    fn is_document(&self) -> bool {
        self.kind() == "document"
    }

    fn is_plain_scalar(&self) -> bool {
        self.kind() == "plain_scalar"
    }

    fn is_single_quote_scalar(&self) -> bool {
        self.kind() == "single_quote_scalar"
    }

    fn is_double_quote_scalar(&self) -> bool {
        self.kind() == "double_quote_scalar"
    }

    fn is_quoted_scalar(&self) -> bool {
        self.is_single_quote_scalar() || self.is_double_quote_scalar()
    }

    fn is_scalar(&self) -> bool {
        self.is_plain_scalar() || self.is_quoted_scalar() || self.is_block_scalar()
    }
}

/// Possible errors when performing YAML path routes.
#[derive(Error, Debug)]
pub enum QueryError {
    /// The tree-sitter backend couldn't accept the YAML grammar.
    #[error("malformed or unsupported tree-sitter grammar")]
    InvalidLanguage(#[from] tree_sitter::LanguageError),
    /// The user's input YAML is malformed.
    #[error("input is not valid YAML")]
    InvalidInput,
    /// The route expects a key at a given point, but the input isn't a mapping.
    #[error("expected mapping containing key `{0}`")]
    ExpectedMapping(String),
    /// The route expects a list index at a given point, but the input isn't a list.
    #[error("expected list for index `[{0}]`")]
    ExpectedList(usize),
    /// The route expects the given key in a mapping, but the mapping doesn't have that key.
    #[error("mapping has no key `{0}`")]
    ExhaustedMapping(String),
    /// The route expects the given list index, but the list isn't the right size.
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
    /// Any other route error that doesn't fit cleanly above.
    #[error("route error: {0}")]
    Other(String),
}

/// A route into some YAML document.
///
/// Internally, a route is zero or more "component" selectors, each of which
/// is either a mapping key or list index to descend through. An empty
/// route corresponds to the top-most document feature.
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
#[derive(Clone, Debug, Default, Serialize)]
pub struct Route<'a> {
    /// The individual top-down components of this route.
    route: Vec<Component<'a>>,
}

impl<'a> Route<'a> {
    /// Returns whether this route is empty.
    pub fn is_empty(&self) -> bool {
        self.route.is_empty()
    }

    /// Create a new route from this route, with the given component
    /// added to the end.
    pub fn with_key(&self, component: impl Into<Component<'a>>) -> Self {
        let mut components = self.route.clone();
        components.push(component.into());

        Self::from(components)
    }

    /// Create a new route from this route, with the given components
    /// added to the end.
    pub fn with_keys(&self, components: impl IntoIterator<Item = Component<'a>>) -> Self {
        let mut new_route = self.route.clone();
        new_route.extend(components);

        Self::from(new_route)
    }

    /// Returns a route for the "parent" path of the route's current path,
    /// or `None` the current route has no parent.
    pub fn parent(&self) -> Option<Self> {
        if self.is_empty() {
            None
        } else {
            let mut route = self.route.clone();
            route.truncate(self.route.len() - 1);
            Some(Self::from(route))
        }
    }
}

/// Convenience builder for constructing a `Route`.
#[macro_export]
macro_rules! route {
    ($($key:expr),* $(,)?) => {
        $crate::Route::from(
            vec![$($crate::Component::from($key)),*]
        )
    };
    () => {
        $crate::Route::default()
    };
}

impl<'a> From<Vec<Component<'a>>> for Route<'a> {
    fn from(route: Vec<Component<'a>>) -> Self {
        Self { route }
    }
}

/// A single `Route` component.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum Component<'a> {
    /// A YAML key.
    Key(Cow<'a, str>),

    /// An index into a YAML array.
    Index(usize),
}

impl From<usize> for Component<'_> {
    fn from(index: usize) -> Self {
        Component::Index(index)
    }
}

impl<'a> From<&'a str> for Component<'a> {
    fn from(key: &'a str) -> Self {
        Component::Key(key.into())
    }
}

impl From<String> for Component<'_> {
    fn from(key: String) -> Self {
        Component::Key(key.into())
    }
}

/// Represents the concrete location of some YAML syntax.
#[derive(Debug)]
pub struct Location {
    /// The byte span at which the route's result appears.
    pub byte_span: (usize, usize),
    /// The "point" (i.e., line/column) span at which the route's result appears.
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

/// Represents the result of a successful route.
#[derive(Debug)]
pub struct Feature<'tree> {
    /// The tree-sitter node that this feature was extracted from.
    _node: Node<'tree>,

    /// The exact location of the route result.
    pub location: Location,

    /// The "context" location for the route result.
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
        // Our feature's underlying node is often a
        // `block_node` or `flow_node`, which is a container
        // for the real kind of node we're interested in.
        let node = if self._node.is_block_or_flow_node() {
            self._node
                .child(0)
                .expect("internal error: expected child of block_node/flow_node")
        } else {
            self._node
        };

        match () {
            _ if node.is_block_mapping() => FeatureKind::BlockMapping,
            _ if node.is_block_sequence() => FeatureKind::BlockSequence,
            _ if node.is_flow_mapping() => FeatureKind::FlowMapping,
            _ if node.is_flow_sequence() => FeatureKind::FlowSequence,
            _ if node.is_scalar() => FeatureKind::Scalar,
            _ => unreachable!("unexpected feature kind: {}", node.kind()),
        }
    }

    /// Returns whether this feature spans multiple lines.
    pub fn is_multiline(&self) -> bool {
        self.location.point_span.0.0 != self.location.point_span.1.0
    }
}

impl RangeBounds<usize> for &Feature<'_> {
    fn start_bound(&self) -> std::ops::Bound<&usize> {
        std::ops::Bound::Included(&self.location.byte_span.0)
    }

    fn end_bound(&self) -> std::ops::Bound<&usize> {
        std::ops::Bound::Excluded(&self.location.byte_span.1)
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
    /// For routes that terminate in a key, make the extracted
    /// feature only that key, rather than both the key and value ("pretty"),
    /// or just the value ("exact").
    ///
    /// For example, querying `foo: bar` for `foo` will return `foo`.
    KeyOnly,
    /// Make extracted features as "exact" as possible, e.g. by
    /// including only the exact span of the route result.
    Exact,
}

/// A holder type so that we can associate both source and node references
/// with the same lifetime for [`self_cell`].
#[derive(Clone)]
struct SourceTree {
    source: String,
    tree: tree_sitter::Tree,
}

impl Deref for SourceTree {
    type Target = tree_sitter::Tree;

    fn deref(&self) -> &Self::Target {
        &self.tree
    }
}

type AnchorMap<'tree> = HashMap<&'tree str, BTreeMap<usize, Node<'tree>>>;

self_cell::self_cell!(
    /// A wrapper for a [`SourceTree`] that also contains a computed
    /// anchor map.
    struct Tree {
        owner: SourceTree,

        #[covariant]
        dependent: AnchorMap,
    }
);

impl Tree {
    fn build(inner: SourceTree) -> Result<Self, QueryError> {
        Tree::try_new(SourceTree::clone(&inner), |tree| {
            let mut anchor_map: AnchorMap = HashMap::new();

            for anchor in TreeIter::new(tree).filter(|n| n.is_anchor()) {
                // NOTE(ww): We could poke into the `anchor_name` child
                // instead of slicing, but this is simpler.
                let anchor_name = &anchor
                    .utf8_text(tree.source.as_bytes())
                    .expect("impossible: anchor name should be UTF-8 by construction")[1..];

                // NOTE(ww): We insert the anchor's next non-comment
                // sibling as the anchor's target. This makes things
                // a bit simpler when descending later, plus it produces
                // more useful spans, since neither the anchor node
                // nor its parent are useful in the aliased context.
                let parent = anchor.parent().ok_or_else(|| {
                    QueryError::UnexpectedNode("anchor node has no parent".into())
                })?;

                let mut cursor = parent.walk();
                let sibling = parent
                    .named_children(&mut cursor)
                    .find(|child| !child.is_anchor() && !child.is_comment())
                    .ok_or_else(|| {
                        QueryError::UnexpectedNode("anchor has no non-comment sibling".into())
                    })?;

                // Store anchor with its position; duplicates are allowed and
                // resolved by position when aliases are encountered.
                anchor_map
                    .entry(anchor_name)
                    .or_default()
                    .insert(anchor.start_byte(), sibling);
            }

            Ok(anchor_map)
        })
    }
}

impl Clone for Tree {
    fn clone(&self) -> Self {
        // Cloning is mildly annoying: we can clone the tree itself,
        // but we need to reconstruct the anchor map from scratch since
        // it borrows from the tree.
        // TODO: Can we do better here?
        // Unwrap safety: we're cloning from an existing valid owner.
        Self::build(self.borrow_owner().clone())
            .expect("impossible: cloning a Tree preserves invariants")
    }
}

impl Deref for Tree {
    type Target = tree_sitter::Tree;

    fn deref(&self) -> &Self::Target {
        &self.borrow_owner().tree
    }
}

/// Represents a queryable YAML document.
#[derive(Clone)]
pub struct Document {
    tree: Tree,
    line_index: LineIndex,
}

impl Document {
    /// Construct a new `Document` from the given YAML.
    pub fn new(source: impl Into<String>) -> Result<Self, QueryError> {
        let source = source.into();

        let mut parser = Parser::new();
        let language: Language = tree_sitter_yaml::LANGUAGE.into();
        parser.set_language(&language)?;

        // NOTE: Infallible, assuming `language` is correctly constructed above.
        let tree = parser
            .parse(&source, None)
            .expect("impossible: tree-sitter parsing should never fail");

        if tree.root_node().has_error() {
            return Err(QueryError::InvalidInput);
        }

        let line_index = LineIndex::new(&source);

        let source_tree = SourceTree {
            source: source,
            tree,
        };

        Ok(Self {
            tree: Tree::build(source_tree)?,
            line_index,
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
        &self.tree.borrow_owner().source
    }

    /// Resolve an anchor by name, returning the target node that was active
    /// at the given position. For duplicate anchors, this returns the most
    /// recent definition that appears before `position`.
    fn resolve_anchor(&self, name: &str, position: usize) -> Option<Node<'_>> {
        self.tree
            .borrow_dependent()
            .get(name)?
            .range(..position)
            .next_back()
            .map(|(_, node)| *node)
    }

    /// Returns a [`Feature`] for the topmost semantic object in this document.
    ///
    /// This is typically useful as a "fallback" feature, e.g. for positioning
    /// relative to the "top" of the document.
    pub fn top_feature(&self) -> Result<Feature<'_>, QueryError> {
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
            Some(child) => child.is_comment(),
            None => false,
        }
    }

    /// Returns whether the given offset is within a comment node's span.
    pub fn offset_inside_comment(&self, offset: usize) -> bool {
        self.range_spanned_by_comment(offset, offset)
    }

    /// Perform a route on the current document, returning `true`
    /// if the route succeeds (i.e. references an existing feature).
    ///
    /// All errors become `false`.
    pub fn query_exists(&self, route: &Route) -> bool {
        self.query_node(route, QueryMode::Exact).is_ok()
    }

    /// Perform a route on the current document, returning a `Feature`
    /// if the route succeeds.
    ///
    /// The feature is extracted in "pretty" mode, meaning that it'll
    /// contain a subjectively relevant "pretty" span rather than the
    /// exact span of the route result.
    ///
    /// For example, querying `foo: bar` for `foo` will return
    /// `foo: bar` instead of just `bar`.
    pub fn query_pretty(&self, route: &Route) -> Result<Feature<'_>, QueryError> {
        self.query_node(route, QueryMode::Pretty).map(|n| n.into())
    }

    /// Perform a route on the current document, returning a `Feature`
    /// if the route succeeds. Returns `None` if the route
    /// succeeds, but matches an absent value (e.g. `foo:`).
    ///
    /// The feature is extracted in "exact" mode, meaning that it'll
    /// contain the exact span of the route result.
    ///
    /// For example, querying `foo: bar` for `foo` will return
    /// just `bar` instead of `foo: bar`.
    pub fn query_exact(&self, route: &Route) -> Result<Option<Feature<'_>>, QueryError> {
        let node = self.query_node(route, QueryMode::Exact)?;

        if node.is_pair() {
            // If the route matches a mapping pair, we return None,
            // since this indicates an absent value.
            Ok(None)
        } else {
            // Otherwise, we return the node as a feature.
            Ok(Some(node.into()))
        }
    }

    /// Perform a route on the current document, returning a `Feature`
    /// if the route succeeds.
    ///
    /// The feature is extracted in "key only" mode, meaning that it'll
    /// contain only the key of a mapping, rather than the
    /// key and value ("pretty") or just the value ("exact").
    ///
    /// For example, querying `foo: bar` for `foo` will return
    /// just `foo` instead of `foo: bar` or `bar`.
    pub fn query_key_only(&self, route: &Route) -> Result<Feature<'_>, QueryError> {
        if !matches!(route.route.last(), Some(Component::Key(_))) {
            return Err(QueryError::Other(
                "route must end with a key component for key-only routes".into(),
            ));
        }

        self.query_node(route, QueryMode::KeyOnly).map(|n| n.into())
    }

    /// Computes the byte range that should be deleted from the document's
    /// [`Self::source`] in order to remove the value at `route`, together
    /// with the structural "affixes" appropriate to the value's container.
    ///
    /// This is aware of the value's container kind as determined by the
    /// parse tree.
    ///
    /// The affixes removed depend on the container:
    ///
    /// - In block mappings and sequences, the value's entire line (or
    ///   lines, for multi-line values) is removed, including leading
    ///   indentation, any trailing same-line comment, and the trailing
    ///   newline.
    /// - In flow mappings and sequences, the value is removed along with a
    ///   single adjacent comma (the following one if present, otherwise
    ///   the preceding one) and any whitespace separating it from its
    ///   neighbor, so the surrounding flow collection stays well-formed. A
    ///   sole remaining member collapses cleanly to `{}` or `[]`.
    ///
    /// The element is resolved at its own lexical site: a final alias is
    /// **not** followed, so removing `b` from `{a: &x 1, b: *x}` deletes
    /// `b: *x` rather than the anchor definition it points to.
    ///
    /// When removing the sole member of a *block* container would leave a
    /// dangling null parent (e.g. removing the only key under `env:` would
    /// leave `env:` with a null value), the enclosing element is removed
    /// instead, repeating upward. Flow containers are left as explicit
    /// `{}`/`[]`, which are valid, so they are not collapsed.
    ///
    /// The returned range is a half-open `[start, end)` byte range into
    /// [`Self::source`].
    pub fn removal_span(&self, route: &Route) -> Result<core::ops::Range<usize>, QueryError> {
        let Some(last) = route.route.last() else {
            return Err(QueryError::Other(
                "cannot compute a removal span for the empty (root) route".into(),
            ));
        };

        // Resolve the element to remove at its own lexical site. Crucially,
        // we do not follow a final alias: `query_node(.., Exact)` would
        // resolve a terminal `*alias` to the anchor definition elsewhere in
        // the document, so removing it would corrupt an unrelated location.
        let seed = match last {
            // For a key, the key node sits at the reference site, and its
            // enclosing pair is the element to remove. `KeyOnly` navigates
            // the reference site even when the value is an alias.
            Component::Key(_) => self.query_node(route, QueryMode::KeyOnly)?,
            // For an index, select the item node directly from the parent
            // sequence (via `flatten_sequence`, which keeps aliased items
            // as-is) so an aliased element isn't resolved away.
            Component::Index(idx) => {
                let parent_route = route
                    .parent()
                    .expect("non-empty route always has a parent route");
                let parent = self.query_node(&parent_route, QueryMode::Exact)?;

                let sequence = if parent.is_sequence() {
                    parent
                } else {
                    let mut cursor = parent.walk();
                    parent
                        .named_children(&mut cursor)
                        .find(|child| child.is_sequence())
                        .ok_or(QueryError::ExpectedList(*idx))?
                };

                let items = self.flatten_sequence(&sequence)?;
                *items
                    .get(*idx)
                    .ok_or(QueryError::ExhaustedList(*idx, items.len()))?
            }
        };

        let (mut element, mut container) = Self::walk_to_container(seed)?;

        // Collapse dangling block parents: if `element` is the only content
        // member of a *block* container, removing it would leave that
        // container empty, which serializes to a null-valued parent (e.g.
        // `env:` with nothing under it). In that case, remove the
        // container's enclosing element instead, repeating upward. Block
        // containers only ever nest inside other block containers, so this
        // never crosses into flow. Flow containers are left as explicit
        // `{}`/`[]`, which are valid, so they are not collapsed.
        while (container.is_block_mapping() || container.is_block_sequence())
            && Self::is_sole_content_child(&container, &element)
        {
            match Self::walk_to_container(container) {
                Ok((outer_element, outer_container)) => {
                    element = outer_element;
                    container = outer_container;
                }
                // Reached the top-level container, which has no enclosing
                // element to collapse into; remove the element as-is.
                Err(_) => break,
            }
        }

        // NOTE: `container` is always one of `block_mapping`,
        // `block_sequence`, `flow_mapping`, or `flow_sequence` by
        // construction in `walk_to_container`.
        let span = if container.is_block_mapping() || container.is_block_sequence() {
            self.block_removal_span(&element)
        } else {
            self.flow_removal_span(&element, &container)
        };

        Ok(span)
    }

    /// Returns whether `node` is a "content" member of a collection, i.e. a
    /// mapping pair, a block sequence item, or a flow node (a flow sequence
    /// element or a bare flow-mapping key). Punctuation, comments, and
    /// anchors are not content members.
    fn is_content_node(node: &Node) -> bool {
        node.is_pair() || node.is_block_sequence_item() || node.is_flow_node()
    }

    /// Returns whether `element` is the only content member of `container`,
    /// i.e. removing it would leave `container` empty. Comments, anchors,
    /// and punctuation do not count as content.
    fn is_sole_content_child(container: &Node, element: &Node) -> bool {
        let mut cursor = container.walk();
        !container
            .named_children(&mut cursor)
            .any(|child| child.id() != element.id() && Self::is_content_node(&child))
    }

    /// If `element` is the first key of a block mapping that is the inline
    /// value of a block sequence item (so it shares its line with the
    /// item's `- ` marker), return the next sibling key, which should slide
    /// onto the marker's line when `element` is removed. Returns `None` in
    /// every other case, where ordinary whole-line removal is correct.
    fn sequence_item_inline_next_sibling<'b>(element: &Node<'b>) -> Option<Node<'b>> {
        if !element.is_block_mapping_pair() {
            return None;
        }

        // The mapping pair must live directly inside a block mapping that is
        // itself the inline value of a block sequence item:
        //   block_sequence_item -> block_node -> block_mapping -> (element)
        let container = element.parent()?;
        if !container.is_block_mapping() {
            return None;
        }
        let block_node = container.parent()?;
        if !block_node.is_block_node() {
            return None;
        }
        let item = block_node.parent()?;
        if !item.is_block_sequence_item() {
            return None;
        }

        // Only the mapping's first key shares the item's `- ` line; for any
        // other key, whole-line removal does not touch the marker.
        let dash = item.child(0)?;
        if dash.start_position().row != element.start_position().row {
            return None;
        }

        // Return the content sibling that follows `element` (the key that
        // slides onto the marker's line). If there is none, `element` is the
        // mapping's sole key and the caller would have collapsed the whole
        // item instead, so fall back to ordinary removal.
        let mut cursor = container.walk();
        let mut content = container
            .named_children(&mut cursor)
            .filter(|child| Self::is_content_node(child));
        content.find(|child| child.id() == element.id())?;
        content.next()
    }

    /// Walk up from a resolved node to the element node that is a direct
    /// child of its enclosing mapping or sequence, returning the
    /// `(element, container)` pair.
    ///
    /// The container kind is derived from the parse tree, so this is
    /// robust against arbitrary nesting of flow and block collections.
    fn walk_to_container(seed: Node<'_>) -> Result<(Node<'_>, Node<'_>), QueryError> {
        let mut element = seed;
        loop {
            let parent = element.parent().ok_or_else(|| {
                QueryError::Other("value to remove has no enclosing container".into())
            })?;

            if parent.is_mapping() || parent.is_sequence() {
                return Ok((element, parent));
            }

            element = parent;
        }
    }

    /// Compute the removal span for an `element` in a block container.
    ///
    /// Normally this removes the element's entire line(s), including leading
    /// indentation, any trailing same-line comment, and the trailing
    /// newline. There is one special case: when `element` is the first key
    /// of a block mapping that is the inline value of a block sequence item,
    /// it shares its line with the item's `- ` marker. Naive whole-line
    /// removal would delete that marker and silently turn the sequence into
    /// a mapping, so instead we remove up to the next sibling key's start,
    /// which preserves the `- ` marker and slides that key onto its line.
    fn block_removal_span(&self, element: &Node) -> core::ops::Range<usize> {
        if let Some(next) = Self::sequence_item_inline_next_sibling(element) {
            return element.start_byte()..next.start_byte();
        }

        let start_byte = element.start_byte();
        let end_byte = element.end_byte();

        let start_line = self
            .line_index
            .line_col(TextSize::new(start_byte as u32))
            .line;
        // `end_byte` is exclusive, so the last byte that actually belongs
        // to the element is `end_byte - 1`. Empty elements can't occur
        // here, but guard against underflow regardless.
        let last_byte = end_byte.saturating_sub(1).max(start_byte);
        let end_line = self
            .line_index
            .line_col(TextSize::new(last_byte as u32))
            .line;

        let start = self
            .line_index
            .line(start_line)
            .map(|range| usize::from(range.start()))
            .unwrap_or(start_byte);
        let end = self
            .line_index
            .line(end_line)
            .map(|range| usize::from(range.end()))
            .unwrap_or(end_byte);

        start..end
    }

    /// Compute the removal span for an `element` in a flow container,
    /// removing the element plus a single adjacent comma separator (and
    /// the whitespace up to the next neighbor) so the collection remains
    /// well-formed.
    fn flow_removal_span(&self, element: &Node, container: &Node) -> core::ops::Range<usize> {
        let source = self.source().as_bytes();

        // Collect the container's children, including the anonymous comma
        // and bracket tokens, so we can locate the separators adjacent to
        // the element.
        let mut cursor = container.walk();
        let children: Vec<Node> = container.children(&mut cursor).collect();

        // The element is always a direct child of its container here, so
        // this lookup is infallible in practice.
        let pos = children
            .iter()
            .position(|child| child.id() == element.id())
            .unwrap_or(0);

        let following_comma = children[pos + 1..].iter().find(|child| child.kind() == ",");
        let preceding_comma = children[..pos]
            .iter()
            .rev()
            .find(|child| child.kind() == ",");

        if let Some(comma) = following_comma {
            // Not the last element: remove the element, the following
            // comma, and any whitespace up to the next neighbor (which may
            // include a newline and indentation for multi-line flows).
            let start = element.start_byte();
            let mut end = comma.end_byte();
            while end < source.len() && matches!(source[end], b' ' | b'\t' | b'\r' | b'\n') {
                end += 1;
            }
            start..end
        } else if let Some(comma) = preceding_comma {
            // Last element: remove the preceding comma through the element.
            comma.start_byte()..element.end_byte()
        } else {
            // Only element in the container: drop everything between the
            // delimiters so the collection collapses cleanly to `{}`/`[]`,
            // including any interior whitespace around the element. The
            // first and last children of a flow collection are always its
            // opening and closing delimiter tokens.
            match (children.first(), children.last()) {
                (Some(open), Some(close)) if open.end_byte() <= close.start_byte() => {
                    open.end_byte()..close.start_byte()
                }
                _ => element.start_byte()..element.end_byte(),
            }
        }
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
        &self.source()[feature.location.byte_span.0..feature.location.byte_span.1]
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
        let pre_slice = &self.source()[0..start_idx];
        if let Some(last_newline) = pre_slice.rfind('\n') {
            // If everything between the last newline and the start_index
            // is ASCII spaces, then we include it.
            if self.source()[last_newline + 1..start_idx]
                .bytes()
                .all(|b| b == b' ')
            {
                start_idx = last_newline + 1
            }
        }

        &self.source()[start_idx..feature.location.byte_span.1]
    }

    /// Given a [`Feature`], return all comments that span the same range
    /// as the feature does.
    pub fn feature_comments<'tree>(&'tree self, feature: &Feature<'tree>) -> Vec<Feature<'tree>> {
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
            start_line: usize,
            end_line: usize,
        ) -> Vec<Feature<'tree>> {
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
                        c.is_comment()
                            && c.start_position().row >= start_line
                            && c.end_position().row <= end_line
                    })
                    .map(|c| c.into()),
            );

            for child in node.children(&mut cur) {
                comments.extend(trawl(&child, start_line, end_line));
            }

            comments
        }

        trawl(&self.tree.root_node(), start_line, end_line)
    }

    /// Returns whether this document contains any YAML anchors.
    pub fn has_anchors(&self) -> bool {
        !self.tree.borrow_dependent().is_empty()
    }

    /// Returns the topmost semantic object in the YAML document,
    /// i.e. the node corresponding to the first block or flow feature.
    fn top_object(&self) -> Result<Node<'_>, QueryError> {
        // All tree-sitter-yaml trees start with a `stream` node.
        let stream = self.tree.root_node();

        // The `document` child is the "body" of the YAML document; it
        // might not be the first node in the `stream` if there are comments.
        let mut cur = stream.walk();
        let document = stream
            .named_children(&mut cur)
            .find(|c| c.is_document())
            .ok_or_else(|| QueryError::MissingChild(stream.kind().into(), "document".into()))?;

        // The document might have a directives section, which we need to
        // skip over. We do this by finding the top-level `block_node`
        // or `flow_node`, of which one will be present depending on how
        // the top-level document value is expressed.
        let top_node = document
            .named_children(&mut cur)
            .find(|c| c.is_block_or_flow_node())
            .ok_or_else(|| QueryError::Other("document has no block_node or flow_node".into()))?;

        Ok(top_node)
    }

    fn query_node(&self, route: &Route, mode: QueryMode) -> Result<Node<'_>, QueryError> {
        let mut focus_node = self.top_object()?;
        for component in &route.route {
            {
                let next = self.descend(&focus_node, component)?;
                focus_node = next
            }
        }

        // Our focus node might be an alias, in which case we need to
        // do one last leap to get our "real" final focus node.
        //
        // We save the pre-resolution node so that KeyOnly and Pretty modes
        // can navigate the alias reference's tree structure rather than the
        // anchor definition's tree structure.
        let pre_resolution_node = focus_node;
        focus_node = match focus_node.child(0) {
            Some(child) if child.is_alias() => {
                let alias_name = child
                    .utf8_text(self.source().as_bytes())
                    .expect("impossible: alias name should be UTF-8 by construction");
                self.resolve_anchor(&alias_name[1..], child.start_byte())
                    .ok_or_else(|| QueryError::Other(format!("unknown alias: {}", alias_name)))?
            }
            // Our focus node might have an anchor prefix (e.g. `[&x v, *x]`),
            // in which case we skip to the non-anchor sibling.
            Some(child) if child.is_anchor() => {
                let mut cursor = focus_node.walk();
                focus_node
                    .named_children(&mut cursor)
                    .find(|n| !n.is_anchor())
                    .unwrap_or(focus_node)
            }
            _ => focus_node,
        };
        let was_alias = pre_resolution_node.id() != focus_node.id();

        // For Pretty and KeyOnly modes, we need the structural position
        // in the tree. When an alias was resolved, use the pre-resolution
        // node so we navigate the alias reference site, not the anchor
        // definition site.
        let structural_node = if was_alias {
            pre_resolution_node
        } else {
            focus_node
        };

        focus_node = match mode {
            QueryMode::Pretty => {
                // If we're in "pretty" mode, we want to return the
                // block/flow pair node that contains the key.
                // This results in a (subjectively) more intuitive extracted feature,
                // since `foo: bar` gets extracted for `foo` instead of just `bar`.
                //
                // NOTE: We might already be on the block/flow pair if we terminated
                // with an absent value, in which case we don't need to do this cleanup.
                if matches!(route.route.last(), Some(Component::Key(_)))
                    && !structural_node.is_pair()
                {
                    structural_node
                        .parent()
                        .expect("missing parent of focus node")
                } else {
                    structural_node
                }
            }
            QueryMode::KeyOnly => {
                // If we're in "key only" mode, we need to walk back up to
                // the parent block/flow pair node that contains the key,
                // and isolate on the key child instead.

                let parent_node = if structural_node.is_pair() {
                    // If we're already on block/flow pair, then we're already
                    // the key's parent.
                    structural_node
                } else if structural_node.is_block_scalar() {
                    // We might be on the internal `block_scalar` node, if
                    // we got here via an alias. We need to go up two levels
                    // to get to the mapping pair.
                    structural_node
                        .parent()
                        .expect("missing parent of focus node")
                        .parent()
                        .expect("missing grandparent of focus node")
                } else {
                    // Otherwise, we expect to be on the `block_node`
                    // or `flow_node`, so we go up one level.
                    structural_node
                        .parent()
                        .expect("missing parent of focus node")
                };

                if parent_node.is_flow_mapping() {
                    // Handle the annoying `foo: { key }` case, where our "parent"
                    // is actually a `flow_mapping` instead of a proper block/flow pair.
                    // To handle this, we get the first `flow_node` child of the
                    // flow_mapping, which is the "key".
                    let mut cur = parent_node.walk();
                    parent_node
                        .named_children(&mut cur)
                        .find(|n| n.is_flow_node())
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
            && matches!(route.route.last(), Some(Component::Key(_)))
            && !focus_node.is_block_mapping_pair()
        {
            focus_node = focus_node.parent().expect("missing parent of focus node")
        }

        Ok(focus_node)
    }

    fn descend<'b>(
        &'b self,
        node: &Node<'b>,
        component: &Component,
    ) -> Result<Node<'b>, QueryError> {
        // The cursor is assumed to start on a block_node or flow_node,
        // which has a child containing the inner scalar/vector/alias
        // type we're descending through.
        //
        // To get to that child, we might have to skip over any
        // anchor nodes that we're not actually aliasing through
        // in this descent step.
        //
        // For example, for a YAML snippet like:
        //
        // ```yaml
        // foo: &foo
        //   bar: baz
        // ```
        //
        // ...the relevant part of the CST looks roughly like:
        //
        // ```
        // block_node         <- `node` points here
        // |--- anchor        <- we need to skip this
        // |--- block_mapping <- we want `child` to point here
        // ```
        let mut child = {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|n| !n.is_anchor())
                .ok_or_else(|| {
                    QueryError::Other(format!(
                        "node of kind {} has no non-anchor child",
                        node.kind()
                    ))
                })?
        };

        // We might be on an alias node, in which case we need to
        // jump to the alias's target via the anchor map.
        if child.is_alias() {
            let alias_name = node
                .utf8_text(self.source().as_bytes())
                .expect("impossible: alias name should be UTF-8 by construction");

            child = self
                .resolve_anchor(&alias_name[1..], node.start_byte())
                .ok_or_else(|| QueryError::Other(format!("unknown alias: {}", alias_name)))?;
        }

        // We expect the child to be a sequence or mapping of either
        // flow or block type.
        if child.is_mapping() {
            match component {
                Component::Key(key) => self.descend_mapping(&child, key),
                Component::Index(idx) => Err(QueryError::ExpectedList(*idx)),
            }
        } else if child.is_sequence() {
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
            let key = if child.is_pair() {
                // If we're on a `flow_pair` or `block_mapping_pair`, we
                // need to get the `key` child.
                child
                    .child_by_field_name("key")
                    .ok_or_else(|| QueryError::MissingChildField(child.kind().into(), "key"))?
            } else if child.is_flow_node() {
                // NOTE: Annoying edge case: if we have a flow mapping
                // like `{ foo }`, then `foo` is a `flow_node` instead
                // of a `flow_pair`.
                child
            } else {
                continue;
            };

            // NOTE: To get the key's actual value, we need to get down to its
            // inner scalar. This is slightly annoying, since keys can be
            // quoted strings with no interior unquoted child. In those cases,
            // we need to manually unquote them.
            //
            // NOTE: text unwraps are infallible, since our document is UTF-8.
            // NOTE: The key might have an anchor prefix (e.g. `{ &v foo: bar }`),
            // so we need to skip any anchor nodes to find the actual scalar.
            let key_value = {
                let mut cursor = key.walk();
                let scalar = key.named_children(&mut cursor).find(|n| !n.is_anchor());

                match scalar {
                    Some(scalar) => {
                        let key_value = scalar
                            .utf8_text(self.source().as_bytes())
                            .expect("impossible: value for key should be UTF-8 by construction");

                        if scalar.is_quoted_scalar() {
                            let mut chars = key_value.chars();
                            chars.next();
                            chars.next_back();
                            chars.as_str()
                        } else {
                            key_value
                        }
                    }
                    None => key
                        .utf8_text(self.source().as_bytes())
                        .expect("impossible: key should be UTF-8 by construction"),
                }
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

    /// Given a `block_sequence` or `flow_sequence` node, return
    /// a full list of child nodes after expanding any aliases present.
    ///
    /// The returned child nodes are the inner
    /// `block_node`/`flow_node`/`flow_pair` nodes for each sequence item.
    fn flatten_sequence<'b>(&'b self, node: &Node<'b>) -> Result<Vec<Node<'b>>, QueryError> {
        let mut children = vec![];

        let mut cur = node.walk();
        for child in node.named_children(&mut cur).filter(|child| {
            child.is_block_sequence_item() || child.is_flow_node() || child.is_flow_pair()
        }) {
            let mut child = child;

            // If we have a `block_sequence_item`, we need to get its
            // inner `block_node`/`flow_node`, which might be interceded
            // by comments.
            if child.is_block_sequence_item() {
                let mut cur = child.walk();
                child = child
                    .named_children(&mut cur)
                    .find(|c| c.is_block_or_flow_node())
                    .ok_or_else(|| {
                        QueryError::MissingChild(child.kind().into(), "block_sequence_item".into())
                    })?;
            }

            // `child` is now a `block_node`, a `flow_node`, or `flow_pair`:
            //
            // `block_node` looks like `- a: b`
            // `flow_node` looks like `- a`
            // `flow_pair` looks like `[a: b]`
            //
            // Aliases are drop-in replacements for their anchored values,
            // so we just keep the child as-is. The alias will be resolved
            // during descent when we navigate into it.
            children.push(child);
        }

        Ok(children)
    }

    fn descend_sequence<'b>(&'b self, node: &Node<'b>, idx: usize) -> Result<Node<'b>, QueryError> {
        let children = self.flatten_sequence(node)?;
        let Some(child) = children.get(idx) else {
            return Err(QueryError::ExhaustedList(idx, children.len()));
        };

        if child.is_flow_pair() {
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

    use crate::{Component, Document, FeatureKind, QueryError, Route};

    #[test]
    fn test_document_preserves_leading_trailing_whitespace() {
        let source = "\n\n   foo: bar   \n   baz: quux   \n\n";
        let doc = Document::new(source).unwrap();
        assert_eq!(doc.source(), source);
    }

    #[test]
    fn test_query_parent() {
        let route = route!("foo", "bar", "baz");
        assert_eq!(
            route.parent().unwrap().route,
            [Component::Key("foo".into()), Component::Key("bar".into())]
        );

        let route = route!("foo");
        assert!(route.parent().is_some());

        let route = Route::from(vec![]);
        assert!(route.parent().is_none());
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
        let route = route!("foo", "bar", 1, 123, "lol");

        assert_eq!(
            route.route,
            [
                Component::Key("foo".into()),
                Component::Key("bar".into()),
                Component::Index(1),
                Component::Index(123),
                Component::Key("lol".into()),
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
        let route = Route {
            route: vec![
                Component::Key("baz".into()),
                Component::Key("sub".into()),
                Component::Key("keys".into()),
                Component::Key("abc".into()),
                Component::Index(2),
                Component::Index(3),
            ],
        };

        assert_eq!(
            doc.extract_with_leading_whitespace(&doc.query_pretty(&route).unwrap()),
            "{d: e}"
        );
    }

    #[test]
    fn test_top_feature() {
        let doc = r#"
foo: bar
baz:
  abc: def
"#;

        let doc = Document::new(doc).unwrap();
        let feature = doc.top_feature().unwrap();

        assert_eq!(doc.extract(&feature).trim(), doc.source().trim());
        assert_eq!(feature.kind(), FeatureKind::BlockMapping);
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
        let route = Route {
            route: vec![Component::Key("root".into())],
        };
        let feature = doc.query_pretty(&route).unwrap();
        assert_eq!(
            doc.feature_comments(&feature)
                .iter()
                .map(|f| doc.extract(f))
                .collect::<Vec<_>>(),
            &["# rootlevel", "# foo", "# bar", "# baz", "# quux"]
        );

        // Querying a nested key gives us its adjacent comment,
        // even though it's above it on the AST.
        let route = Route {
            route: vec![
                Component::Key("root".into()),
                Component::Key("e".into()),
                Component::Index(1),
            ],
        };
        let feature = doc.query_pretty(&route).unwrap();
        assert_eq!(
            doc.feature_comments(&feature)
                .iter()
                .map(|f| doc.extract(f))
                .collect::<Vec<_>>(),
            &["# quux"]
        );
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

        for (route, expected_kind) in &[
            (
                vec![Component::Key("block-mapping".into())],
                FeatureKind::BlockMapping,
            ),
            (
                vec![Component::Key("block-mapping-quoted".into())],
                FeatureKind::BlockMapping,
            ),
            (
                vec![Component::Key("block-sequence".into())],
                FeatureKind::BlockSequence,
            ),
            (
                vec![Component::Key("block-sequence-quoted".into())],
                FeatureKind::BlockSequence,
            ),
            (
                vec![Component::Key("flow-mapping".into())],
                FeatureKind::FlowMapping,
            ),
            (
                vec![Component::Key("flow-sequence".into())],
                FeatureKind::FlowSequence,
            ),
            (
                vec![Component::Key("scalars".into()), Component::Index(0)],
                FeatureKind::Scalar,
            ),
            (
                vec![Component::Key("scalars".into()), Component::Index(1)],
                FeatureKind::Scalar,
            ),
            (
                vec![Component::Key("scalars".into()), Component::Index(2)],
                FeatureKind::Scalar,
            ),
            (
                vec![Component::Key("scalars".into()), Component::Index(3)],
                FeatureKind::Scalar,
            ),
            (
                vec![Component::Key("scalars".into()), Component::Index(4)],
                FeatureKind::Scalar,
            ),
            (
                vec![Component::Key("scalars".into()), Component::Index(5)],
                FeatureKind::Scalar,
            ),
            (
                vec![Component::Key("scalars".into()), Component::Index(6)],
                FeatureKind::Scalar,
            ),
            (
                vec![Component::Key("scalars".into()), Component::Index(7)],
                FeatureKind::Scalar,
            ),
            (
                vec![Component::Key("scalars".into()), Component::Index(8)],
                FeatureKind::Scalar,
            ),
            (
                vec![Component::Key("scalars".into()), Component::Index(9)],
                FeatureKind::Scalar,
            ),
            (
                vec![Component::Key("scalars".into()), Component::Index(10)],
                FeatureKind::Scalar,
            ),
            (
                vec![
                    Component::Key("nested".into()),
                    Component::Key("foo".into()),
                    Component::Index(2),
                ],
                FeatureKind::FlowMapping,
            ),
            (
                vec![
                    Component::Key("nested".into()),
                    Component::Key("foo".into()),
                    Component::Index(3),
                ],
                FeatureKind::FlowMapping,
            ),
        ] {
            let route = Route::from(route.clone());
            let feature = doc.query_exact(&route).unwrap().unwrap();
            assert_eq!(feature.kind(), *expected_kind);
        }
    }

    #[test]
    fn test_duplicate_anchors() {
        let test_cases: Vec<(&str, Vec<(Route, &str)>)> = vec![
            // Same anchor name defined twice, alias resolves based on document position
            (
                "first: &x value1\nsecond: &x value2\nref: *x",
                vec![(route!("ref"), "value2")],
            ),
            // Alias before redefinition sees old value, alias after sees new value
            (
                "a1: &x old_x\nref_x: *x\na2: &x new_x\nref_x2: *x",
                vec![(route!("ref_x"), "old_x"), (route!("ref_x2"), "new_x")],
            ),
            // Inline flow sequence with duplicate anchor
            (
                "foo: [&x x, *x, &x y, *x]",
                vec![
                    (route!("foo", 0), "x"),
                    (route!("foo", 1), "x"),
                    (route!("foo", 2), "y"),
                    (route!("foo", 3), "y"),
                ],
            ),
        ];

        for (yaml, queries) in test_cases {
            let doc = Document::new(yaml).unwrap();
            for (route, expected) in queries {
                let feature = doc.query_exact(&route).unwrap().unwrap();
                assert_eq!(doc.extract(&feature), expected, "YAML: {}", yaml);
            }
        }
    }

    #[test]
    fn test_anchor_map() {
        let anchors = r#"
foo: &foo-anchor
  bar: &bar-anchor
    baz: quux
        "#;

        let doc = Document::new(anchors).unwrap();
        let anchor_map = doc.tree.borrow_dependent();

        assert_eq!(anchor_map.len(), 2);
        // Each anchor name maps to a BTreeMap of positions -> nodes
        assert_eq!(anchor_map["foo-anchor"].len(), 1);
        assert_eq!(anchor_map["bar-anchor"].len(), 1);
        assert_eq!(
            anchor_map["foo-anchor"].values().next().unwrap().kind(),
            "block_mapping"
        );
        assert_eq!(
            anchor_map["bar-anchor"].values().next().unwrap().kind(),
            "block_mapping"
        );
    }

    #[test]
    fn test_sequence_alias_not_flattened() {
        // Backstop test for #1551
        let doc = r#"
defaults: &defaults
  - a
  - b
  - c
list:
  - *defaults
  - d
  - e
        "#;

        let doc = Document::new(doc).unwrap();

        for (route, expected_kind, expected_value) in [
            (
                route!("list", 0),
                FeatureKind::BlockSequence,
                "- a\n  - b\n  - c",
            ),
            (route!("list", 1), FeatureKind::Scalar, "d"),
            (route!("list", 2), FeatureKind::Scalar, "e"),
        ] {
            let feature = doc.query_exact(&route).unwrap().unwrap();
            assert_eq!(feature.kind(), expected_kind);
            assert_eq!(doc.extract(&feature).trim(), expected_value);
        }

        assert!(matches!(
            doc.query_exact(&route!("list", 3)),
            Err(QueryError::ExhaustedList(3, 3))
        ));
    }

    #[test]
    fn test_inline_anchor_alias_patterns() {
        let test_cases: Vec<(&str, Vec<(Route, &str)>)> = vec![
            // Basic flow sequence cases
            (
                "foo: [&x v, *x]",
                vec![(route!("foo", 0), "v"), (route!("foo", 1), "v")],
            ),
            (
                "foo: [a, &x v, *x]",
                vec![
                    (route!("foo", 0), "a"),
                    (route!("foo", 1), "v"),
                    (route!("foo", 2), "v"),
                ],
            ),
            (
                "foo: [&a 1, &b 2, *a, *b]",
                vec![
                    (route!("foo", 0), "1"),
                    (route!("foo", 1), "2"),
                    (route!("foo", 2), "1"),
                    (route!("foo", 3), "2"),
                ],
            ),
            // Flow mapping cases
            (
                "top: { &a foo: &b bar, nested: *a, other: *b }",
                vec![
                    (route!("top", "foo"), "bar"),
                    (route!("top", "nested"), "foo"),
                    (route!("top", "other"), "bar"),
                ],
            ),
            (
                "top: { &a k1: v1, &b k2: v2, ref1: *a, ref2: *b }",
                vec![
                    (route!("top", "k1"), "v1"),
                    (route!("top", "k2"), "v2"),
                    (route!("top", "ref1"), "k1"),
                    (route!("top", "ref2"), "k2"),
                ],
            ),
            // Anchor on complex values
            (
                "top: { seq: &x [a, b], ref: *x }",
                vec![
                    (route!("top", "seq", 0), "a"),
                    (route!("top", "ref", 1), "b"),
                ],
            ),
            (
                "top: { map: &x {a: 1}, ref: *x }",
                vec![
                    (route!("top", "map", "a"), "1"),
                    (route!("top", "ref", "a"), "1"),
                ],
            ),
            // Quoted keys with anchors (alias returns the quoted form)
            (
                r#"top: { &x "foo": bar, nested: *x }"#,
                vec![
                    (route!("top", "foo"), "bar"),
                    (route!("top", "nested"), "\"foo\""),
                ],
            ),
            (
                "top: { &x 'foo': bar, nested: *x }",
                vec![
                    (route!("top", "foo"), "bar"),
                    (route!("top", "nested"), "'foo'"),
                ],
            ),
        ];

        for (yaml, queries) in test_cases {
            let doc = Document::new(yaml).unwrap();
            for (route, expected) in queries {
                let feature = doc.query_exact(&route).unwrap().unwrap();
                assert_eq!(doc.extract(&feature), expected, "YAML: {}", yaml);
            }
        }
    }
}
