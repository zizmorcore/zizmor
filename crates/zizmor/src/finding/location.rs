//! Symbolic and concrete locations.

use std::{ops::Range, sync::LazyLock};

use crate::{audit::AuditInput, models::AsDocument, registry::InputKey};
use github_actions_expressions::SpannedExpr;
use line_index::{LineCol, TextSize};
use regex::Regex;
use serde::Serialize;
use terminal_link::Link;

/// Represents a location's type.
#[derive(Serialize, Copy, Clone, Debug, Default)]
pub(crate) enum LocationKind {
    /// A location that is subjectively "primary" to a finding.
    ///
    /// This is used to distinguish between "primary" and "related" locations
    /// in output formats like SARIF.
    Primary,

    /// A location that is "related" to a finding.
    ///
    /// This is the default location type.
    #[default]
    Related,

    /// A hidden location.
    ///
    /// These locations are not rendered in output formats like SARIF or
    /// the cargo-style output. Instead, they're used to provide spanning
    /// information for checking things like ignore comments.
    Hidden,
}

#[derive(Serialize, Clone, Debug)]
pub(crate) enum RouteComponent<'doc> {
    Key(&'doc str),
    Index(usize),
}

impl From<usize> for RouteComponent<'_> {
    fn from(value: usize) -> Self {
        Self::Index(value)
    }
}

impl<'doc> From<&'doc str> for RouteComponent<'doc> {
    fn from(value: &'doc str) -> Self {
        Self::Key(value)
    }
}

#[derive(Serialize, Clone, Debug)]
pub(crate) struct Route<'doc> {
    components: Vec<RouteComponent<'doc>>,
}

impl<'doc> Route<'doc> {
    pub(crate) fn new() -> Route<'doc> {
        Self {
            components: Default::default(),
        }
    }

    pub(crate) fn with_keys(&self, keys: &[RouteComponent<'doc>]) -> Route<'doc> {
        let mut components = self.components.clone();
        components.extend(keys.iter().cloned());
        Route { components }
    }

    pub(crate) fn is_root(&self) -> bool {
        self.components.is_empty()
    }

    pub(crate) fn to_query(&self) -> Option<yamlpath::Query<'doc>> {
        if self.is_root() {
            return None;
        }

        let mut builder = yamlpath::QueryBuilder::new();

        for component in &self.components {
            builder = match component {
                RouteComponent::Key(key) => builder.key(key),
                RouteComponent::Index(idx) => builder.index(*idx),
            }
        }

        Some(builder.build())
    }
}

impl<'doc> From<Vec<RouteComponent<'doc>>> for Route<'doc> {
    fn from(components: Vec<RouteComponent<'doc>>) -> Self {
        Self { components }
    }
}

#[macro_export]
macro_rules! route {
    ($($key:expr),* $(,)?) => {
        $crate::finding::location::Route::from(
            vec![$($crate::finding::location::RouteComponent::from($key)),*]
        )
    };
    () => {
        $crate::finding::location::Route::new()
    };
}

/// Represents a "subfeature" of a symbolic location, such as a substring
/// within a YAML string.
#[derive(Serialize, Clone, Debug)]
pub(crate) struct Subfeature<'doc> {
    pub(crate) after: usize,
    pub(crate) fragment: &'doc str,
}

impl<'doc> Subfeature<'doc> {
    pub(crate) fn from_spanned_expr(expr: &SpannedExpr<'doc>, bias: usize) -> Subfeature<'doc> {
        Self {
            after: expr.span.start + bias,
            fragment: expr.raw,
        }
    }
}

/// Represents a symbolic location.
#[derive(Serialize, Clone, Debug)]
pub(crate) struct SymbolicLocation<'doc> {
    /// The unique ID of the input, as it appears in the input registry.
    pub(crate) key: &'doc InputKey,

    /// An annotation for this location.
    pub(crate) annotation: String,

    /// An OSC 8 rendered link for the location's annotation, if applicable.
    ///
    /// Not serialized, since it contains ANSI escape codes.
    #[serde(skip_serializing)]
    pub(crate) link: Option<String>,

    /// A symbolic route (of keys and indices) to the final location.
    pub(crate) route: Route<'doc>,

    /// An optional subfeature for the symbolic location.
    pub(crate) subfeature: Option<Subfeature<'doc>>,

    /// The kind of location.
    pub(crate) kind: LocationKind,
}

impl<'doc> SymbolicLocation<'doc> {
    pub(crate) fn with_keys(&self, keys: &[RouteComponent<'doc>]) -> SymbolicLocation<'doc> {
        SymbolicLocation {
            key: self.key,
            annotation: self.annotation.clone(),
            link: None,
            route: self.route.with_keys(keys),
            subfeature: None,
            kind: self.kind,
        }
    }

    /// Adds a subfeature to the current `SymbolicLocation`.
    pub(crate) fn subfeature(mut self, subfeature: Subfeature<'doc>) -> SymbolicLocation<'doc> {
        self.subfeature = Some(subfeature);
        self
    }

    /// Adds a human-readable annotation to the current `SymbolicLocation`.
    pub(crate) fn annotated(mut self, annotation: impl Into<String>) -> SymbolicLocation<'doc> {
        self.annotation = annotation.into();
        self
    }

    /// Adds a URL to the current `SymbolicLocation`.
    pub(crate) fn with_url(mut self, url: impl Into<String>) -> SymbolicLocation<'doc> {
        self.link = Some(Link::new(&self.annotation, &url.into()).to_string());
        self
    }

    /// Mark the current `SymbolicLocation` as a "primary" location.
    pub(crate) fn primary(mut self) -> SymbolicLocation<'doc> {
        self.kind = LocationKind::Primary;
        self
    }

    /// Mark the current `SymbolicLocation` as a "hidden" location.
    pub(crate) fn hidden(mut self) -> SymbolicLocation<'doc> {
        self.kind = LocationKind::Hidden;
        self
    }

    pub(crate) fn is_primary(&self) -> bool {
        matches!(self.kind, LocationKind::Primary)
    }

    pub(crate) fn is_hidden(&self) -> bool {
        matches!(self.kind, LocationKind::Hidden)
    }

    /// Concretize this `SymbolicLocation`, consuming it in the process.
    pub(crate) fn concretize(
        self,
        document: &'doc yamlpath::Document,
    ) -> anyhow::Result<Location<'doc>> {
        let (extracted, location, feature) = match &self.subfeature {
            Some(subfeature) => {
                // If we have a subfeature, we have to extract its exact
                // parent feature.
                let feature = match self.route.to_query() {
                    Some(query) => document.query_exact(&query)?.ok_or_else(|| {
                        // This should never fail in practice, unless our
                        // route is malformed or ends in a key-only feature
                        // (e.g. `foo:`). The latter shouldn't really happen,
                        // since there's no meaningful subfeature in that case.
                        anyhow::anyhow!(
                            "failed to extract exact feature for symbolic location: {}",
                            self.annotation
                        )
                    })?,
                    None => document.root(),
                };

                let extracted = document.extract(&feature);

                let subfeature_span = {
                    let bias = feature.location.byte_span.0;
                    let start = &extracted[subfeature.after..]
                        .find(subfeature.fragment)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "failed to find subfeature '{}' in feature '{}'",
                                subfeature.fragment,
                                extracted
                            )
                        })?;

                    (start + bias)..(start + bias + subfeature.fragment.len())
                };

                (
                    extracted,
                    ConcreteLocation::from_span(subfeature_span, document),
                    feature,
                )
            }
            None => {
                let feature = match self.route.to_query() {
                    Some(query) => document.query_pretty(&query)?,
                    None => document.root(),
                };

                (
                    document.extract_with_leading_whitespace(&feature),
                    ConcreteLocation::from(&feature.location),
                    feature,
                )
            }
        };

        Ok(Location {
            symbolic: self,
            concrete: Feature {
                location,
                feature: extracted,
                comments: document
                    .feature_comments(&feature)
                    .into_iter()
                    .map(Comment)
                    .collect(),
            },
        })
    }
}

/// Gives models (e.g. workflow steps) the ability to express their symbolic location.
pub(crate) trait Locatable<'doc> {
    /// Returns the symbolic location of this model.
    fn location(&self) -> SymbolicLocation<'doc>;

    /// Returns an "enriched" symbolic location of this model,
    /// when the model is of a type that has a name. Otherwise,
    /// returns the same symbolic location as `location()`.
    ///
    /// For example, a GitHub Actions workflow step has an optional name,
    /// which is included in this symbolic location if present.
    fn location_with_name(&self) -> SymbolicLocation<'doc> {
        self.location()
    }
}

pub(crate) trait Routable<'a, 'doc> {
    fn route(&'a self) -> Route<'doc>;
}

impl<'a, 'doc, T: Locatable<'doc>> Routable<'a, 'doc> for T {
    fn route(&'a self) -> Route<'doc> {
        self.location().route
    }
}

/// Represents a `(row, column)` point within a file.
#[derive(Serialize)]
pub(crate) struct Point {
    pub(crate) row: usize,
    pub(crate) column: usize,
}

impl From<LineCol> for Point {
    fn from(value: LineCol) -> Self {
        Self {
            row: value.line as usize,
            column: value.col as usize,
        }
    }
}

/// A "concrete" location for some feature.
/// Every concrete location contains two spans: a line-and-column span,
/// and an offset range.
#[derive(Serialize)]
pub(crate) struct ConcreteLocation {
    pub(crate) start_point: Point,
    pub(crate) end_point: Point,
    pub(crate) offset_span: Range<usize>,
}

impl ConcreteLocation {
    pub(crate) fn new(start_point: Point, end_point: Point, offset_span: Range<usize>) -> Self {
        Self {
            start_point,
            end_point,
            offset_span,
        }
    }

    pub(crate) fn from_span(span: Range<usize>, doc: &yamlpath::Document) -> Self {
        let start = TextSize::new(span.start as u32);
        let end = TextSize::new(span.end as u32);

        let start_point = doc.line_index().line_col(start);
        let end_point = doc.line_index().line_col(end);

        Self {
            start_point: start_point.into(),
            end_point: end_point.into(),
            offset_span: span.clone(),
        }
    }
}

impl From<&yamlpath::Location> for ConcreteLocation {
    fn from(value: &yamlpath::Location) -> Self {
        Self {
            start_point: Point {
                row: value.point_span.0.0,
                column: value.point_span.0.1,
            },
            end_point: Point {
                row: value.point_span.1.0,
                column: value.point_span.1.1,
            },
            offset_span: value.byte_span.0..value.byte_span.1,
        }
    }
}

static ANY_COMMENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"#.*$").unwrap());

static IGNORE_EXPR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"# zizmor: ignore\[(.+)\](?:\s+.*)?$").unwrap());

/// Represents a single source comment.
#[derive(Debug, Serialize)]
#[serde(transparent)]
pub(crate) struct Comment<'doc>(&'doc str);

impl Comment<'_> {
    pub(crate) fn ignores(&self, rule_id: &str) -> bool {
        // Extracts foo,bar from `# zizmor: ignore[foo,bar]`
        let Some(caps) = IGNORE_EXPR.captures(self.0) else {
            return false;
        };

        caps.get(1)
            .unwrap()
            .as_str()
            .split(",")
            .any(|r| r.trim() == rule_id)
    }
}

/// An extracted feature, along with its concrete location.
#[derive(Serialize)]
pub(crate) struct Feature<'doc> {
    /// The feature's concrete location, as both an offset range and point span.
    pub(crate) location: ConcreteLocation,

    /// The feature's textual content.
    pub(crate) feature: &'doc str,

    /// Any comments within the feature's line span.
    pub(crate) comments: Vec<Comment<'doc>>,
}

impl<'doc> Feature<'doc> {
    pub(crate) fn from_span(span: &Range<usize>, input: &'doc AuditInput) -> Self {
        let raw = input.as_document().source();
        let start = TextSize::new(span.start as u32);
        let end = TextSize::new(span.end as u32);

        let start_point = input.line_index().line_col(start);
        let end_point = input.line_index().line_col(end);

        // Extract any comments within the feature's line span.
        //
        // This is slightly less precise than comment extraction
        // when concretizing a symbolic location, since we're operating
        // on a raw span rather than an AST-aware YAML path.
        //
        // NOTE: We can't use LineIndex::lines() to extract the comment-eligible
        // lines, because it doesn't include full line spans if the input
        // span is a strict subset of a single line.
        let comments = (start_point.line..=end_point.line)
            .flat_map(|line| {
                // NOTE: We don't really expect this to fail, since this
                // line range comes from the line index itself.
                let line = input.line_index().line(line)?;
                // Chomp the trailing newline rather than enabling
                // multi-line mode in ANY_COMMENT, on the theory that
                // chomping is a little faster.
                let line = &raw[line].trim_end();
                ANY_COMMENT.is_match(line).then_some(Comment(line))
            })
            .collect();

        Feature {
            location: ConcreteLocation::new(
                start_point.into(),
                end_point.into(),
                span.start..span.end,
            ),
            feature: &raw[span.start..span.end],
            comments,
        }
    }
}

/// A location within a GitHub Actions workflow, with both symbolic and concrete components.
#[derive(Serialize)]
pub(crate) struct Location<'doc> {
    /// The symbolic workflow location.
    pub(crate) symbolic: SymbolicLocation<'doc>,
    /// The concrete location, including extracted feature.
    pub(crate) concrete: Feature<'doc>,
}

impl<'doc> Location<'doc> {
    pub(crate) fn new(symbolic: SymbolicLocation<'doc>, concrete: Feature<'doc>) -> Self {
        Self { symbolic, concrete }
    }
}

#[cfg(test)]
mod tests {
    use super::Comment;

    #[test]
    fn test_comment_ignores() {
        let cases = &[
            // Trivial cases.
            ("# zizmor: ignore[foo]", "foo", true),
            ("# zizmor: ignore[foo,bar]", "foo", true),
            // Dashes are OK.
            ("# zizmor: ignore[foo,bar,foo-bar]", "foo-bar", true),
            // Spaces are OK.
            ("# zizmor: ignore[foo, bar,   foo-bar]", "foo-bar", true),
            // Extra commas and duplicates are nonsense but OK.
            ("# zizmor: ignore[foo,foo,,foo,,,,foo,]", "foo", true),
            // Trailing content with a space is OK.
            ("# zizmor: ignore[foo] some other stuff", "foo", true),
            // Trailing spaces are OK.
            ("# zizmor: ignore[foo] ", "foo", true),
            ("# zizmor: ignore[foo]  ", "foo", true),
            ("# zizmor: ignore[foo]   ", "foo", true),
            // Trailing content without a space is not OK.
            ("# zizmor: ignore[foo]some other stuff", "foo", false),
            // Valid ignore, but not a match.
            ("# zizmor: ignore[foo,bar]", "baz", false),
            // Invalid ignore: empty rule list.
            ("# zizmor: ignore[]", "", false),
            ("# zizmor: ignore[]", "foo", false),
            // Invalid ignore: no commas.
            ("# zizmor: ignore[foo bar]", "foo", false),
            // Invalid ignore: missing opening and/or closing [].
            ("# zizmor: ignore[foo", "foo", false),
            ("# zizmor: ignore foo", "foo", false),
            ("# zizmor: ignore foo]", "foo", false),
            // Invalid ignore: space after # and : is mandatory and fixed.
            ("# zizmor:ignore[foo]", "foo", false),
            ("#zizmor: ignore[foo]", "foo", false),
            ("#  zizmor: ignore[foo]", "foo", false),
            ("#  zizmor:  ignore[foo]", "foo", false),
        ];

        for (comment, rule, ignores) in cases {
            assert_eq!(
                Comment(comment).ignores(rule),
                *ignores,
                "{comment} does not ignore {rule}"
            )
        }
    }
}
