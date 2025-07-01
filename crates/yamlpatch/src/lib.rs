//! Comment and format-preserving YAML patch operations.

use std::borrow::Cow;

use line_index::{LineCol, TextRange, TextSize};
use serde::Serialize;

/// Represents a route component in a YAML path.
#[derive(Serialize, Clone, Debug)]
pub enum RouteComponent<'doc> {
    /// A key in a mapping.
    Key(&'doc str),
    /// An index in a sequence.
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

/// Represents a route (path) to a YAML feature.
#[derive(Serialize, Clone, Debug)]
pub struct Route<'doc> {
    components: Vec<RouteComponent<'doc>>,
}

impl Default for Route<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'doc> Route<'doc> {
    /// Create a new empty route.
    pub fn new() -> Route<'doc> {
        Self {
            components: Default::default(),
        }
    }

    /// Create a new route with the given keys appended.
    pub fn with_keys(&self, keys: &[RouteComponent<'doc>]) -> Route<'doc> {
        let mut components = self.components.clone();
        components.extend(keys.iter().cloned());
        Route { components }
    }

    /// Check if this route is the root route (empty).
    pub fn is_root(&self) -> bool {
        self.components.is_empty()
    }

    /// Convert this route to a yamlpath query.
    pub fn to_query(&self) -> Option<yamlpath::Query<'doc>> {
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

/// Macro to create a route from a series of keys and indices.
#[macro_export]
macro_rules! route {
    ($($key:expr),* $(,)?) => {
        $crate::Route::from(
            vec![$($crate::RouteComponent::from($key)),*]
        )
    };
    () => {
        $crate::Route::new()
    };
}

/// Error types for YAML patch operations
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("YAML query error: {0}")]
    Query(#[from] yamlpath::QueryError),
    #[error("YAML serialization error: {0}")]
    Serialization(#[from] serde_yaml::Error),
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
}

/// Represents different YAML styles for a feature.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Style {
    /// Block style mappings
    BlockMapping,
    /// Block style sequences
    BlockSequence,
    /// Multiline flow mapping style:
    ///
    /// ```yaml
    /// {
    ///   key: value,
    ///   key2: value2
    /// }
    /// ```
    MultilineFlowMapping,
    /// Single-line flow mapping style: { key: value, key2: value2 }
    FlowMapping,
    /// Multiline flow sequence style:
    /// ```yaml
    /// [
    ///   item1,
    ///   item2,
    /// ]
    /// ```
    MultilineFlowSequence,
    /// Single-line flow sequence style: [ item1, item2, item3 ]
    FlowSequence,
    /// Literal scalar style: |
    MultilineLiteralScalar,
    /// Folded scalar style: >
    MultilineFoldedScalar,
    /// Double quoted scalar style: "value"
    DoubleQuoted,
    /// Single quoted scalar style: 'value'
    SingleQuoted,
    /// Plain scalar style: value
    PlainScalar,
}

impl Style {
    /// Given a feature and its document, determine the style of the feature.
    pub fn from_feature(feature: &yamlpath::Feature, doc: &yamlpath::Document) -> Self {
        let content = doc.extract(feature);
        let trimmed = content.trim().as_bytes();
        let multiline = trimmed.contains(&b'\n');

        match feature.kind() {
            yamlpath::FeatureKind::BlockMapping => Style::BlockMapping,
            yamlpath::FeatureKind::BlockSequence => Style::BlockSequence,
            yamlpath::FeatureKind::FlowMapping => {
                if multiline {
                    Style::MultilineFlowMapping
                } else {
                    Style::FlowMapping
                }
            }
            yamlpath::FeatureKind::FlowSequence => {
                if multiline {
                    Style::MultilineFlowSequence
                } else {
                    Style::FlowSequence
                }
            }
            yamlpath::FeatureKind::Scalar => match trimmed[0] {
                b'|' => Style::MultilineLiteralScalar,
                b'>' => Style::MultilineFoldedScalar,
                b'"' => Style::DoubleQuoted,
                b'\'' => Style::SingleQuoted,
                _ => Style::PlainScalar,
            },
        }
    }
}

/// Represents a single YAML patch.
///
/// A patch operation consists of a route to the feature to patch
/// and the operation to perform on that feature.
#[derive(Debug, Clone)]
pub struct Patch<'doc> {
    /// The route to the feature to patch.
    pub route: Route<'doc>,
    /// The operation to perform on the feature.
    pub operation: Op<'doc>,
}

/// Represents a YAML patch operation.
#[derive(Debug, Clone)]
pub enum Op<'doc> {
    /// Rewrites a fragment of a feature at the given path.
    ///
    /// This can be used to perform graceful rewrites of string values,
    /// regardless of their nested position or single/multi-line nature.
    ///
    /// For example, the following:
    ///
    /// ```yaml
    /// run: |
    ///   echo "foo: ${{ foo }}"
    /// ```
    ///
    /// can be rewritten to:
    ///
    /// ```yaml
    /// run: |
    ///   echo "foo ${FOO}"
    /// ```
    ///
    /// via a `RewriteFragment` with:
    ///
    /// ```text
    /// route: "/run",
    /// from: "${{ foo }}",
    /// to: "${FOO}",
    /// ```
    ///
    /// This operation performs exactly one rewrite at a time, meaning
    /// that the first match of `from` in the feature will be replaced.
    ///
    /// This can be made more precise by passing a `after` index,
    /// which specifies that the rewrite should only occur on
    /// the first match of `from` that occurs after the given byte index.
    RewriteFragment {
        from: Cow<'doc, str>,
        to: Cow<'doc, str>,
        after: Option<usize>,
    },
    /// Replace the value at the given path
    Replace(serde_yaml::Value),
    /// Add a new key-value pair at the given path.
    ///
    /// The route should point to a mapping.
    ///
    /// Limitations:
    ///
    /// - The mapping must be a block mapping or single-line flow mapping.
    ///   Multi-line flow mappings are not currently supported.
    /// - The key must not already exist in the targeted mapping.
    Add {
        key: String,
        value: serde_yaml::Value,
    },
    /// Merge a key-value pair into an existing mapping at the given path, or create the key if it doesn't exist.
    /// If both the existing value and new value are mappings, they are merged together.
    /// Otherwise, the new value replaces the existing one.
    MergeInto {
        key: String,
        value: serde_yaml::Value,
    },
    /// Remove the key at the given path
    Remove,
}

/// Apply a sequence of YAML patch operations to a YAML document.
/// Returns a new YAML document with the patches applied.
///
/// Returns an error if the given YAML input is not valid, if a patch
/// operation fails, or if the resulting YAML is malformed.
///
/// Each patch is applied in the order given. The [`Patch`] APIs are
/// designed to operate symbolically without absolute byte positions,
/// so operations should not invalidate each other unless they actually
/// conflict in terms of proposed changes.
pub fn apply_yaml_patches(
    document: &yamlpath::Document,
    patches: &[Patch],
) -> Result<yamlpath::Document, Error> {
    let mut patches = patches.iter();

    let mut next_document = {
        let Some(patch) = patches.next() else {
            return Err(Error::InvalidOperation("no patches provided".to_string()));
        };

        apply_single_patch(document, patch)?
    };

    for patch in patches {
        next_document = apply_single_patch(&next_document, patch)?;
    }

    Ok(next_document)
}

/// Apply a single YAML patch operation
fn apply_single_patch(
    document: &yamlpath::Document,
    patch: &Patch,
) -> Result<yamlpath::Document, Error> {
    let content = document.source();
    match &patch.operation {
        Op::RewriteFragment { from, to, after } => {
            let Some(feature) = route_to_feature_exact(&patch.route, document)? else {
                return Err(Error::InvalidOperation(format!(
                    "no pre-existing value to patch at {route:?}",
                    route = patch.route
                )));
            };

            let extracted_feature = document.extract(&feature);

            let bias = match after {
                Some(after) => *after,
                None => 0,
            };

            if bias > extracted_feature.len() {
                return Err(Error::InvalidOperation(format!(
                    "replacement scan index {bias} is out of bounds for feature",
                )));
            }

            let slice = &extracted_feature[bias..];

            let (from_start, from_end) = match slice.find(from.as_ref()) {
                Some(idx) => (idx + bias, idx + bias + from.len()),
                None => {
                    return Err(Error::InvalidOperation(format!(
                        "no match for '{}' in feature",
                        from
                    )));
                }
            };

            let mut patched_feature = extracted_feature.to_string();
            patched_feature.replace_range(from_start..from_end, to);

            // Finally, put our patch back into the overall content.
            let mut patched_content = content.to_string();
            patched_content.replace_range(
                feature.location.byte_span.0..feature.location.byte_span.1,
                &patched_feature,
            );

            yamlpath::Document::new(patched_content).map_err(Error::from)
        }
        Op::Replace(value) => {
            let feature = route_to_feature_pretty(&patch.route, document)?;

            // Get the replacement content
            let replacement = apply_value_replacement(&feature, document, value, true)?;

            // Extract the current content to calculate spans
            let current_content = document.extract(&feature);
            let current_content_with_ws = document.extract_with_leading_whitespace(&feature);

            // Find the span to replace - use the span with leading whitespace if it's a key-value pair
            let (start_span, end_span) = if current_content_with_ws.contains(':') {
                // Replace the entire key-value pair span
                let ws_start = feature.location.byte_span.0
                    - (current_content_with_ws.len() - current_content.len());
                (ws_start, feature.location.byte_span.1)
            } else {
                // Replace just the value
                (feature.location.byte_span.0, feature.location.byte_span.1)
            };

            // Replace the content
            let mut result = content.to_string();
            result.replace_range(start_span..end_span, &replacement);

            yamlpath::Document::new(result).map_err(Error::from)
        }
        Op::Add { key, value } => {
            // Check to see whether `key` is already present within the route.
            // NOTE: Safe unwrap, since `with_keys` ensures we always have at
            // least one component.
            let key_query = patch
                .route
                .with_keys(&[key.as_str().into()])
                .to_query()
                .unwrap();

            if document.query_exists(&key_query) {
                return Err(Error::InvalidOperation(format!(
                    "key '{key}' already exists at {route:?}",
                    key = key,
                    route = patch.route
                )));
            }

            let feature = if patch.route.is_root() {
                document.top_feature()?
            } else {
                route_to_feature_exact(&patch.route, document)?.ok_or_else(|| {
                    Error::InvalidOperation(format!(
                        "no existing mapping at {route:?}",
                        route = patch.route
                    ))
                })?
            };

            let style = Style::from_feature(&feature, document);
            let feature_content = document.extract(&feature);

            let updated_feature = match style {
                Style::BlockMapping => {
                    handle_block_mapping_addition(feature_content, document, &feature, key, value)
                }
                Style::FlowMapping => handle_flow_mapping_addition(feature_content, key, value),
                // TODO: Remove this limitation.
                Style::MultilineFlowMapping => Err(Error::InvalidOperation(format!(
                    "add operation is not permitted against multiline flow mapping route: {:?}",
                    patch.route
                ))),
                _ => Err(Error::InvalidOperation(format!(
                    "add operation is not permitted against non-mapping route: {:?}",
                    patch.route
                ))),
            }?;

            // Replace the content in the document
            let mut result = content.to_string();
            result.replace_range(
                feature.location.byte_span.0..feature.location.byte_span.1,
                &updated_feature,
            );
            yamlpath::Document::new(result).map_err(Error::from)
        }
        Op::MergeInto { key, value } => {
            if patch.route.is_root() {
                // Handle root-level merges specially
                return handle_root_level_addition(document, key, value);
            }

            // Check if the key already exists in the target mapping
            let existing_key_route = patch.route.with_keys(&[key.as_str().into()]);

            if let Ok(existing_feature) = route_to_feature_pretty(&existing_key_route, document) {
                // Key exists, check if we need to merge mappings
                if let serde_yaml::Value::Mapping(new_mapping) = &value {
                    // Try to parse the existing value as YAML to see if it's also a mapping
                    let existing_content = document.extract(&existing_feature);
                    if let Ok(existing_value) =
                        serde_yaml::from_str::<serde_yaml::Value>(existing_content)
                    {
                        // The extracted content includes the key, so we need to get the value
                        let actual_existing_value =
                            if let serde_yaml::Value::Mapping(outer_mapping) = existing_value {
                                // If the extracted content is like "env: { ... }", get the value part
                                if let Some(inner_value) =
                                    outer_mapping.get(serde_yaml::Value::String(key.clone()))
                                {
                                    inner_value.clone()
                                } else {
                                    // Fallback: use the outer mapping directly
                                    serde_yaml::Value::Mapping(outer_mapping)
                                }
                            } else {
                                existing_value
                            };

                        if let serde_yaml::Value::Mapping(_) = actual_existing_value {
                            // Both are mappings, merge them using Add operations to preserve comments
                            let mut current_document = document.clone();
                            for (k, v) in new_mapping {
                                let key_str = match k {
                                    serde_yaml::Value::String(s) => s.clone(),
                                    _ => serde_yaml::to_string(k)?.trim().to_string(),
                                };

                                // Check if this key already exists in the mapping
                                let nested_key_route =
                                    existing_key_route.with_keys(&[key_str.as_str().into()]);
                                if let Ok(Some(_)) =
                                    route_to_feature_exact(&nested_key_route, &current_document)
                                {
                                    // Key exists, replace it
                                    current_document = apply_single_patch(
                                        &current_document,
                                        &Patch {
                                            route: nested_key_route,
                                            operation: Op::Replace(v.clone()),
                                        },
                                    )?;
                                } else {
                                    // Key doesn't exist, add it using Add operation to preserve comments
                                    current_document = apply_single_patch(
                                        &current_document,
                                        &Patch {
                                            route: existing_key_route.clone(),
                                            operation: Op::Add {
                                                key: key_str,
                                                value: v.clone(),
                                            },
                                        },
                                    )?;
                                }
                            }
                            return Ok(current_document);
                        }
                    }
                }

                // Not both mappings, or parsing failed, just replace
                return apply_single_patch(
                    document,
                    &Patch {
                        route: existing_key_route,
                        operation: Op::Replace(value.clone()),
                    },
                );
            }

            // Key doesn't exist, add it using Add operation
            apply_single_patch(
                document,
                &Patch {
                    route: patch.route.clone(),
                    operation: Op::Add {
                        key: key.clone(),
                        value: value.clone(),
                    },
                },
            )
        }
        Op::Remove => {
            if patch.route.is_root() {
                return Err(Error::InvalidOperation(
                    "Cannot remove root document".to_string(),
                ));
            }

            let feature = route_to_feature_pretty(&patch.route, document)?;

            // For removal, we need to remove the entire line including leading whitespace
            // TODO: This isn't sound, e.g. removing `b:` from `{a: a, b: b}` will
            // remove the entire line.
            let start_pos = {
                let range = line_span(document, feature.location.byte_span.0);
                range.start
            };
            let end_pos = {
                let range = line_span(document, feature.location.byte_span.1);
                range.end
            };

            let mut result = content.to_string();
            result.replace_range(start_pos..end_pos, "");
            yamlpath::Document::new(result).map_err(Error::from)
        }
    }
}

pub fn route_to_feature_pretty<'a>(
    route: &Route<'_>,
    doc: &'a yamlpath::Document,
) -> Result<yamlpath::Feature<'a>, Error> {
    match route.to_query() {
        Some(query) => doc.query_pretty(&query).map_err(Error::from),
        None => Ok(doc.root()),
    }
}

pub fn route_to_feature_exact<'a>(
    route: &Route<'_>,
    doc: &'a yamlpath::Document,
) -> Result<Option<yamlpath::Feature<'a>>, Error> {
    match route.to_query() {
        Some(query) => doc.query_exact(&query).map_err(Error::from),
        None => Ok(Some(doc.root())),
    }
}

/// Serialize a serde_yaml::Value to a YAML string, handling different types appropriately
fn serialize_yaml_value(value: &serde_yaml::Value) -> Result<String, Error> {
    let yaml_str = serde_yaml::to_string(value)?;
    Ok(yaml_str.trim_end().to_string()) // Remove trailing newline
}

/// Serialize a [`serde_yaml::Value`] to a YAML string in flow layout.
///
/// This serializes only a restricted subset of YAML: tags are not
/// supported, and mapping keys must be strings.
pub fn serialize_flow(value: &serde_yaml::Value) -> Result<String, Error> {
    let mut buf = String::new();
    fn serialize_inner(value: &serde_yaml::Value, buf: &mut String) -> Result<(), Error> {
        match value {
            serde_yaml::Value::Null => {
                // serde_yaml puts a trailing newline on this for some reasons
                // so we do it manually.
                buf.push_str("null");
                Ok(())
            }
            serde_yaml::Value::Bool(b) => {
                buf.push_str(if *b { "true" } else { "false" });
                Ok(())
            }
            serde_yaml::Value::Number(n) => {
                buf.push_str(&n.to_string());
                Ok(())
            }
            serde_yaml::Value::String(s) => {
                // Note: there are other plain-scalar-safe chars, but this is fine
                // for a first approximation.
                if s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                {
                    buf.push_str(s);
                } else {
                    // Dumb hack: serde_yaml will always produce a reasonable-enough
                    // single-line string scalar for us.
                    buf.push_str(
                        &serde_json::to_string(s)
                            .map_err(|e| Error::InvalidOperation(e.to_string()))?,
                    );
                }

                Ok(())
            }
            serde_yaml::Value::Sequence(values) => {
                // Serialize sequence in flow style: [item1, item2, item3]
                buf.push('[');
                for (i, item) in values.iter().enumerate() {
                    if i > 0 {
                        buf.push_str(", ");
                    }
                    serialize_inner(item, buf)?;
                }
                buf.push(']');
                Ok(())
            }
            serde_yaml::Value::Mapping(mapping) => {
                // Serialize mapping in flow style: { key1: value1, key2: value2 }
                buf.push_str("{ ");
                for (i, (key, value)) in mapping.iter().enumerate() {
                    if i > 0 {
                        buf.push_str(", ");
                    }
                    if !matches!(key, serde_yaml::Value::String(_)) {
                        return Err(Error::InvalidOperation(format!(
                            "mapping keys must be strings, found: {:?}",
                            key
                        )));
                    }
                    serialize_inner(key, buf)?;

                    buf.push_str(": ");
                    if !matches!(value, serde_yaml::Value::Null) {
                        // Skip the null part of `key: null`, since `key: `
                        // is more idiomatic.
                        serialize_inner(value, buf)?;
                    }
                }
                buf.push_str(" }");
                Ok(())
            }
            serde_yaml::Value::Tagged(tagged_value) => Err(Error::InvalidOperation(format!(
                "cannot serialize tagged value: {:?}",
                tagged_value
            ))),
        }
    }

    serialize_inner(value, &mut buf)?;
    Ok(buf)
}

/// Given a document and a position, return the span of the line containing that position.
///
/// Panics if the position is invalid.
fn line_span(doc: &yamlpath::Document, pos: usize) -> core::ops::Range<usize> {
    let pos = TextSize::new(pos as u32);
    let LineCol { line, .. } = doc.line_index().line_col(pos);
    doc.line_index().line(line).unwrap().into()
}

/// Extract the number of leading spaces need to align a block item with
/// its surrounding context.
///
/// This takes into account block sequences, e.g. where the mapping is
/// a child of a list item and needs to be properly aligned with the list
/// item's other content.
pub fn extract_leading_indentation_for_block_item(
    doc: &yamlpath::Document,
    feature: &yamlpath::Feature,
) -> usize {
    let line_range = line_span(doc, feature.location.byte_span.0);

    // NOTE: We trim the end since trailing whitespace doesn't count,
    // and we don't watch to match on the line's newline.
    let line_content = &doc.source()[line_range].trim_end();

    let mut accept_dash = true;
    for (idx, b) in line_content.bytes().enumerate() {
        match b {
            b' ' => {
                accept_dash = true;
            }
            b'-' => {
                if accept_dash {
                    accept_dash = false;
                } else {
                    return idx - 1;
                }
            }
            _ => {
                // If we accepted a dash last and we're on a non-dash/non-space,
                // then the last dash was part of a scalar.
                if !accept_dash {
                    return idx - 1;
                } else {
                    return idx;
                }
            }
        }
    }

    // If we've reached the end of the line without hitting a non-space
    // or non-dash, then we have a funky line item like:
    //
    // ```yaml
    //   -
    //     foo: bar
    // ```
    //
    // In which case our expected leading indentation the length plus one.
    //
    // This is reliable in practice but not technically sound, since the
    // user might have written:
    //
    // ```yaml
    //   -
    //       foo: bar
    // ```
    //
    // In which case we'll attempt to insert at the wrong indentation, and
    // probably produce invalid YAML.
    //
    // The trick there would probably be to walk forward on the feature's
    // lines and grab the first non-empty, non-comment line's leading whitespace.
    line_content.len() + 1
}

/// Extract leading whitespace from the beginning of the line containing
/// the given feature.
pub fn extract_leading_whitespace<'doc>(
    doc: &'doc yamlpath::Document,
    feature: &yamlpath::Feature,
) -> &'doc str {
    let line_range = line_span(doc, feature.location.byte_span.0);
    let line_content = &doc.source()[line_range];

    let end = line_content
        .bytes()
        .position(|b| b != b' ')
        .unwrap_or(line_content.len());

    &line_content[..end]
}

/// Indent multi-line YAML content to match the target indentation
fn indent_multiline_yaml(content: &str, base_indent: &str) -> String {
    let lines: Vec<&str> = content.lines().collect();
    if lines.len() <= 1 {
        return content.to_string();
    }

    let mut result = String::new();
    for (i, line) in lines.iter().enumerate() {
        if i == 0 {
            result.push_str(line);
        } else {
            result.push('\n');
            result.push_str(base_indent);
            if !line.trim().is_empty() {
                result.push_str("  "); // Additional indentation for continuation
                result.push_str(line.trim_start());
            }
        }
    }
    result
}

fn handle_block_mapping_addition(
    feature_content: &str,
    doc: &yamlpath::Document,
    feature: &yamlpath::Feature,
    key: &str,
    value: &serde_yaml::Value,
) -> Result<String, Error> {
    // Convert the new value to YAML string for block style handling
    let new_value_str = if matches!(value, serde_yaml::Value::Sequence(_)) {
        // For sequences, use flow-aware serialization to maintain consistency
        serialize_flow(value)?
    } else {
        serialize_yaml_value(value)?
    };
    let new_value_str = new_value_str.trim_end(); // Remove trailing newline

    // Determine the appropriate indentation
    let indent = " ".repeat(extract_leading_indentation_for_block_item(doc, feature));

    // Format the new entry
    let mut final_entry = if let serde_yaml::Value::Mapping(mapping) = &value {
        if mapping.is_empty() {
            // For empty mappings, format inline
            format!("\n{indent}{key}: {new_value_str}")
        } else {
            // For non-empty mappings, format as a nested structure
            let value_lines = new_value_str.lines();
            let mut result = format!("\n{indent}{key}:");
            for line in value_lines {
                if !line.trim().is_empty() {
                    result.push('\n');
                    result.push_str(&indent);
                    result.push_str("  "); // 2 spaces for nested content
                    result.push_str(line.trim_start());
                }
            }
            result
        }
    } else if new_value_str.contains('\n') {
        // Handle multiline values
        let indented_value = indent_multiline_yaml(new_value_str, &indent);
        format!("\n{indent}{key}: {indented_value}")
    } else {
        format!("\n{indent}{key}: {new_value_str}")
    };

    // Figure out the insertion point.
    // To do this, we find the end of the feature's content, i.e.
    // the last non-empty, non-comment line in the feature.
    let insertion_point = find_content_end(feature, doc);

    // If our insertion point is before the end of the feature,
    // we need to insert a newline to preserve the flow of any
    // trailing comments.
    if insertion_point < feature.location.byte_span.1 {
        final_entry.push('\n');
    }

    // Check if we need to add a newline before the entry
    // If the content at insertion point already ends with a newline, don't add another
    let needs_leading_newline = if insertion_point > 0 {
        doc.source().chars().nth(insertion_point - 1) != Some('\n')
    } else {
        true
    };

    let final_entry_to_insert = if needs_leading_newline {
        final_entry
    } else {
        // Remove the leading newline since there's already one
        final_entry
            .strip_prefix('\n')
            .unwrap_or(&final_entry)
            .to_string()
    };

    // Insert the final entry into the feature's content.
    // To do this, we need to readjust the insertion point using
    // the feature's start as the bias.
    let bias = feature.location.byte_span.0;
    let relative_insertion_point = insertion_point - bias;

    let mut updated_feature = feature_content.to_string();
    updated_feature.insert_str(relative_insertion_point, &final_entry_to_insert);

    Ok(updated_feature)
}

/// Handle adding a key-value pair to a flow mapping while preserving flow style
fn handle_flow_mapping_addition(
    feature_content: &str,
    key: &str,
    value: &serde_yaml::Value,
) -> Result<String, Error> {
    // Our strategy for flow mappings is to deserialize the existing feature,
    // add the new key-value pair, and then serialize it back.
    // This is probably slightly slower than just string manipulation,
    // but it saves us a lot of special-casing around trailing commas,
    // empty mapping forms, etc.
    //
    // We can get away with this because, unlike block mappings, single
    // line flow mappings can't contain comments or (much) other user
    // significant formatting.

    let mut existing_mapping = serde_yaml::from_str::<serde_yaml::Mapping>(feature_content)
        .map_err(Error::Serialization)?;

    existing_mapping.insert(key.into(), value.clone());

    let updated_content = serialize_flow(&serde_yaml::Value::Mapping(existing_mapping))?;

    Ok(updated_content)
}

/// Find the end of actual step content, excluding trailing comments
pub fn find_content_end(feature: &yamlpath::Feature, doc: &yamlpath::Document) -> usize {
    let lines: Vec<_> = doc
        .line_index()
        .lines(TextRange::new(
            (feature.location.byte_span.0 as u32).into(),
            (feature.location.byte_span.1 as u32).into(),
        ))
        .collect();

    // Walk over the feature's lines in reverse, and return the absolute
    // position of the end of the last non-empty, non-comment line
    for line in lines.into_iter().rev() {
        let line_content = &doc.source()[line];
        let trimmed = line_content.trim();

        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            return line.end().into();
        }
    }

    feature.location.byte_span.1 // Fallback to original end if no content found
}

/// Handle root-level additions and merges by finding the best insertion point at the document root
fn handle_root_level_addition(
    document: &yamlpath::Document,
    key: &str,
    value: &serde_yaml::Value,
) -> Result<yamlpath::Document, Error> {
    let content = document.source();

    // Convert the new value to YAML string
    let new_value_str = serialize_yaml_value(value)?;
    let new_value_str = new_value_str.trim_end(); // Remove trailing newline

    // For root-level additions, we want to insert at the end of the document
    // but before any trailing whitespace or comments
    let lines: Vec<&str> = content.lines().collect();

    // Find the last line that contains actual YAML content (not empty or comment-only)
    let mut last_content_line_idx = None;
    for (i, line) in lines.iter().enumerate().rev() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            last_content_line_idx = Some(i);
            break;
        }
    }

    // Format the new entry for root level (no indentation)
    let new_entry = if let serde_yaml::Value::Mapping(mapping) = value {
        if mapping.is_empty() {
            // For empty mappings, format inline
            format!("{}: {}", key, new_value_str)
        } else {
            // For non-empty mappings, format as a nested structure
            let value_lines: Vec<&str> = new_value_str.lines().collect();
            let mut result = format!("{}:", key);
            for line in value_lines.iter() {
                if !line.trim().is_empty() {
                    result.push('\n');
                    result.push_str("  "); // 2 spaces for nested content
                    result.push_str(line.trim_start());
                }
            }
            result
        }
    } else {
        // For scalar values, simple key: value format
        format!("{}: {}", key, new_value_str)
    };

    let mut result = content.to_string();

    if let Some(last_idx) = last_content_line_idx {
        // Calculate the insertion point after the last content line
        let mut insertion_point = 0;
        for (i, line) in lines.iter().enumerate() {
            if i <= last_idx {
                insertion_point += line.len();
                if i < lines.len() - 1 {
                    insertion_point += 1; // +1 for newline
                }
            } else {
                break;
            }
        }

        // Insert the new entry with a leading newline
        let final_entry = format!("\n{}", new_entry);
        result.insert_str(insertion_point, &final_entry);
    } else {
        // If there's no content, just append at the end
        if !result.is_empty() && !result.ends_with('\n') {
            result.push('\n');
        }
        result.push_str(&new_entry);
    }

    yamlpath::Document::new(result).map_err(Error::from)
}

/// Apply a value replacement at the given feature location, preserving key structure and formatting
fn apply_value_replacement(
    feature: &yamlpath::Feature,
    doc: &yamlpath::Document,
    value: &serde_yaml::Value,
    support_multiline_literals: bool,
) -> Result<String, Error> {
    // Extract the current content to see what we're replacing
    let current_content_with_ws = doc.extract_with_leading_whitespace(feature);

    // Get the byte span for precise replacement
    let start_byte = feature.location.byte_span.0;
    let end_byte = feature.location.byte_span.1;

    // Check if we're in a flow mapping context by examining the extracted content
    // For true flow mappings, the entire content should be a single-line flow mapping
    let trimmed_content = current_content_with_ws.trim();
    let is_flow_mapping = trimmed_content.starts_with('{')
        && trimmed_content.ends_with('}')
        && !trimmed_content.contains('\n');

    if is_flow_mapping {
        // Handle flow mapping replacement - we need to be more surgical
        return handle_flow_mapping_value_replacement(
            doc.source(),
            start_byte,
            end_byte,
            current_content_with_ws,
            value,
        );
    }

    // For mapping values, we need to preserve the key part
    let replacement = if let Some(colon_pos) = current_content_with_ws.find(':') {
        // This is a key-value pair, preserve the key and whitespace
        let key_part = &current_content_with_ws[..colon_pos + 1];
        let value_part = &current_content_with_ws[colon_pos + 1..];

        if support_multiline_literals {
            // Check if this is a multiline YAML string (contains |)
            let is_multiline_literal = value_part.trim_start().starts_with('|');

            if is_multiline_literal {
                // Check if this is a multiline string value
                if let serde_yaml::Value::String(string_content) = value {
                    if string_content.contains('\n') {
                        // For multiline literal blocks, use the raw string content
                        let leading_whitespace = extract_leading_whitespace(doc, feature);
                        let content_indent = format!("{}  ", leading_whitespace); // Key indent + 2 spaces for content

                        // Format as: key: |\n  content\n  more content
                        let indented_content = string_content
                            .lines()
                            .map(|line| {
                                if line.trim().is_empty() {
                                    String::new()
                                } else {
                                    format!("{}{}", content_indent, line.trim_start())
                                }
                            })
                            .collect::<Vec<_>>()
                            .join("\n");

                        // Find the position of | in the original content and include it
                        let pipe_pos = value_part.find('|').unwrap();
                        let key_with_pipe = &current_content_with_ws
                            [..colon_pos + 1 + value_part[..pipe_pos].len() + 1];
                        return Ok(format!(
                            "{}\n{}",
                            key_with_pipe.trim_end(),
                            indented_content
                        ));
                    }
                }
            }
        }

        // Regular block style - use standard formatting
        let val_str = serialize_yaml_value(value)?;
        format!("{} {}", key_part, val_str.trim())
    } else {
        // This is just a value, replace it directly

        serialize_yaml_value(value)?
    };

    Ok(replacement)
}

/// Handle value replacement within flow mappings more precisely
fn handle_flow_mapping_value_replacement(
    _content: &str,
    _start_byte: usize,
    _end_byte: usize,
    current_content: &str,
    value: &serde_yaml::Value,
) -> Result<String, Error> {
    let val_str = serialize_yaml_value(value)?;
    let val_str = val_str.trim();

    // Parse the flow mapping content to understand the structure
    let trimmed = current_content.trim();

    // Case 1: { key: } - has colon, empty value
    if let Some(colon_pos) = trimmed.find(':') {
        let before_colon = &trimmed[..colon_pos];
        let after_colon = &trimmed[colon_pos + 1..];

        // Check if there's already a value after the colon (excluding the closing brace)
        let value_part = after_colon.trim().trim_end_matches('}').trim();

        if value_part.is_empty() {
            // Case: { key: } -> { key: value }
            let key_part = before_colon.trim_start_matches('{').trim();
            Ok(format!("{{ {}: {} }}", key_part, val_str))
        } else {
            // Case: { key: oldvalue } -> { key: newvalue }
            let key_part = before_colon.trim_start_matches('{').trim();
            Ok(format!("{{ {}: {} }}", key_part, val_str))
        }
    } else {
        // Case 2: { key } - no colon, bare key -> { key: value }
        let key_part = trimmed.trim_start_matches('{').trim_end_matches('}').trim();
        Ok(format!("{{ {}: {} }}", key_part, val_str))
    }
}
