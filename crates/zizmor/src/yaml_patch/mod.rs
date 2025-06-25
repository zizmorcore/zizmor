//! Comment and format-preserving YAML patch operations.

use std::borrow::Cow;

use line_index::{LineCol, TextRange, TextSize};

use crate::finding::location::Route;

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
    /// ```
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
    #[allow(dead_code)]
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

                        if let serde_yaml::Value::Mapping(existing_mapping) = actual_existing_value
                        {
                            // Both are mappings, merge them
                            let mut merged_mapping = existing_mapping.clone();
                            for (k, v) in new_mapping {
                                merged_mapping.insert(k.clone(), v.clone());
                            }

                            // Use a custom replacement that preserves the key structure
                            return apply_mapping_replacement(
                                document,
                                &existing_key_route,
                                key,
                                &serde_yaml::Value::Mapping(merged_mapping),
                            );
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

fn route_to_feature_pretty<'a>(
    route: &Route<'_>,
    doc: &'a yamlpath::Document,
) -> Result<yamlpath::Feature<'a>, Error> {
    match route.to_query() {
        Some(query) => doc.query_pretty(&query).map_err(Error::from),
        None => Ok(doc.root()),
    }
}

fn route_to_feature_exact<'a>(
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
fn serialize_flow(value: &serde_yaml::Value) -> Result<String, Error> {
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
fn extract_leading_indentation_for_block_item(
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
fn extract_leading_whitespace<'doc>(
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
fn find_content_end(feature: &yamlpath::Feature, doc: &yamlpath::Document) -> usize {
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

/// Apply a mapping replacement that preserves the key structure
fn apply_mapping_replacement(
    doc: &yamlpath::Document,
    route: &Route<'_>,
    _key: &str,
    value: &serde_yaml::Value,
) -> Result<yamlpath::Document, Error> {
    let feature = route_to_feature_pretty(route, doc)?;

    // Extract the current content to see what we're working with
    let current_content_with_ws = doc.extract_with_leading_whitespace(&feature);

    // Check if this is a flow mapping that should be handled specially
    let trimmed_content = current_content_with_ws.trim();
    let is_flow_mapping = trimmed_content.starts_with('{')
        && trimmed_content.ends_with('}')
        && !trimmed_content.contains('\n');

    if is_flow_mapping {
        // For flow mappings, use the existing flow mapping logic
        let replacement = apply_value_replacement(&feature, doc, value, false)?;
        let mut result = doc.source().to_string();
        result.replace_range(
            feature.location.byte_span.0..feature.location.byte_span.1,
            &replacement,
        );
        return yamlpath::Document::new(result).map_err(Error::from);
    }

    // For block mappings, we need to preserve the structure properly
    if let Some(colon_pos) = current_content_with_ws.find(':') {
        // This is a key-value pair like "env:\n  EXISTING_VAR: value"
        let key_part = &current_content_with_ws[..colon_pos + 1]; // "env:"

        // Get the indentation level for the mapping content
        let leading_whitespace = extract_leading_whitespace(doc, &feature);
        let content_indent = format!("{}  ", leading_whitespace); // Add 2 spaces for mapping content

        // Serialize the new mapping value and indent it properly
        let new_value_str = serialize_yaml_value(value)?;
        let new_value_str = new_value_str.trim_end();

        // Format the mapping content with proper indentation
        let indented_content = if let serde_yaml::Value::Mapping(mapping) = value {
            if mapping.is_empty() {
                " {}".to_string() // Empty mapping as inline
            } else {
                // Format as block mapping
                let mut formatted_lines = Vec::new();
                for (k, v) in mapping {
                    let key_str = match k {
                        serde_yaml::Value::String(s) => s.clone(),
                        _ => serde_yaml::to_string(k)?.trim().to_string(),
                    };
                    let val_str = serialize_yaml_value(v)?;
                    let val_str = val_str.trim();
                    formatted_lines.push(format!("{}{}: {}", content_indent, key_str, val_str));
                }
                format!("\n{}", formatted_lines.join("\n"))
            }
        } else {
            // Not a mapping, format as regular value
            format!(" {}", new_value_str)
        };

        let replacement = format!("{}{}", key_part, indented_content);

        // Calculate spans for replacement
        let ws_start = feature.location.byte_span.0
            - (current_content_with_ws.len() - current_content_with_ws.trim_start().len());

        let mut result = doc.source().to_string();
        result.replace_range(ws_start..feature.location.byte_span.1, &replacement);
        yamlpath::Document::new(result).map_err(Error::from)
    } else {
        // Not a key-value pair, use regular value replacement
        let replacement = apply_value_replacement(&feature, doc, value, false)?;
        let mut result = doc.source().to_string();
        result.replace_range(
            feature.location.byte_span.0..feature.location.byte_span.1,
            &replacement,
        );
        yamlpath::Document::new(result).map_err(Error::from)
    }
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

#[cfg(test)]
mod tests {
    use crate::route;

    use super::*;

    #[test]
    fn test_serialize_flow() {
        let doc = r#"
foo:
  bar:
  baz: qux
  abc:
    - def
    - ghi
    - null
    - ~
    - |
      abcd
      efgh

flow: [1, 2, 3, {more: 456, evenmore: "abc\ndef"}]
"#;

        let value: serde_yaml::Value = serde_yaml::from_str(doc).unwrap();
        let serialized = serialize_flow(&value).unwrap();

        // serialized is valid YAML
        assert!(serde_yaml::from_str::<serde_yaml::Value>(&serialized).is_ok());

        insta::assert_snapshot!(serialized, @r#"{ foo: { bar: , baz: qux, abc: [def, ghi, null, null, "abcd\nefgh\n"] }, flow: [1, 2, 3, { more: 456, evenmore: "abc\ndef" }] }"#);
    }

    #[test]
    fn test_detect_style() {
        let doc = r#"
block-mapping-a:
  foo: bar
  baz: qux

"block-mapping-b":
  foo: bar

block-sequence-a:
  - item1
  - item2
  - item3

"block-sequence-b":
  - item1
  - item2
  - item3

flow-mapping-a: { a: b, c: d }
flow-mapping-b: { a: b, c: d, }
flow-mapping-c: {
  a: b,
  c: d
}
flow-mapping-d: {
  a: b,
  c: d,
}
flow-mapping-e: {
  a: b, c: d,
}
flow-mapping-f: { abc }
flow-mapping-g: { abc: }

flow-sequence-a: [item1, item2, item3]
flow-sequence-b: [ item1, item2, item3 ]
flow-sequence-c: [
  item1,
  item2,
  item3
]
flow-sequence-d: [
  item1,
  item2,
  item3,
]

scalars:
  - 123
  - abc
  - "abc"
  - 'abc'
  - -123
  - '{abc}'
  - '[abc]'
  - abc def

multiline-scalars:
  literal-a: |
    abcd
  literal-b: |-
    abcd
  literal-c: |+
    abcd
  literal-d: |2
    abcd
  literal-e: |-2
    abcd

  folded-a: >
    abcd
  folded-b: >-
    abcd
  folded-c: >+
    abcd
  folded-d: >2
    abcd
  folded-e: >-2
    abcd

empty:
  foo:

"#;

        let doc = yamlpath::Document::new(doc).unwrap();

        for (route, expected_style) in &[
            (route!("block-mapping-a"), Style::BlockMapping),
            (route!("block-mapping-b"), Style::BlockMapping),
            (route!("block-sequence-a"), Style::BlockSequence),
            (route!("block-sequence-b"), Style::BlockSequence),
            (route!("flow-mapping-a"), Style::FlowMapping),
            (route!("flow-mapping-b"), Style::FlowMapping),
            (route!("flow-mapping-c"), Style::MultilineFlowMapping),
            (route!("flow-mapping-d"), Style::MultilineFlowMapping),
            (route!("flow-mapping-e"), Style::MultilineFlowMapping),
            (route!("flow-mapping-f"), Style::FlowMapping),
            (route!("flow-mapping-g"), Style::FlowMapping),
            (route!("flow-sequence-a"), Style::FlowSequence),
            (route!("flow-sequence-b"), Style::FlowSequence),
            (route!("flow-sequence-c"), Style::MultilineFlowSequence),
            (route!("flow-sequence-d"), Style::MultilineFlowSequence),
            (route!("scalars", 0), Style::PlainScalar),
            (route!("scalars", 1), Style::PlainScalar),
            (route!("scalars", 2), Style::DoubleQuoted),
            (route!("scalars", 3), Style::SingleQuoted),
            (route!("scalars", 4), Style::PlainScalar),
            (route!("scalars", 5), Style::SingleQuoted),
            (route!("scalars", 6), Style::SingleQuoted),
            (route!("scalars", 7), Style::PlainScalar),
            (
                route!("multiline-scalars", "literal-a"),
                Style::MultilineLiteralScalar,
            ),
            (
                route!("multiline-scalars", "literal-b"),
                Style::MultilineLiteralScalar,
            ),
            (
                route!("multiline-scalars", "literal-c"),
                Style::MultilineLiteralScalar,
            ),
            (
                route!("multiline-scalars", "literal-d"),
                Style::MultilineLiteralScalar,
            ),
            (
                route!("multiline-scalars", "literal-e"),
                Style::MultilineLiteralScalar,
            ),
            (
                route!("multiline-scalars", "folded-a"),
                Style::MultilineFoldedScalar,
            ),
            (
                route!("multiline-scalars", "folded-b"),
                Style::MultilineFoldedScalar,
            ),
            (
                route!("multiline-scalars", "folded-c"),
                Style::MultilineFoldedScalar,
            ),
            (
                route!("multiline-scalars", "folded-d"),
                Style::MultilineFoldedScalar,
            ),
            (
                route!("multiline-scalars", "folded-e"),
                Style::MultilineFoldedScalar,
            ),
        ] {
            let feature = route_to_feature_exact(route, &doc).unwrap().unwrap();
            let style = Style::from_feature(&feature, &doc);
            assert_eq!(style, *expected_style, "for route: {route:?}");
        }
    }

    #[test]
    fn test_reparse_exact_extracted() {
        let original = r#"
foo:
  bar:
    a: b
    c: d
    e: f
"#;

        let doc = yamlpath::Document::new(original).unwrap();
        let feature = route_to_feature_exact(&route!("foo", "bar"), &doc)
            .unwrap()
            .unwrap();

        let content = doc.extract_with_leading_whitespace(&feature);

        let reparsed = serde_yaml::from_str::<serde_yaml::Mapping>(content).unwrap();
        assert_eq!(
            reparsed.get(serde_yaml::Value::String("a".to_string())),
            Some(&serde_yaml::Value::String("b".to_string()))
        );
    }

    #[test]
    fn test_rewrite_fragment_single_line() {
        let original = r#"
foo:
  bar: 'echo "foo: ${{ foo }}"'
"#;

        let document = yamlpath::Document::new(original).unwrap();

        let operations = vec![Patch {
            route: route!("foo", "bar"),
            operation: Op::RewriteFragment {
                from: "${{ foo }}".into(),
                to: "${FOO}".into(),
                after: None,
            },
        }];

        let result = apply_yaml_patches(&document, &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r#"
        foo:
          bar: 'echo "foo: ${FOO}"'
        "#);
    }

    #[test]
    fn test_rewrite_fragment_multi_line() {
        let original = r#"
foo:
  bar: |
    echo "foo: ${{ foo }}"
    echo "bar: ${{ bar }}"
    echo "foo: ${{ foo }}"
"#;

        let document = yamlpath::Document::new(original).unwrap();

        // Only the first occurrence of `from` should be replaced
        let operations = vec![Patch {
            route: route!("foo", "bar"),
            operation: Op::RewriteFragment {
                from: "${{ foo }}".into(),
                to: "${FOO}".into(),
                after: None,
            },
        }];

        let result = apply_yaml_patches(&document, &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r#"
        foo:
          bar: |
            echo "foo: ${FOO}"
            echo "bar: ${{ bar }}"
            echo "foo: ${{ foo }}"
        "#);

        // Now test with after set to skip the first occurrence
        let operations = vec![Patch {
            route: route!("foo", "bar"),
            operation: Op::RewriteFragment {
                from: "${{ foo }}".into(),
                to: "${FOO}".into(),
                after: original.find("${{ foo }}").map(|idx| idx + 1),
            },
        }];

        let result = apply_yaml_patches(&document, &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r#"
        foo:
          bar: |
            echo "foo: ${{ foo }}"
            echo "bar: ${{ bar }}"
            echo "foo: ${FOO}"
        "#);
    }

    #[test]
    fn test_rewrite_fragment_multi_line_in_list() {
        let original = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "foo: ${{ foo }}"
          echo "bar: ${{ bar }}"
        "#;

        let document = yamlpath::Document::new(original).unwrap();

        let operations = vec![
            Patch {
                route: route!("jobs", "test", "steps", 0, "run"),
                operation: Op::RewriteFragment {
                    from: "${{ foo }}".into(),
                    to: "${FOO}".into(),
                    after: None,
                },
            },
            Patch {
                route: route!("jobs", "test", "steps", 0, "run"),
                operation: Op::RewriteFragment {
                    from: "${{ bar }}".into(),
                    to: "${BAR}".into(),
                    after: None,
                },
            },
        ];

        let result = apply_yaml_patches(&document, &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r#"
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo "foo: ${FOO}"
                  echo "bar: ${BAR}"
        "#);
    }

    #[test]
    fn test_replace_empty_block_value() {
        let original = r#"
foo:
  bar:
"#;

        let document = yamlpath::Document::new(original).unwrap();

        let operations = vec![Patch {
            route: route!("foo", "bar"),
            operation: Op::Replace(serde_yaml::Value::String("abc".to_string())),
        }];

        let result = apply_yaml_patches(&document, &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r"
        foo:
          bar: abc
        ");
    }

    #[test]
    fn test_replace_empty_flow_value() {
        let original = r#"
    foo: { bar: }
    "#;

        let document = yamlpath::Document::new(original).unwrap();

        let patches = vec![Patch {
            route: route!("foo", "bar"),
            operation: Op::Replace(serde_yaml::Value::String("abc".to_string())),
        }];

        let result = apply_yaml_patches(&document, &patches).unwrap();

        insta::assert_snapshot!(result.source(), @r"foo: { bar: abc }");
    }

    #[test]
    fn test_replace_empty_flow_value_no_colon() {
        let original = r#"
        foo: { bar }
        "#;

        let document = yamlpath::Document::new(original).unwrap();

        let patches = vec![Patch {
            route: route!("foo", "bar"),
            operation: Op::Replace(serde_yaml::Value::String("abc".to_string())),
        }];

        let result = apply_yaml_patches(&document, &patches).unwrap();

        insta::assert_snapshot!(result.source(), @r"foo: { bar: abc }");
    }

    #[test]
    fn test_replace_multiline_string() {
        let original = r#"
foo:
  bar:
    baz: |
      Replace me.
      Replace me too.
"#;

        let document = yamlpath::Document::new(original).unwrap();

        let operations = vec![Patch {
            route: route!("foo", "bar", "baz"),
            operation: Op::Replace("New content.\nMore new content.\n".into()),
        }];

        let result = apply_yaml_patches(&document, &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r"
        foo:
          bar:
            baz: |
              New content.
              More new content.
        ");
    }

    #[test]
    fn test_yaml_patch_replace_preserves_comments() {
        let original = r#"
# This is a workflow file
name: CI
on: push

permissions: # This configures permissions
  contents: read  # Only read access
  actions: write  # Write access for actions

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"#;

        let document = yamlpath::Document::new(original).unwrap();

        let operations = vec![Patch {
            route: route!("permissions", "contents"),
            operation: Op::Replace(serde_yaml::Value::String("write".to_string())),
        }];

        let result = apply_yaml_patches(&document, &operations).unwrap();

        // Preserves all comments, but changes the value of `contents`
        insta::assert_snapshot!(result.source(), @r"
        # This is a workflow file
        name: CI
        on: push

        permissions: # This configures permissions
          contents: write  # Only read access
          actions: write  # Write access for actions

        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
        ");
    }

    #[test]
    fn test_add_rejects_duplicate_key() {
        let original = r#"
        foo:
            bar: abc
        "#;

        let document = yamlpath::Document::new(original).unwrap();

        let operations = vec![Patch {
            route: route!("foo"),
            operation: Op::Add {
                key: "bar".to_string(),
                value: serde_yaml::Value::String("def".to_string()),
            },
        }];

        let result = apply_yaml_patches(&document, &operations);

        // Should return an error about duplicate key
        assert!(result.is_err());
        let Err(err) = result else {
            panic!("expected an error");
        };
        assert!(err.to_string().contains("key 'bar' already exists at"));
    }

    #[test]
    fn test_add_preserves_formatting() {
        let original = r#"
permissions:
  contents: read
  actions: write
"#;

        let document = yamlpath::Document::new(original).unwrap();

        let operations = vec![Patch {
            route: route!("permissions"),
            operation: Op::Add {
                key: "issues".to_string(),
                value: serde_yaml::Value::String("read".to_string()),
            },
        }];

        let result = apply_yaml_patches(&document, &operations).unwrap();

        // Preserves original content, adds new key while maintaining indentation
        insta::assert_snapshot!(result.source(), @r"
        permissions:
          contents: read
          actions: write
          issues: read
        ");
    }

    #[test]
    fn test_add_preserves_flow_mapping_formatting() {
        let original = r#"
foo: { bar: abc }
"#;

        let operations = vec![Patch {
            route: route!("foo"),
            operation: Op::Add {
                key: "baz".to_string(),
                value: serde_yaml::Value::String("qux".to_string()),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        insta::assert_snapshot!(result.source(), @"foo: { bar: abc, baz: qux }");
    }

    #[test]
    fn test_remove_preserves_structure() {
        let original = r#"
permissions:
  contents: read  # Keep this comment
  actions: write  # Remove this line
  issues: read
"#;

        let document = yamlpath::Document::new(original).unwrap();

        let operations = vec![Patch {
            route: route!("permissions", "actions"),
            operation: Op::Remove,
        }];

        let result = apply_yaml_patches(&document, &operations).unwrap();

        // Preserves other content, removes the target line
        insta::assert_snapshot!(result.source(), @r"
        permissions:
          contents: read  # Keep this comment
          issues: read
        ");
    }

    #[test]
    fn test_multiple_operations_preserve_comments() {
        let original = r#"
# Main configuration
name: Test Workflow
on:
  push: # Trigger on push
    branches: [main]

permissions:  # Security settings
  contents: read
  actions: read

jobs:
  build: # Main job
    runs-on: ubuntu-latest
"#;

        let operations = vec![
            Patch {
                route: route!("permissions", "contents"),
                operation: Op::Replace(serde_yaml::Value::String("write".to_string())),
            },
            Patch {
                route: route!("permissions"),
                operation: Op::Add {
                    key: "issues".to_string(),
                    value: serde_yaml::Value::String("write".to_string()),
                },
            },
        ];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        // All comments preserved, all changes applied
        insta::assert_snapshot!(result.source(), @r"
        # Main configuration
        name: Test Workflow
        on:
          push: # Trigger on push
            branches: [main]

        permissions:  # Security settings
          contents: write
          actions: read
          issues: write

        jobs:
          build: # Main job
            runs-on: ubuntu-latest
        ");
    }

    #[test]
    fn test_extract_leading_indentation_for_block_item() {
        let doc = r#"
foo:
  - four:

bar:
  -    foo: abc
       bar: abc

two:
  abc:
  def:

tricky-a:
  - -abc:

tricky-b:
  - --abc:

tricky-c:
  - -123:

tricky-d:
  - - abc: # nested block list

tricky-e:
    - - - --abc:

tricky-f:
  -
    foo:

tricky-g:
  -
      foo: bar

nested:
  - foo: bar
    baz:
      - abc: def
"#;

        let doc = yamlpath::Document::new(doc).unwrap();

        for (route, expected) in &[
            (route!("foo", 0), 4),
            (route!("bar", 0), 7),
            (route!("two"), 2),
            (route!("tricky-a"), 4),
            (route!("tricky-b"), 4),
            (route!("tricky-c"), 4),
            (route!("tricky-d"), 6),
            (route!("tricky-e"), 10),
            (route!("tricky-f"), 4),
            (route!("tricky-g"), 4), // BUG, should be 6
            (route!("nested", 0, "baz", 0), 8),
        ] {
            let feature = route_to_feature_exact(route, &doc).unwrap().unwrap();
            assert_eq!(
                extract_leading_indentation_for_block_item(&doc, &feature),
                *expected
            );
        }
    }

    #[test]
    fn test_extract_leading_whitespace() {
        let doc = r#"
two:
  four:
    six:
      also-six: also eight
"#;
        let doc = yamlpath::Document::new(doc).unwrap();

        // Test leading whitespace extraction for various routes
        // The features are extracted in "exact" mode below, so the indentation
        // corresponds to the body rather than the key.
        for (route, expected) in &[
            (route!(), ""),
            (route!("two"), "  "),
            (route!("two", "four"), "    "),
            (route!("two", "four", "six"), "      "),
            (route!("two", "four", "six", "also-six"), "      "),
        ] {
            let feature = route_to_feature_exact(route, &doc).unwrap().unwrap();

            assert_eq!(extract_leading_whitespace(&doc, &feature), *expected);
        }
    }

    #[test]
    fn test_find_content_end() {
        let doc = r#"
foo:
  bar: baz
  abc: def # comment
  # comment

interior-spaces:
  - foo

  - bar
  # hello
  - baz # hello
  # hello
# hello

normal:
  foo: bar
"#;

        let doc = yamlpath::Document::new(doc).unwrap();

        let feature = route_to_feature_exact(&route!("foo"), &doc)
            .unwrap()
            .unwrap();
        let end = find_content_end(&feature, &doc);

        insta::assert_snapshot!(doc.source()[feature.location.byte_span.0..end], @r"
        bar: baz
          abc: def # comment
        ");

        let feature = route_to_feature_exact(&route!("interior-spaces"), &doc)
            .unwrap()
            .unwrap();
        let end = find_content_end(&feature, &doc);
        insta::assert_snapshot!(doc.source()[feature.location.byte_span.0..end], @r"
        - foo

          - bar
          # hello
          - baz # hello
        ");

        let feature = route_to_feature_exact(&route!("normal"), &doc)
            .unwrap()
            .unwrap();
        let end = find_content_end(&feature, &doc);
        insta::assert_snapshot!(doc.source()[feature.location.byte_span.0..end], @"foo: bar");
    }

    #[test]
    fn test_full_demo_workflow() {
        // This test demonstrates the complete workflow for comment-preserving YAML patches
        let original_yaml = r#"
# GitHub Actions Workflow
name: CI
on: push

# Security permissions
permissions: # This section defines permissions
  contents: read  # Only read access to repository contents
  actions: write  # Write access for GitHub Actions
  issues: read    # Read access to issues

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"#;

        let operations = vec![
            Patch {
                route: route!("permissions", "contents"),
                operation: Op::Replace(serde_yaml::Value::String("write".to_string())),
            },
            Patch {
                route: route!("permissions"),
                operation: Op::Add {
                    key: "packages".to_string(),
                    value: serde_yaml::Value::String("read".to_string()),
                },
            },
        ];

        let result = apply_yaml_patches(
            &yamlpath::Document::new(original_yaml).unwrap(),
            &operations,
        )
        .unwrap();

        insta::assert_snapshot!(result.source(), @r"
        # GitHub Actions Workflow
        name: CI
        on: push

        # Security permissions
        permissions: # This section defines permissions
          contents: write  # Only read access to repository contents
          actions: write  # Write access for GitHub Actions
          issues: read    # Read access to issues
          packages: read

        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
        ")
    }

    #[test]
    fn test_empty_mapping_formatting() {
        let original = r#"name: Test
jobs:
  test:
    runs-on: ubuntu-latest"#;

        // Test empty mapping formatting
        let empty_mapping = serde_yaml::Mapping::new();
        let operations = vec![Patch {
            route: route!("jobs", "test"),
            operation: Op::Add {
                key: "permissions".to_string(),
                value: serde_yaml::Value::Mapping(empty_mapping),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        // Empty mapping should be formatted inline
        insta::assert_snapshot!(result.source(), @r"
        name: Test
        jobs:
          test:
            runs-on: ubuntu-latest
            permissions: {}
        ");
    }

    #[test]
    fn test_no_empty_lines_after_insertion() {
        let original = r#"name: Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "test""#;

        // Test with trailing newline (common in real files)
        let original_with_newline = format!("{}\n", original);

        let operations = vec![Patch {
            route: route!("jobs", "test"),
            operation: Op::Add {
                key: "permissions".to_string(),
                value: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
            },
        }];

        let result = apply_yaml_patches(
            &yamlpath::Document::new(original_with_newline).unwrap(),
            &operations,
        )
        .unwrap();

        insta::assert_snapshot!(result.source(), @r#"
        name: Test
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo "test"
            permissions: {}
        "#);
    }

    #[test]
    fn test_debug_comments_and_spacing() {
        let original = r#"# GitHub Actions Workflow
name: Test
jobs:
  test:
    runs-on: ubuntu-latest  # Use latest Ubuntu

    # Steps section with comments
    steps:
      # Checkout step
      - name: Checkout repository
        uses: actions/checkout@v4  # Latest checkout action
        # No persist-credentials set

      # Build step
      - name: Build project
        run: echo "Building...""#;

        // Test what yamlpath extracts for the checkout step
        let doc = yamlpath::Document::new(original).unwrap();
        let checkout_query = route!("jobs", "test", "steps", 0).to_query().unwrap();
        let checkout_feature = doc.query_pretty(&checkout_query).unwrap();

        // Test what yamlpath extracts for the test job
        let job_query = route!("jobs", "test").to_query().unwrap();
        let job_feature = doc.query_pretty(&job_query).unwrap();

        // Assert that the checkout step extraction includes the expected content
        let checkout_content = doc.extract(&checkout_feature);
        assert!(checkout_content.contains("name: Checkout repository"));
        assert!(checkout_content.contains("uses: actions/checkout@v4"));

        // Assert that the job extraction includes the expected content
        let job_content = doc.extract(&job_feature);
        assert!(job_content.contains("runs-on: ubuntu-latest"));
        assert!(job_content.contains("steps:"));

        // Assert that byte spans are valid and non-overlapping
        let checkout_end = checkout_feature.location.byte_span.1;
        let job_end = job_feature.location.byte_span.1;

        assert!(checkout_feature.location.byte_span.0 < checkout_end);
        assert!(job_feature.location.byte_span.0 < job_end);
        assert!(checkout_end <= original.len());
        assert!(job_end <= original.len());

        // Assert that the checkout step is contained within the job
        assert!(checkout_feature.location.byte_span.0 >= job_feature.location.byte_span.0);
        assert!(checkout_feature.location.byte_span.1 <= job_feature.location.byte_span.1);
    }

    #[test]
    fn test_step_insertion_with_comments() {
        let original = r#"steps:
  - name: Checkout
    uses: actions/checkout@v4
    # This is a comment after the step

  - name: Build
    run: echo "build""#;

        let operations = vec![Patch {
            route: route!("steps", 0),
            operation: Op::Add {
                key: "with".to_string(),
                value: serde_yaml::Value::Mapping({
                    let mut map = serde_yaml::Mapping::new();
                    map.insert(
                        serde_yaml::Value::String("persist-credentials".to_string()),
                        serde_yaml::Value::Bool(false),
                    );
                    map
                }),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        // The with section should be added to the first step correctly, not mixed with comments
        insta::assert_snapshot!(result.source(), @r#"
        steps:
          - name: Checkout
            uses: actions/checkout@v4
            with:
              persist-credentials: false
            # This is a comment after the step

          - name: Build
            run: echo "build"
        "#);
    }

    #[test]
    fn test_comment_boundary_issue() {
        let original = r#"steps:
  - name: Step1
    uses: actions/checkout@v4
    # Comment after step1

  # Comment before step2
  - name: Step2
    run: echo "test""#;

        // See what yamlpath extracts for step 0
        let doc = yamlpath::Document::new(original).unwrap();
        let step0_query = route!("steps", 0).to_query().unwrap();
        let step0_feature = doc.query_pretty(&step0_query).unwrap();

        // See what yamlpath extracts for step 1
        let step1_query = route!("steps", 1).to_query().unwrap();
        let step1_feature = doc.query_pretty(&step1_query).unwrap();

        // Check for overlaps
        if step0_feature.location.byte_span.1 > step1_feature.location.byte_span.0 {
            // Handle overlap case
        }

        // Assert that the steps have valid boundaries and content
        let content_between =
            &original[step0_feature.location.byte_span.1..step1_feature.location.byte_span.0];

        // Assert that there's content between the steps (whitespace and list marker)
        assert!(
            !content_between.is_empty(),
            "There should be content between steps. Content between: {:?}",
            content_between
        );

        // The content between is just whitespace and the list marker for step2
        // yamlpath includes comments as part of the respective steps
        assert!(
            content_between.contains("- "),
            "Should contain list marker for step2. Content between: {:?}",
            content_between
        );

        // Assert that step boundaries don't overlap
        assert!(
            step0_feature.location.byte_span.1 <= step1_feature.location.byte_span.0,
            "Step boundaries should not overlap"
        );

        // Assert that both steps have valid content
        let step0_content = doc.extract(&step0_feature);
        let step1_content = doc.extract(&step1_feature);
        assert!(
            step0_content.contains("name: Step1"),
            "Step0 should contain its name"
        );
        assert!(
            step1_content.contains("name: Step2"),
            "Step1 should contain its name"
        );

        // Assert that step0 includes the comment after it (yamlpath behavior)
        assert!(
            step0_content.contains("uses: actions/checkout@v4"),
            "Step0 should contain the uses directive"
        );

        // Verify that yamlpath includes comments with their respective steps
        assert!(
            step0_content.contains("# Comment after step1")
                || content_between.contains("# Comment after step1"),
            "Comment after step1 should be included somewhere"
        );
    }

    #[test]
    fn test_add_root_level_preserves_formatting() {
        let original = r#"# GitHub Actions Workflow
name: CI
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"#;

        let operations = vec![Patch {
            route: route!(),
            operation: Op::Add {
                key: "permissions".to_string(),
                value: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r"
        # GitHub Actions Workflow
        name: CI
        on: push

        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
        permissions: {}
        ");
    }

    #[test]
    fn test_add_root_level_path_handling() {
        // Test that root path is handled correctly
        let original = r#"name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest"#;

        let operations = vec![Patch {
            route: route!(),
            operation: Op::Add {
                key: "permissions".to_string(),
                value: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
            },
        }];

        let result = apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations);
        assert!(result.is_ok());

        let result = result.unwrap();
        insta::assert_snapshot!(result.source(), @r"
        name: Test
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
        permissions: {}
        ");
    }

    #[test]
    fn test_step_content_end_detection() {
        let original = r#"steps:
  - name: Step1
    uses: actions/checkout@v4
    # Comment after step1

  # Comment before step2
  - name: Step2
    run: echo "test""#;

        let operations = vec![Patch {
            route: route!("steps", 0),
            operation: Op::Add {
                key: "with".to_string(),
                value: serde_yaml::Value::Mapping({
                    let mut map = serde_yaml::Mapping::new();
                    map.insert(
                        serde_yaml::Value::String("persist-credentials".to_string()),
                        serde_yaml::Value::Bool(false),
                    );
                    map
                }),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r#"
        steps:
          - name: Step1
            uses: actions/checkout@v4
            with:
              persist-credentials: false
            # Comment after step1

          # Comment before step2
          - name: Step2
            run: echo "test"
        "#);
    }

    #[test]
    fn test_merge_into_new_key() {
        // Test MergeInto when the key doesn't exist yet
        let original = r#"jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Test step
        run: echo "hello""#;

        let operations = vec![Patch {
            route: route!("jobs", "test", "steps", 0),
            operation: Op::MergeInto {
                key: "env".to_string(),
                value: serde_yaml::Value::Mapping({
                    let mut map = serde_yaml::Mapping::new();
                    map.insert(
                        serde_yaml::Value::String("TEST_VAR".to_string()),
                        serde_yaml::Value::String("test_value".to_string()),
                    );
                    map
                }),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();
        insta::assert_snapshot!(result.source(), @r#"
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Test step
                run: echo "hello"
                env:
                  TEST_VAR: test_value
        "#);
    }

    #[test]
    fn test_merge_into_existing_key() {
        // Test MergeInto when the key already exists
        let original = r#"jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Test step
        run: echo "hello"
        env:
          EXISTING_VAR: existing_value"#;

        let operations = vec![Patch {
            route: route!("jobs", "test", "steps", 0),
            operation: Op::MergeInto {
                key: "env".to_string(),
                value: serde_yaml::Value::Mapping({
                    let mut map = serde_yaml::Mapping::new();
                    map.insert(
                        serde_yaml::Value::String("NEW_VAR".to_string()),
                        serde_yaml::Value::String("new_value".to_string()),
                    );
                    map
                }),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        // Should merge the new mapping with the existing one
        insta::assert_snapshot!(result.source(), @r#"
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Test step
                run: echo "hello"
                env:
                  EXISTING_VAR: existing_value
                  NEW_VAR: new_value
        "#);
    }

    #[test]
    fn test_merge_into_prevents_duplicate_keys() {
        // Test that MergeInto prevents duplicate env keys
        let original = r#"jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Test step
        run: echo "hello"
        env:
          EXISTING_VAR: existing_value
          ANOTHER_VAR: another_value"#;

        let operations = vec![Patch {
            route: route!("jobs", "test", "steps", 0),
            operation: Op::MergeInto {
                key: "env".to_string(),
                value: serde_yaml::Value::Mapping({
                    let mut map = serde_yaml::Mapping::new();
                    map.insert(
                        serde_yaml::Value::String("NEW_VAR".to_string()),
                        serde_yaml::Value::String("new_value".to_string()),
                    );
                    map
                }),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        // Should only have one env: key
        assert_eq!(result.source().matches("env:").count(), 1);
        insta::assert_snapshot!(result.source(), @r#"
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Test step
                run: echo "hello"
                env:
                  EXISTING_VAR: existing_value
                  ANOTHER_VAR: another_value
                  NEW_VAR: new_value
        "#);
    }

    #[test]
    fn test_merge_into_with_shell_key() {
        // Test MergeInto with shell key to simulate template injection fixes
        let original = r#"jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Test step
        run: echo "hello""#;

        let operations = vec![Patch {
            route: route!("jobs", "test", "steps", 0),
            operation: Op::MergeInto {
                key: "env".to_string(),
                value: serde_yaml::Value::Mapping({
                    let mut map = serde_yaml::Mapping::new();
                    map.insert(
                        serde_yaml::Value::String("GITHUB_REF_NAME".to_string()),
                        serde_yaml::Value::String("${{ github.ref_name }}".to_string()),
                    );
                    map
                }),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r#"
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Test step
                run: echo "hello"
                env:
                  GITHUB_REF_NAME: ${{ github.ref_name }}
        "#);
    }

    #[test]
    fn test_debug_indentation_issue() {
        let original = r#"jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Test step
        run: |
          echo "line 1"
          echo "line 2""#;

        // Test yamlpath extraction
        let doc = yamlpath::Document::new(original).unwrap();
        let step_query = route!("jobs", "build", "steps", 0).to_query().unwrap();
        let step_feature = doc.query_pretty(&step_query).unwrap();

        // Test indentation calculation and content extraction
        let feature_with_ws = doc.extract_with_leading_whitespace(&step_feature);
        let step_content = doc.extract(&step_feature);

        // Assert that the step content contains expected elements
        assert!(step_content.contains("name: Test step"));
        assert!(step_content.contains("run: |"));
        assert!(step_content.contains("echo \"line 1\""));
        assert!(step_content.contains("echo \"line 2\""));

        // Assert that leading whitespace extraction includes the step content
        assert!(
            feature_with_ws.contains("name: Test step"),
            "Step should contain the step name. Actual content: {:?}",
            feature_with_ws
        );

        // Assert that the content includes the multiline run block
        assert!(
            feature_with_ws.contains("run: |"),
            "Step should contain multiline run block"
        );

        // Check if we're adding to a list item (should be true for step 0)
        let path = "/jobs/build/steps/0";
        let is_list_item = path
            .split('/')
            .next_back()
            .unwrap_or("")
            .parse::<usize>()
            .is_ok();
        assert!(is_list_item, "Path should indicate this is a list item");

        // Test indentation calculation for key-value pairs
        if let Some(first_line) = feature_with_ws.lines().next() {
            if let Some(_colon_pos) = first_line.find(':') {
                let key_indent = &first_line[..first_line.len() - first_line.trim_start().len()];
                let final_indent = format!("{}  ", key_indent);

                // Assert that indentation calculation works correctly
                assert!(!final_indent.is_empty(), "Final indent should not be empty");
                assert!(
                    final_indent.len() >= 2,
                    "Final indent should have at least 2 spaces"
                );
            }
        }

        // Test leading whitespace extraction function
        let leading_ws = extract_leading_whitespace(&doc, &step_feature);
        assert!(
            !leading_ws.is_empty(),
            "Leading whitespace should not be empty for indented step"
        );

        // Test the actual MergeInto operation
        let operations = vec![Patch {
            route: route!("jobs", "build", "steps", 0),
            operation: Op::MergeInto {
                key: "shell".to_string(),
                value: serde_yaml::Value::String("bash".to_string()),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r#"
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - name: Test step
                run: |
                  echo "line 1"
                  echo "line 2"
                shell: bash
        "#);
    }

    #[test]
    fn test_debug_merge_into_env_issue() {
        let original = r#"name: Test
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - name: Multiline step with env
        run: |
          echo "${{ steps.meta.outputs.tags }}" | xargs -I {} echo {}
        env:
          IDENTITY: ${{ secrets.IDENTITY }}
        shell: bash"#;

        // Test yamlpath extraction of the env section
        let doc = yamlpath::Document::new(original).unwrap();
        let env_query = route!("jobs", "test", "steps", 0, "env")
            .to_query()
            .unwrap();

        if let Ok(env_feature) = doc.query_pretty(&env_query) {
            let env_content = doc.extract(&env_feature);

            // Assert that env content is extracted correctly
            assert!(env_content.contains("IDENTITY: ${{ secrets.IDENTITY }}"));

            // Try to parse it as YAML and verify structure
            match serde_yaml::from_str::<serde_yaml::Value>(env_content) {
                Ok(value) => {
                    if let serde_yaml::Value::Mapping(outer_mapping) = value {
                        // Assert that the mapping contains expected keys
                        assert!(
                            !outer_mapping.is_empty(),
                            "Outer mapping should not be empty"
                        );

                        // The extracted content includes the "env:" key, so we need to look inside it
                        if let Some(env_value) =
                            outer_mapping.get(serde_yaml::Value::String("env".to_string()))
                        {
                            if let serde_yaml::Value::Mapping(env_mapping) = env_value {
                                // Verify that we can iterate over the env mapping
                                let mut found_identity = false;
                                for (k, _v) in env_mapping {
                                    if let serde_yaml::Value::String(key_str) = k {
                                        if key_str == "IDENTITY" {
                                            found_identity = true;
                                        }
                                    }
                                }
                                assert!(found_identity, "Should find IDENTITY key in env mapping");
                            } else {
                                panic!("Env value should be a mapping");
                            }
                        } else {
                            panic!("Should find env key in outer mapping");
                        }
                    } else {
                        panic!(
                            "Env content should parse as a mapping. Actual content: {:?}",
                            env_content
                        );
                    }
                }
                Err(e) => {
                    panic!(
                        "Env content should parse as valid YAML: {}. Actual content: {:?}",
                        e, env_content
                    );
                }
            }
        } else {
            panic!("Should be able to query env section");
        }

        // Test the MergeInto operation
        let new_env = {
            let mut map = serde_yaml::Mapping::new();
            map.insert(
                serde_yaml::Value::String("STEPS_META_OUTPUTS_TAGS".to_string()),
                serde_yaml::Value::String("${{ steps.meta.outputs.tags }}".to_string()),
            );
            map
        };

        let operations = vec![Patch {
            route: route!("jobs", "test", "steps", 0),
            operation: Op::MergeInto {
                key: "env".to_string(),
                value: serde_yaml::Value::Mapping(new_env),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r#"
        name: Test
        on: push
        permissions: {}
        jobs:
          test:
            runs-on: ubuntu-latest
            permissions: {}
            steps:
              - name: Multiline step with env
                run: |
                  echo "${{ steps.meta.outputs.tags }}" | xargs -I {} echo {}
                env:
                  IDENTITY: ${{ secrets.IDENTITY }}
                  STEPS_META_OUTPUTS_TAGS: ${{ steps.meta.outputs.tags }}
                shell: bash
        "#);
    }

    #[test]
    fn test_merge_into_complex_env_mapping() {
        // Test merging into an existing env section with multiple variables
        let original = r#"jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Test step
        run: echo "hello"
        env:
          IDENTITY: ${{ secrets.IDENTITY }}
          OIDC_ISSUER_URL: ${{ secrets.OIDC_ISSUER_URL }}
        shell: bash"#;

        let new_env = {
            let mut map = serde_yaml::Mapping::new();
            map.insert(
                serde_yaml::Value::String("STEPS_META_OUTPUTS_TAGS".to_string()),
                serde_yaml::Value::String("${{ steps.meta.outputs.tags }}".to_string()),
            );
            map
        };

        let operations = vec![Patch {
            route: route!("jobs", "test", "steps", 0),
            operation: Op::MergeInto {
                key: "env".to_string(),
                value: serde_yaml::Value::Mapping(new_env),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        // Should only have one env: key
        assert_eq!(result.source().matches("env:").count(), 1);
        insta::assert_snapshot!(result.source(), @r#"
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Test step
                run: echo "hello"
                env:
                  IDENTITY: ${{ secrets.IDENTITY }}
                  OIDC_ISSUER_URL: ${{ secrets.OIDC_ISSUER_URL }}
                  STEPS_META_OUTPUTS_TAGS: ${{ steps.meta.outputs.tags }}
                shell: bash
        "#);
    }

    #[test]
    fn test_merge_into_reuses_existing_key_no_duplicates() {
        // Test that MergeInto reuses an existing key instead of creating duplicates
        let original = r#"jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Test step
        run: echo "hello"
        env:
          EXISTING_VAR: existing_value
          ANOTHER_VAR: another_value"#;

        let operations = vec![Patch {
            route: route!("jobs", "test", "steps", 0),
            operation: Op::MergeInto {
                key: "env".to_string(),
                value: serde_yaml::Value::Mapping({
                    let mut map = serde_yaml::Mapping::new();
                    map.insert(
                        serde_yaml::Value::String("NEW_VAR".to_string()),
                        serde_yaml::Value::String("new_value".to_string()),
                    );
                    map
                }),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r#"
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Test step
                run: echo "hello"
                env:
                  EXISTING_VAR: existing_value
                  ANOTHER_VAR: another_value
                  NEW_VAR: new_value
        "#);
    }

    #[test]
    fn test_merge_into_with_mapping_merge_behavior() {
        // Test what true merging behavior would look like for mappings
        // This test documents what merging behavior could be if implemented
        let original = r#"jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Test step
        run: echo "hello"
        env:
          EXISTING_VAR: existing_value
          KEEP_THIS: keep_value"#;

        // Apply multiple MergeInto operations to see how they interact
        let operations = vec![
            Patch {
                route: route!("jobs", "test", "steps", 0),
                operation: Op::MergeInto {
                    key: "env".to_string(),
                    value: serde_yaml::Value::Mapping({
                        let mut map = serde_yaml::Mapping::new();
                        map.insert(
                            serde_yaml::Value::String("NEW_VAR_1".to_string()),
                            serde_yaml::Value::String("new_value_1".to_string()),
                        );
                        map
                    }),
                },
            },
            Patch {
                route: route!("jobs", "test", "steps", 0),
                operation: Op::MergeInto {
                    key: "env".to_string(),
                    value: serde_yaml::Value::Mapping({
                        let mut map = serde_yaml::Mapping::new();
                        map.insert(
                            serde_yaml::Value::String("NEW_VAR_2".to_string()),
                            serde_yaml::Value::String("new_value_2".to_string()),
                        );
                        map
                    }),
                },
            },
        ];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r#"
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Test step
                run: echo "hello"
                env:
                  EXISTING_VAR: existing_value
                  KEEP_THIS: keep_value
                  NEW_VAR_1: new_value_1
                  NEW_VAR_2: new_value_2
        "#);
    }

    #[test]
    fn test_merge_into_key_reuse_with_different_value_types() {
        // Test MergeInto behavior when existing key has different value type
        let original = r#"jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Test step
        run: echo "hello"
        shell: bash"#;

        // Try to merge a mapping into a step that has a shell key with string value
        let operations = vec![Patch {
            route: route!("jobs", "test", "steps", 0),
            operation: Op::MergeInto {
                key: "env".to_string(),
                value: serde_yaml::Value::Mapping({
                    let mut map = serde_yaml::Mapping::new();
                    map.insert(
                        serde_yaml::Value::String("GITHUB_REF_NAME".to_string()),
                        serde_yaml::Value::String("${{ github.ref_name }}".to_string()),
                    );
                    map
                }),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r#"
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Test step
                run: echo "hello"
                shell: bash
                env:
                  GITHUB_REF_NAME: ${{ github.ref_name }}
        "#);
    }

    #[test]
    fn test_mixed_flow_block_styles_github_workflow() {
        // GitHub Action workflow with mixed flow and block styles similar to the user's example
        let original = r#"
name: CI
on:
  push:
    branches: [main]   # Flow sequence inside block mapping
  pull_request: { branches: [main, develop] }  # Flow mapping with flow sequence

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - { os: ubuntu-latest, node: 18 }  # Flow mapping in block list
          - os: macos-latest                 # Block mapping in block list
            node: 20
            extra_flags: ["--verbose"]       # Flow sequence in block mapping
          - { os: windows-latest, node: 16, extra_flags: ["--silent", "--prod"] }  # Mixed flow
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with: { fetch-depth: 0 }           # Flow mapping in block context
      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node }}
          cache: npm
"#;

        // Test adding to the flow mapping in pull_request trigger
        let operations = vec![Patch {
            route: route!("on", "pull_request"),
            operation: Op::Add {
                key: "types".to_string(),
                value: serde_yaml::Value::Sequence(vec![
                    serde_yaml::Value::String("opened".to_string()),
                    serde_yaml::Value::String("synchronize".to_string()),
                ]),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r#"
        name: CI
        on:
          push:
            branches: [main]   # Flow sequence inside block mapping
          pull_request: { branches: [main, develop], types: [opened, synchronize] }  # Flow mapping with flow sequence

        jobs:
          test:
            runs-on: ubuntu-latest
            strategy:
              matrix:
                include:
                  - { os: ubuntu-latest, node: 18 }  # Flow mapping in block list
                  - os: macos-latest                 # Block mapping in block list
                    node: 20
                    extra_flags: ["--verbose"]       # Flow sequence in block mapping
                  - { os: windows-latest, node: 16, extra_flags: ["--silent", "--prod"] }  # Mixed flow
            steps:
              - name: Checkout
                uses: actions/checkout@v4
                with: { fetch-depth: 0 }           # Flow mapping in block context
              - name: Setup Node
                uses: actions/setup-node@v4
                with:
                  node-version: ${{ matrix.node }}
                  cache: npm
        "#);
    }

    #[test]
    fn test_replace_value_in_flow_mapping_within_block_context() {
        let original = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Test step
        with: { timeout: 300 }
"#;

        let operations = vec![Patch {
            route: route!("jobs", "test", "steps", 0, "with", "timeout"),
            operation: Op::Replace(serde_yaml::Value::Number(serde_yaml::Number::from(600))),
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r#"
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Test step
                with: { timeout: 600 }
        "#);
    }

    #[test]
    fn test_add_nested_mapping_with_comments() {
        let original = r#"
foo:
  bar:
    baz: abc # comment
    # another comment
# some nonsense here
"#;

        let operations = vec![Patch {
            route: route!("foo", "bar"),
            operation: Op::Add {
                key: "qux".to_string(),
                value: serde_yaml::Value::String("xyz".to_string()),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r"
        foo:
          bar:
            baz: abc # comment
            qux: xyz
            # another comment
        # some nonsense here
        ");
    }

    #[test]
    fn test_add_to_block_mapping_in_block_list() {
        let original = r#"
matrix:
  include:
    - os: ubuntu-latest
      node: 18
    - os: macos-latest
      node: 20
"#;

        let operations = vec![Patch {
            route: route!("matrix", "include", 0),
            operation: Op::Add {
                key: "arch".to_string(),
                value: serde_yaml::Value::String("x64".to_string()),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r"
        matrix:
          include:
            - os: ubuntu-latest
              node: 18
              arch: x64
            - os: macos-latest
              node: 20
        ");
    }

    #[test]
    fn test_add_to_block_mapping_in_block_list_funky_indentation() {
        let original = r#"
matrix:
   include:
      -   os: ubuntu-latest
          node: 18
      -   os: macos-latest
          node: 20
"#;

        let operations = vec![Patch {
            route: route!("matrix", "include", 0),
            operation: Op::Add {
                key: "arch".to_string(),
                value: serde_yaml::Value::String("x64".to_string()),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r"
        matrix:
           include:
              -   os: ubuntu-latest
                  node: 18
                  arch: x64
              -   os: macos-latest
                  node: 20
        ");
    }

    #[test]
    fn test_add_to_flow_mapping_nested_in_block_list() {
        let original = r#"
strategy:
  matrix:
    include:
      - { os: ubuntu-latest, node: 18 }
      - { os: macos-latest, node: 20 }
"#;

        let operations = vec![Patch {
            route: route!("strategy", "matrix", "include", 0),
            operation: Op::Add {
                key: "arch".to_string(),
                value: serde_yaml::Value::String("x64".to_string()),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r"
        strategy:
          matrix:
            include:
              - { os: ubuntu-latest, node: 18, arch: x64 }
              - { os: macos-latest, node: 20 }
        ");
    }

    #[test]
    fn test_add_to_flow_mapping_trailing_comma() {
        let original = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    env: { NODE_ENV: "production", DEBUG: "true", }
"#;

        let operations = vec![Patch {
            route: route!("jobs", "test", "env"),
            operation: Op::Add {
                key: "LOG_LEVEL".to_string(),
                value: serde_yaml::Value::String("info".to_string()),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r"
        jobs:
          test:
            runs-on: ubuntu-latest
            env: { NODE_ENV: production, DEBUG: true, LOG_LEVEL: info }
        ");
    }

    #[test]
    fn test_add_to_flow_mapping_trailing_comment() {
        let original = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    env: { NODE_ENV: "production", DEBUG: "true" } # trailing comment
"#;

        let operations = vec![Patch {
            route: route!("jobs", "test", "env"),
            operation: Op::Add {
                key: "LOG_LEVEL".to_string(),
                value: serde_yaml::Value::String("info".to_string()),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        // The trailing comment should be preserved after the mapping
        insta::assert_snapshot!(result.source(), @r"
        jobs:
          test:
            runs-on: ubuntu-latest
            env: { NODE_ENV: production, DEBUG: true, LOG_LEVEL: info } # trailing comment
        ");
    }

    #[test]
    #[ignore = "known issue"]
    fn test_add_to_multiline_flow_mapping() {
        let original = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    env: {
      NODE_ENV: "production",
      DEBUG: "true"
    }
"#;

        let operations = vec![Patch {
            route: route!("jobs", "test", "env"),
            operation: Op::Add {
                key: "LOG_LEVEL".to_string(),
                value: serde_yaml::Value::String("info".to_string()),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r#"
        jobs:
          test:
            runs-on: ubuntu-latest
            env: {
              NODE_ENV: "production",
              DEBUG: "true",
              LOG_LEVEL: "info"
            }
        "#);
    }

    #[test]
    #[ignore = "known issue"]
    fn test_add_to_multiline_flow_mapping_funky() {
        let original = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    env: {
      NODE_ENV: "production", DEBUG: "true",
      BLAH: xyz
    }
"#;

        let operations = vec![Patch {
            route: route!("jobs", "test", "env"),
            operation: Op::Add {
                key: "LOG_LEVEL".to_string(),
                value: serde_yaml::Value::String("info".to_string()),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r#"
        jobs:
          test:
            runs-on: ubuntu-latest
            env: {
              NODE_ENV: "production",
              DEBUG: "true",
              BLAH: xyz,
              LOG_LEVEL: "info"
            }
        "#);
    }

    #[test]
    fn test_add_complex_mixed_styles_permissions() {
        let original = r#"
permissions:
  contents: read
  actions: { read: true, write: false }  # Flow mapping in block context
  packages: write
"#;

        let operations = vec![Patch {
            route: route!("permissions", "actions"),
            operation: Op::Add {
                key: "delete".to_string(),
                value: serde_yaml::Value::Bool(true),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r#"
        permissions:
          contents: read
          actions: { read: true, write: false, delete: true }  # Flow mapping in block context
          packages: write
        "#);
    }

    #[test]
    fn test_add_preserve_flow_sequence_in_block_mapping() {
        let original = r#"
on:
  push:
    branches: [main, develop]
  schedule:
    - cron: "0 0 * * *"
"#;

        let operations = vec![Patch {
            route: route!("on", "push"),
            operation: Op::Add {
                key: "tags".to_string(),
                value: serde_yaml::Value::Sequence(vec![serde_yaml::Value::String(
                    "v*".to_string(),
                )]),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r#"
        on:
          push:
            branches: [main, develop]
            tags: ["v*"]
          schedule:
            - cron: "0 0 * * *"
        "#);
    }

    #[test]
    fn test_add_empty_flow_mapping_expansion() {
        let original = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    env: {}
    steps:
      - run: echo "test"
"#;

        let operations = vec![Patch {
            route: route!("jobs", "test", "env"),
            operation: Op::Add {
                key: "NODE_ENV".to_string(),
                value: serde_yaml::Value::String("test".to_string()),
            },
        }];

        let result =
            apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

        insta::assert_snapshot!(result.source(), @r#"
        jobs:
          test:
            runs-on: ubuntu-latest
            env: { NODE_ENV: test }
            steps:
              - run: echo "test"
        "#);
    }
}
