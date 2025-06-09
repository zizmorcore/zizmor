//! Comment and format-preserving YAML patch operations.

use std::borrow::Cow;

use crate::finding::location::{Route, RouteComponent};

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

/// Represents different YAML style formats for collections and scalars
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum YamlStyle {
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
    /// An empty feature, e.g. the value part of `foo:`
    Empty,
}

impl YamlStyle {
    /// Detect the YAML style of a value from its string representation
    ///
    /// Assumes that [`content`] is a well-formed YAML serialization.
    pub fn detect(route: &Route, doc: &yamlpath::Document) -> Result<Self, Error> {
        let Some(feature) = route_to_feature_exact(&route, &doc)? else {
            return Ok(YamlStyle::Empty);
        };

        let content = doc.extract(&feature);
        let trimmed = content.trim().as_bytes();
        let multiline = trimmed.contains(&b'\n');

        match feature.kind() {
            yamlpath::FeatureKind::BlockMapping => Ok(YamlStyle::BlockMapping),
            yamlpath::FeatureKind::BlockSequence => Ok(YamlStyle::BlockSequence),
            yamlpath::FeatureKind::FlowMapping => {
                if multiline {
                    Ok(YamlStyle::MultilineFlowMapping)
                } else {
                    Ok(YamlStyle::FlowMapping)
                }
            }
            yamlpath::FeatureKind::FlowSequence => {
                if multiline {
                    Ok(YamlStyle::MultilineFlowSequence)
                } else {
                    Ok(YamlStyle::FlowSequence)
                }
            }
            yamlpath::FeatureKind::Scalar => match trimmed[0] {
                b'|' => Ok(YamlStyle::MultilineLiteralScalar),
                b'>' => Ok(YamlStyle::MultilineFoldedScalar),
                b'"' => Ok(YamlStyle::DoubleQuoted),
                b'\'' => Ok(YamlStyle::SingleQuoted),
                _ => Ok(YamlStyle::PlainScalar),
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
    /// Add a new key-value pair at the given path. The path should point to a mapping,
    /// or use "/" for root-level additions. Maintains proper indentation and formatting.
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

/// Apply YAML patch operations while preserving comments and formatting
///
/// This function takes a YAML string and a list of patch operations, applying them
/// while preserving all comments, formatting, and structure that isn't directly modified.
///
/// # Operation Order
///
/// Operations are internally sorted by their byte positions and applied from the end
/// of the document backwards to avoid invalidating byte positions during modification.
/// This means the logical order of operations in the input vector is preserved, but
/// the actual application order is optimized for correctness.
///
/// # Error Handling
///
/// Returns an error if:
/// - The input YAML is not valid
/// - Any path in the operations is invalid or not found
/// - YAML serialization fails during value conversion
pub fn apply_yaml_patches(content: &str, patches: &[Patch]) -> Result<String, Error> {
    // Validate that the input YAML is parseable before attempting patches
    if let Err(e) = serde_yaml::from_str::<serde_yaml::Value>(content) {
        return Err(Error::InvalidOperation(format!(
            "input is not valid YAML: {}",
            e
        )));
    }

    let mut result = content.to_string();

    // Sort operations by byte position (reverse order) so we can apply them without
    // invalidating subsequent positions
    let mut positioned_ops = Vec::new();

    for patch in patches {
        let doc = yamlpath::Document::new(&result)?;
        let feature = route_to_feature_pretty(&patch.route, &doc)?;
        positioned_ops.push((feature.location.byte_span.0, patch));
    }

    // Sort by position (descending) so we apply changes from end to beginning
    positioned_ops.sort_by(|a, b| b.0.cmp(&a.0));

    for (_, op) in positioned_ops {
        result = apply_single_patch(&result, op)?;
    }

    Ok(result)
}

/// Apply a single YAML patch operation
fn apply_single_patch(content: &str, patch: &Patch) -> Result<String, Error> {
    let doc = yamlpath::Document::new(content)?;

    match &patch.operation {
        Op::RewriteFragment { from, to, after } => {
            let Some(feature) = route_to_feature_exact(&patch.route, &doc)? else {
                return Err(Error::InvalidOperation(format!(
                    "no pre-existing value to patch at {route:?}",
                    route = patch.route
                )));
            };

            let extracted_feature = doc.extract(&feature);

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

            Ok(patched_content)
        }
        Op::Replace(value) => {
            let feature = route_to_feature_pretty(&patch.route, &doc)?;

            // Get the replacement content
            let replacement = apply_value_replacement(content, &feature, &doc, value, true)?;

            // Extract the current content to calculate spans
            let current_content = doc.extract(&feature);
            let current_content_with_ws = doc.extract_with_leading_whitespace(&feature);

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
            Ok(result)
        }

        Op::Add { key, value } => {
            if patch.route.is_root() {
                // Handle root-level additions specially
                return handle_root_level_addition(content, key, value);
            }

            let feature = route_to_feature_pretty(&patch.route, &doc)?;

            // Detect the target's YAML style
            let current_content = doc.extract(&feature);
            let target_style = YamlStyle::detect(&patch.route, &doc)?;

            // Check if we're adding to a flow mapping
            if target_style == YamlStyle::FlowMapping {
                return handle_flow_mapping_addition(content, &feature, key, value);
            }

            // Convert the new value to YAML string for block style handling
            let new_value_str = if matches!(value, serde_yaml::Value::Sequence(_)) {
                // For sequences, use flow-aware serialization to maintain consistency
                serialize_yaml_value_for_flow_context(value)?
            } else {
                serialize_yaml_value(value)?
            };
            let new_value_str = new_value_str.trim_end(); // Remove trailing newline

            // Check if we're adding to a list item by examining the path
            let is_list_item = matches!(patch.route.last(), Some(RouteComponent::Index(_)));

            // Determine the appropriate indentation
            let indent = if is_list_item {
                // For list items, we need to match the indentation of other keys in the same item
                // The feature extraction gives us the content without the leading "- " part,
                // so we need to use the leading whitespace of the step itself plus 2 spaces
                let leading_whitespace =
                    extract_leading_whitespace(content, feature.location.byte_span.0);
                format!("{}  ", leading_whitespace)
            } else {
                // For regular mappings, add 2 spaces to current indentation
                let leading_whitespace =
                    extract_leading_whitespace(content, feature.location.byte_span.0);
                format!("{}  ", leading_whitespace)
            };

            // Format the new entry
            let final_entry = if let serde_yaml::Value::Mapping(mapping) = &value {
                if mapping.is_empty() {
                    // For empty mappings, format inline
                    format!("\n{}{}: {}", indent, key, new_value_str)
                } else {
                    // For non-empty mappings, format as a nested structure
                    let value_lines: Vec<&str> = new_value_str.lines().collect();
                    let mut result = format!("\n{}{}:", indent, key);
                    for line in value_lines.iter() {
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
                format!("\n{}{}: {}", indent, key, indented_value)
            } else {
                format!("\n{}{}: {}", indent, key, new_value_str)
            };

            // Find the insertion point
            let insertion_point = if is_list_item {
                // For list items, we need to find the end of the actual step content,
                // not including trailing comments that yamlpath may have included
                find_step_content_end(content, &feature, &doc)
            } else {
                feature.location.byte_span.1
            };

            // Check if we need to add a newline before the entry
            // If the content at insertion point already ends with a newline, don't add another
            let needs_leading_newline = if insertion_point > 0 {
                content.chars().nth(insertion_point - 1) != Some('\n')
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

            // Insert the new entry
            let mut result = content.to_string();
            result.insert_str(insertion_point, &final_entry_to_insert);
            Ok(result)
        }

        Op::MergeInto { key, value } => {
            if patch.route.is_root() {
                // Handle root-level merges specially
                return handle_root_level_addition(content, key, value);
            }

            // Check if the key already exists in the target mapping
            let existing_key_route = patch.route.with_keys(&[key.as_str().into()]);

            if let Ok(existing_feature) = route_to_feature_pretty(&existing_key_route, &doc) {
                // Key exists, check if we need to merge mappings
                if let serde_yaml::Value::Mapping(new_mapping) = &value {
                    // Try to parse the existing value as YAML to see if it's also a mapping
                    let existing_content = doc.extract(&existing_feature);
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
                                content,
                                &existing_key_route,
                                key,
                                &serde_yaml::Value::Mapping(merged_mapping),
                            );
                        }
                    }
                }

                // Not both mappings, or parsing failed, just replace
                return apply_single_patch(
                    content,
                    &Patch {
                        route: existing_key_route,
                        operation: Op::Replace(value.clone()),
                    },
                );
            }

            // Key doesn't exist, add it using Add operation
            apply_single_patch(
                content,
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

            let feature = route_to_feature_pretty(&patch.route, &doc)?;

            // For removal, we need to remove the entire line including leading whitespace
            let start_pos = find_line_start(content, feature.location.byte_span.0);
            let end_pos = find_line_end(content, feature.location.byte_span.1);

            let mut result = content.to_string();
            result.replace_range(start_pos..end_pos, "");
            Ok(result)
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

/// Serialize a serde_yaml::Value to a YAML string in flow style for sequences when in flow context
fn serialize_yaml_value_for_flow_context(value: &serde_yaml::Value) -> Result<String, Error> {
    match value {
        serde_yaml::Value::Sequence(seq) => {
            // Serialize sequence in flow style: [item1, item2, item3]
            let items: Result<Vec<String>, Error> = seq
                .iter()
                .map(|item| {
                    match item {
                        serde_yaml::Value::String(s) => Ok(s.clone()),
                        serde_yaml::Value::Number(n) => Ok(n.to_string()),
                        serde_yaml::Value::Bool(b) => Ok(b.to_string()),
                        serde_yaml::Value::Null => Ok("null".to_string()),
                        _ => {
                            // For complex nested values, serialize them normally
                            let serialized = serde_yaml::to_string(item)?;
                            Ok(serialized.trim().to_string())
                        }
                    }
                })
                .collect();

            let items = items?;
            Ok(format!("[{}]", items.join(", ")))
        }
        _ => {
            // For non-sequences, use normal serialization
            serialize_yaml_value(value)
        }
    }
}

/// Extract leading whitespace from the beginning of the line containing the given position
fn extract_leading_whitespace(content: &str, pos: usize) -> String {
    let line_start = find_line_start(content, pos);
    let line_content = &content[line_start..];

    line_content
        .chars()
        .take_while(|&c| c == ' ' || c == '\t')
        .collect()
}

/// Find the start of the line containing the given position
fn find_line_start(content: &str, pos: usize) -> usize {
    content[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0)
}

/// Find the end of the line containing the given position
fn find_line_end(content: &str, pos: usize) -> usize {
    content[pos..]
        .find('\n')
        .map(|i| pos + i + 1)
        .unwrap_or(content.len())
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

/// Handle adding a key-value pair to a flow mapping while preserving flow style
fn handle_flow_mapping_addition(
    content: &str,
    feature: &yamlpath::Feature,
    key: &str,
    value: &serde_yaml::Value,
) -> Result<String, Error> {
    let current_content =
        content[feature.location.byte_span.0..feature.location.byte_span.1].to_string();

    // Find the closing brace position
    let closing_brace_pos = current_content.rfind('}').ok_or_else(|| {
        Error::InvalidOperation("No closing brace found in flow mapping".to_string())
    })?;

    // Check if the mapping is empty (just has { })
    let content_inside_braces =
        &current_content[current_content.find('{').unwrap() + 1..closing_brace_pos].trim();
    let is_empty = content_inside_braces.is_empty();

    // Serialize the new value using flow context-aware serialization
    let new_value_str = serialize_yaml_value_for_flow_context(value)?;
    let new_value_str = new_value_str.trim();

    // Create the new key-value pair
    let new_pair = format!("{}: {}", key, new_value_str);

    // Create the updated flow mapping content
    let updated_content = if is_empty {
        // Empty mapping: { } -> { key: value }
        current_content.replace("{}", &format!("{{ {} }}", new_pair))
    } else {
        // Non-empty mapping: { existing } -> { existing, key: value }
        let before_brace = &current_content[..closing_brace_pos].trim_end();
        let after_brace = &current_content[closing_brace_pos..];

        // Standard flow mapping format: { key1: val1, key2: val2 }
        format!("{}, {} {}", before_brace, new_pair, after_brace)
    };

    // Replace the content in the document
    let mut result = content.to_string();
    result.replace_range(
        feature.location.byte_span.0..feature.location.byte_span.1,
        &updated_content,
    );
    Ok(result)
}

/// Find the end of actual step content, excluding trailing comments
#[allow(clippy::needless_range_loop)]
fn find_step_content_end(
    _content: &str,
    feature: &yamlpath::Feature,
    doc: &yamlpath::Document,
) -> usize {
    let feature_content = doc.extract(feature);
    let feature_start = feature.location.byte_span.0;

    // Split the feature content into lines to analyze
    let lines: Vec<&str> = feature_content.lines().collect();

    // Find the last line that contains actual YAML content (not a comment or empty line)
    for (i, line) in lines.iter().enumerate().rev() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            // This is the last line with actual content
            // Calculate its position relative to the start of the feature
            let mut current_pos = 0;

            for j in 0..=i {
                if j == i {
                    // This is our target line, find the end of it
                    current_pos += lines[j].len();
                    return feature_start + current_pos;
                } else {
                    current_pos += lines[j].len() + 1; // +1 for newline
                }
            }
        }
    }

    // Fallback to original end if no content found
    feature.location.byte_span.1
}

/// Handle root-level additions and merges by finding the best insertion point at the document root
fn handle_root_level_addition(
    content: &str,
    key: &str,
    value: &serde_yaml::Value,
) -> Result<String, Error> {
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

    Ok(result)
}

/// Apply a mapping replacement that preserves the key structure
fn apply_mapping_replacement(
    content: &str,
    route: &Route<'_>,
    _key: &str,
    value: &serde_yaml::Value,
) -> Result<String, Error> {
    let doc = yamlpath::Document::new(content)?;
    let feature = route_to_feature_pretty(route, &doc)?;

    // Extract the current content to see what we're working with
    let current_content_with_ws = doc.extract_with_leading_whitespace(&feature);

    // Check if this is a flow mapping that should be handled specially
    let trimmed_content = current_content_with_ws.trim();
    let is_flow_mapping = trimmed_content.starts_with('{')
        && trimmed_content.ends_with('}')
        && !trimmed_content.contains('\n');

    if is_flow_mapping {
        // For flow mappings, use the existing flow mapping logic
        let replacement = apply_value_replacement(content, &feature, &doc, value, false)?;
        let mut result = content.to_string();
        result.replace_range(
            feature.location.byte_span.0..feature.location.byte_span.1,
            &replacement,
        );
        return Ok(result);
    }

    // For block mappings, we need to preserve the structure properly
    if let Some(colon_pos) = current_content_with_ws.find(':') {
        // This is a key-value pair like "env:\n  EXISTING_VAR: value"
        let key_part = &current_content_with_ws[..colon_pos + 1]; // "env:"

        // Get the indentation level for the mapping content
        let leading_whitespace = extract_leading_whitespace(content, feature.location.byte_span.0);
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

        let mut result = content.to_string();
        result.replace_range(ws_start..feature.location.byte_span.1, &replacement);
        Ok(result)
    } else {
        // Not a key-value pair, use regular value replacement
        let replacement = apply_value_replacement(content, &feature, &doc, value, false)?;
        let mut result = content.to_string();
        result.replace_range(
            feature.location.byte_span.0..feature.location.byte_span.1,
            &replacement,
        );
        Ok(result)
    }
}

/// Apply a value replacement at the given feature location, preserving key structure and formatting
fn apply_value_replacement(
    content: &str,
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
            content,
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
                        let leading_whitespace =
                            extract_leading_whitespace(content, feature.location.byte_span.0);
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
        let val_str = serialize_yaml_value(value)?;
        val_str
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
    fn test_detect_yaml_style() {
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
            (route!("block-mapping-a"), YamlStyle::BlockMapping),
            (route!("block-mapping-b"), YamlStyle::BlockMapping),
            (route!("block-sequence-a"), YamlStyle::BlockSequence),
            (route!("block-sequence-b"), YamlStyle::BlockSequence),
            (route!("flow-mapping-a"), YamlStyle::FlowMapping),
            (route!("flow-mapping-b"), YamlStyle::FlowMapping),
            (route!("flow-mapping-c"), YamlStyle::MultilineFlowMapping),
            (route!("flow-mapping-d"), YamlStyle::MultilineFlowMapping),
            (route!("flow-mapping-e"), YamlStyle::MultilineFlowMapping),
            (route!("flow-mapping-f"), YamlStyle::FlowMapping),
            (route!("flow-mapping-g"), YamlStyle::FlowMapping),
            (route!("flow-sequence-a"), YamlStyle::FlowSequence),
            (route!("flow-sequence-b"), YamlStyle::FlowSequence),
            (route!("flow-sequence-c"), YamlStyle::MultilineFlowSequence),
            (route!("flow-sequence-d"), YamlStyle::MultilineFlowSequence),
            (route!("scalars", 0), YamlStyle::PlainScalar),
            (route!("scalars", 1), YamlStyle::PlainScalar),
            (route!("scalars", 2), YamlStyle::DoubleQuoted),
            (route!("scalars", 3), YamlStyle::SingleQuoted),
            (route!("scalars", 4), YamlStyle::PlainScalar),
            (route!("scalars", 5), YamlStyle::SingleQuoted),
            (route!("scalars", 6), YamlStyle::SingleQuoted),
            (route!("scalars", 7), YamlStyle::PlainScalar),
            (
                route!("multiline-scalars", "literal-a"),
                YamlStyle::MultilineLiteralScalar,
            ),
            (
                route!("multiline-scalars", "literal-b"),
                YamlStyle::MultilineLiteralScalar,
            ),
            (
                route!("multiline-scalars", "literal-c"),
                YamlStyle::MultilineLiteralScalar,
            ),
            (
                route!("multiline-scalars", "literal-d"),
                YamlStyle::MultilineLiteralScalar,
            ),
            (
                route!("multiline-scalars", "literal-e"),
                YamlStyle::MultilineLiteralScalar,
            ),
            (
                route!("multiline-scalars", "folded-a"),
                YamlStyle::MultilineFoldedScalar,
            ),
            (
                route!("multiline-scalars", "folded-b"),
                YamlStyle::MultilineFoldedScalar,
            ),
            (
                route!("multiline-scalars", "folded-c"),
                YamlStyle::MultilineFoldedScalar,
            ),
            (
                route!("multiline-scalars", "folded-d"),
                YamlStyle::MultilineFoldedScalar,
            ),
            (
                route!("multiline-scalars", "folded-e"),
                YamlStyle::MultilineFoldedScalar,
            ),
            (route!("empty", "foo"), YamlStyle::Empty),
        ] {
            let style = YamlStyle::detect(&route, &doc).unwrap();
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
    fn test_yaml_path_rewrite_fragment_single_line() {
        let original = r#"
foo:
  bar: 'echo "foo: ${{ foo }}"'
"#;

        let operations = vec![Patch {
            route: route!("foo", "bar"),
            operation: Op::RewriteFragment {
                from: "${{ foo }}".into(),
                to: "${FOO}".into(),
                after: None,
            },
        }];

        let result = apply_yaml_patches(original, &operations).unwrap();

        insta::assert_snapshot!(result, @r#"
        foo:
          bar: 'echo "foo: ${FOO}"'
        "#);
    }

    #[test]
    fn test_yaml_path_rewrite_fragment_multi_line() {
        let original = r#"
foo:
  bar: |
    echo "foo: ${{ foo }}"
    echo "bar: ${{ bar }}"
    echo "foo: ${{ foo }}"
"#;

        // Only the first occurrence of `from` should be replaced
        let operations = vec![Patch {
            route: route!("foo", "bar"),
            operation: Op::RewriteFragment {
                from: "${{ foo }}".into(),
                to: "${FOO}".into(),
                after: None,
            },
        }];

        let result = apply_yaml_patches(original, &operations).unwrap();

        insta::assert_snapshot!(result, @r#"
        foo:
          bar: |
            echo "foo: ${FOO}"
            echo "bar: ${{ bar }}"
            echo "foo: ${{ foo }}"
        "#);

        // Now test with not_before set to skip the first occurrence
        let operations = vec![Patch {
            route: route!("foo", "bar"),
            operation: Op::RewriteFragment {
                from: "${{ foo }}".into(),
                to: "${FOO}".into(),
                after: original.find("${{ foo }}").map(|idx| idx + 1),
            },
        }];

        let result = apply_yaml_patches(original, &operations).unwrap();

        insta::assert_snapshot!(result, @r#"
        foo:
          bar: |
            echo "foo: ${{ foo }}"
            echo "bar: ${{ bar }}"
            echo "foo: ${FOO}"
        "#);
    }

    #[test]
    fn test_yaml_path_rewrite_fragment_multi_line_in_list() {
        let original = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "foo: ${{ foo }}"
          echo "bar: ${{ bar }}"
        "#;

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

        let result = apply_yaml_patches(original, &operations).unwrap();

        insta::assert_snapshot!(result, @r#"
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
    fn test_yaml_path_replace_empty_block_value() {
        let original = r#"
foo:
  bar:
"#;

        let operations = vec![Patch {
            route: route!("foo", "bar"),
            operation: Op::Replace(serde_yaml::Value::String("abc".to_string())),
        }];

        let result = apply_yaml_patches(original, &operations).unwrap();

        insta::assert_snapshot!(result, @r"
        foo:
          bar: abc
        ");
    }

    #[test]
    fn test_yaml_path_replace_empty_flow_value() {
        let original = r#"
    foo: { bar: }
    "#;

        let patches = vec![Patch {
            route: route!("foo", "bar"),
            operation: Op::Replace(serde_yaml::Value::String("abc".to_string())),
        }];

        let result = apply_yaml_patches(original, &patches).unwrap();

        insta::assert_snapshot!(result, @r"foo: { bar: abc }");
    }

    #[test]
    fn test_yaml_path_replace_empty_flow_value_no_colon() {
        let original = r#"
        foo: { bar }
        "#;

        let patches = vec![Patch {
            route: route!("foo", "bar"),
            operation: Op::Replace(serde_yaml::Value::String("abc".to_string())),
        }];

        let result = apply_yaml_patches(original, &patches).unwrap();

        insta::assert_snapshot!(result, @r"foo: { bar: abc }");
    }

    #[test]
    fn test_yaml_path_replace_multiline_string() {
        let original = r#"
foo:
  bar:
    baz: |
      Replace me.
      Replace me too.
"#;

        let operations = vec![Patch {
            route: route!("foo", "bar", "baz"),
            operation: Op::Replace("New content.\nMore new content.\n".into()),
        }];

        let result = apply_yaml_patches(original, &operations).unwrap();

        insta::assert_snapshot!(result, @r"
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

        let operations = vec![Patch {
            route: route!("permissions", "contents"),
            operation: Op::Replace(serde_yaml::Value::String("write".to_string())),
        }];

        let result = apply_yaml_patches(original, &operations).unwrap();

        // Preserves all comments, but changes the value of `contents`
        insta::assert_snapshot!(result, @r"
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
    fn test_yaml_patch_add_preserves_formatting() {
        let original = r#"
permissions:
  contents: read
  actions: write
"#;

        let operations = vec![Patch {
            route: route!("permissions"),
            operation: Op::Add {
                key: "issues".to_string(),
                value: serde_yaml::Value::String("read".to_string()),
            },
        }];

        let result = apply_yaml_patches(original, &operations).unwrap();

        // Preserves original content, adds new key while maintaining indentation
        insta::assert_snapshot!(result, @r"
        permissions:
          contents: read
          actions: write
          issues: read
        ");
    }

    #[test]
    fn test_yaml_patch_add_preserves_flow_mapping_formatting() {
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        insta::assert_snapshot!(result, @r#"
        foo: { bar: abc, baz: qux }
        "#);
    }

    #[test]
    fn test_yaml_patch_remove_preserves_structure() {
        let original = r#"
permissions:
  contents: read  # Keep this comment
  actions: write  # Remove this line
  issues: read
"#;

        let operations = vec![Patch {
            route: route!("permissions", "actions"),
            operation: Op::Remove,
        }];

        let result = apply_yaml_patches(original, &operations).unwrap();

        // Preserves other content, removes the target line
        insta::assert_snapshot!(result, @r"
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        // All comments preserved, all changes applied
        insta::assert_snapshot!(result, @r"
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
    fn test_whitespace_extraction() {
        let content = "line1\n  indented\n    more-indented";
        assert_eq!(extract_leading_whitespace(content, 6), "  ");
        assert_eq!(extract_leading_whitespace(content, 17), "    ");
        assert_eq!(extract_leading_whitespace(content, 0), "");
    }

    #[test]
    fn test_line_boundaries() {
        let content = "line1\nline2\nline3";
        assert_eq!(find_line_start(content, 0), 0);
        assert_eq!(find_line_start(content, 3), 0);
        assert_eq!(find_line_start(content, 6), 6);
        assert_eq!(find_line_start(content, 9), 6);

        assert_eq!(find_line_end(content, 0), 6);
        assert_eq!(find_line_end(content, 3), 6);
        assert_eq!(find_line_end(content, 6), 12);
        assert_eq!(find_line_end(content, 15), 17);
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

        let result = apply_yaml_patches(original_yaml, &operations).unwrap();

        insta::assert_snapshot!(result, @r"
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        // Empty mapping should be formatted inline
        insta::assert_snapshot!(result, @r"
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

        let result = apply_yaml_patches(&original_with_newline, &operations).unwrap();

        insta::assert_snapshot!(result, @r#"
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        // The with section should be added to the first step correctly, not mixed with comments
        insta::assert_snapshot!(result, @r#"
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
    fn test_root_level_addition_preserves_formatting() {
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        insta::assert_snapshot!(result, @r"
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
    fn test_root_level_path_handling() {
        // Test that root path "/" is handled correctly
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

        let result = apply_yaml_patches(original, &operations);
        assert!(result.is_ok());

        let result = result.unwrap();
        insta::assert_snapshot!(result, @r"
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        insta::assert_snapshot!(result, @r#"
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

        let result = apply_yaml_patches(original, &operations).unwrap();
        insta::assert_snapshot!(result, @r#"
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        // Should merge the new mapping with the existing one
        insta::assert_snapshot!(result, @r#"
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        // Verify the result is valid YAML
        assert!(serde_yaml::from_str::<serde_yaml::Value>(&result).is_ok());

        // Should only have one env: key
        assert_eq!(result.matches("env:").count(), 1);
        insta::assert_snapshot!(result, @r#"
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        // Verify the result is valid YAML
        assert!(serde_yaml::from_str::<serde_yaml::Value>(&result).is_ok());

        insta::assert_snapshot!(result, @r#"
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
        let leading_ws = extract_leading_whitespace(original, step_feature.location.byte_span.0);
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        // Assert that the result is valid YAML
        assert!(serde_yaml::from_str::<serde_yaml::Value>(&result).is_ok());

        insta::assert_snapshot!(result, @r#"
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        // Verify the result is valid YAML
        assert!(serde_yaml::from_str::<serde_yaml::Value>(&result).is_ok());

        insta::assert_snapshot!(result, @r#"
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        // Verify the result is valid YAML
        assert!(serde_yaml::from_str::<serde_yaml::Value>(&result).is_ok());

        // Should only have one env: key
        assert_eq!(result.matches("env:").count(), 1);
        insta::assert_snapshot!(result, @r#"
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        // Verify the result is valid YAML
        assert!(serde_yaml::from_str::<serde_yaml::Value>(&result).is_ok());

        insta::assert_snapshot!(result, @r#"
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        // Verify the result is valid YAML
        assert!(serde_yaml::from_str::<serde_yaml::Value>(&result).is_ok());

        insta::assert_snapshot!(result, @r#"
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        // Verify the result is valid YAML
        assert!(serde_yaml::from_str::<serde_yaml::Value>(&result).is_ok());

        insta::assert_snapshot!(result, @r#"
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        // Debug: print the result to see what went wrong
        println!("Result:\n{}", result);

        // Verify the result is valid YAML
        if let Err(e) = serde_yaml::from_str::<serde_yaml::Value>(&result) {
            panic!("Invalid YAML: {}", e);
        }

        insta::assert_snapshot!(result, @r#"
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        insta::assert_snapshot!(result, @r#"
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Test step
                with: { timeout: 600 }
        "#);
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        insta::assert_snapshot!(result, @r#"
        strategy:
          matrix:
            include:
              - { os: ubuntu-latest, node: 18, arch: x64 }
              - { os: macos-latest, node: 20 }
        "#);
    }

    #[test]
    #[ignore = "known issue"]
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        insta::assert_snapshot!(result, @r#"
        jobs:
          test:
            runs-on: ubuntu-latest
            env: { NODE_ENV: "production", DEBUG: "true", LOG_LEVEL: "info" }
        "#);
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        assert!(serde_yaml::from_str::<serde_yaml::Value>(&result).is_ok());

        insta::assert_snapshot!(result, @r#"
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        insta::assert_snapshot!(result, @r#"
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
    fn test_complex_mixed_styles_permissions() {
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        insta::assert_snapshot!(result, @r#"
        permissions:
          contents: read
          actions: { read: true, write: false, delete: true }  # Flow mapping in block context
          packages: write
        "#);
    }

    #[test]
    fn test_preserve_flow_sequence_in_block_mapping() {
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        insta::assert_snapshot!(result, @r#"
        on:
          push:
            branches: [main, develop]
            tags: [v*]
          schedule:
            - cron: "0 0 * * *"
        "#);
    }

    #[test]
    fn test_empty_flow_mapping_expansion() {
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

        let result = apply_yaml_patches(original, &operations).unwrap();

        insta::assert_snapshot!(result, @r#"
        jobs:
          test:
            runs-on: ubuntu-latest
            env: { NODE_ENV: test }
            steps:
              - run: echo "test"
        "#);
    }
}
