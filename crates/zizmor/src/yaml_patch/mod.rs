//! Comment and format-preserving YAML patch operations.
//!
//! This module provides functionality to modify YAML documents while preserving
//! comments, formatting, and structure. Unlike standard YAML->JSON->YAML round-trips
//! that lose comments, this implementation uses precise byte-level operations
//! guided by the yamlpath library.
//!
//! # Example
//!
//! ```rust
//! use crate::yaml_patch::{YamlPatchOperation, apply_yaml_patch};
//!
//! let yaml = r#"
//! # Configuration
//! permissions: # Security settings
//!   contents: read  # Only read access
//!   actions: write  # Write access for actions
//! "#;
//!
//! let operations = vec![YamlPatchOperation::Replace {
//!     path: "/permissions/contents".to_string(),
//!     value: serde_yaml::Value::String("write".to_string()),
//! }];
//!
//! let result = apply_yaml_patch(yaml, operations).unwrap();
//! // Comments are preserved!
//! ```

use anyhow::Result;

/// Error types for YAML patch operations
#[derive(thiserror::Error, Debug)]
pub enum YamlPatchError {
    #[error("Path not found: {0}")]
    PathNotFound(String),
    #[error("Invalid path format: {0}")]
    InvalidPath(String),
    #[error("YAML query error: {0}")]
    QueryError(#[from] yamlpath::QueryError),
    #[error("YAML serialization error: {0}")]
    SerializationError(#[from] serde_yaml::Error),
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
}

/// Represents a YAML patch operation that preserves comments and formatting
#[derive(Debug, Clone)]
pub enum YamlPatchOperation {
    /// Replace the value at the given path
    Replace {
        path: String,
        value: serde_yaml::Value,
    },
    /// Add a new key-value pair at the given path (path should point to a mapping)
    Add {
        path: String,
        key: String,
        value: serde_yaml::Value,
    },
    /// Merge key-value pairs into an existing mapping at the given path, or create the mapping if it doesn't exist
    MergeInto {
        path: String,
        key: String,
        value: serde_yaml::Value,
    },
    /// Remove the key at the given path
    Remove { path: String },
}

/// Apply YAML patch operations while preserving comments and formatting
///
/// This function takes a YAML string and a list of patch operations, applying them
/// in order while preserving all comments, formatting, and structure that isn't
/// directly modified.
///
/// Operations are applied from the end of the document backwards to avoid
/// invalidating byte positions during modification.
pub fn apply_yaml_patch(
    content: &str,
    operations: Vec<YamlPatchOperation>,
) -> Result<String, YamlPatchError> {
    // Validate that the input YAML is parseable before attempting patches
    if let Err(e) = serde_yaml::from_str::<serde_yaml::Value>(content) {
        return Err(YamlPatchError::InvalidOperation(format!(
            "input is not valid YAML: {}",
            e
        )));
    }

    let mut result = content.to_string();

    // Sort operations by byte position (reverse order) so we can apply them without
    // invalidating subsequent positions
    let mut positioned_ops = Vec::new();

    for op in operations {
        let doc = yamlpath::Document::new(&result)?;
        match &op {
            YamlPatchOperation::Replace { path, value: _ } => {
                if path == "/" {
                    // Handle root replacement - use the document root
                    let feature = doc.root();
                    positioned_ops.push((feature.location.byte_span.0, op));
                } else {
                    let query = parse_json_pointer_to_query(path)?;
                    let _feature = doc.query(&query)?;
                    positioned_ops.push((_feature.location.byte_span.0, op));
                }
            }
            YamlPatchOperation::Add { path, .. } => {
                if path == "/" {
                    // Handle root-level additions - use the document root
                    let feature = doc.root();
                    positioned_ops.push((feature.location.byte_span.1, op));
                } else {
                    let query = parse_json_pointer_to_query(path)?;
                    let feature = doc.query(&query)?;
                    positioned_ops.push((feature.location.byte_span.1, op));
                }
            }
            YamlPatchOperation::MergeInto { path, .. } => {
                if path == "/" {
                    // Handle root-level merges - use the document root
                    let feature = doc.root();
                    positioned_ops.push((feature.location.byte_span.1, op));
                } else {
                    let query = parse_json_pointer_to_query(path)?;
                    let feature = doc.query(&query)?;
                    positioned_ops.push((feature.location.byte_span.1, op));
                }
            }
            YamlPatchOperation::Remove { path } => {
                if path == "/" {
                    // Handle root-level removal - use the document root
                    let feature = doc.root();
                    positioned_ops.push((feature.location.byte_span.0, op));
                } else {
                    let query = parse_json_pointer_to_query(path)?;
                    let feature = doc.query(&query)?;
                    positioned_ops.push((feature.location.byte_span.0, op));
                }
            }
        }
    }

    // Sort by position (descending) so we apply changes from end to beginning
    positioned_ops.sort_by(|a, b| b.0.cmp(&a.0));

    for (_, op) in positioned_ops {
        result = apply_single_operation(&result, op)?;
    }

    Ok(result)
}

/// Apply a single YAML patch operation
fn apply_single_operation(
    content: &str,
    operation: YamlPatchOperation,
) -> Result<String, YamlPatchError> {
    let doc = yamlpath::Document::new(content)?;

    match operation {
        YamlPatchOperation::Replace { path, value } => {
            let feature = if path == "/" {
                doc.root()
            } else {
                let query = parse_json_pointer_to_query(&path)?;
                doc.query(&query)?
            };

            // Convert the new value to YAML string
            let new_value_str = serialize_yaml_value(&value)?;
            let new_value_str = new_value_str.trim_end(); // Remove trailing newline

            // Extract the current content to see what we're replacing
            let current_content = doc.extract(&feature);
            let current_content_with_ws = doc.extract_with_leading_whitespace(&feature);

            // For mapping values, we need to preserve the key part
            let replacement = if let Some(colon_pos) = current_content_with_ws.find(':') {
                // This is a key-value pair, preserve the key and whitespace
                let key_part = &current_content_with_ws[..colon_pos + 1];

                // Check if this is a multiline YAML string (contains |)
                let after_colon = &current_content_with_ws[colon_pos + 1..];
                let is_multiline_literal = after_colon.trim_start().starts_with('|');

                if is_multiline_literal {
                    // Check if this is a multiline string value
                    if let serde_yaml::Value::String(ref string_content) = value {
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
                            let pipe_pos = after_colon.find('|').unwrap();
                            let key_with_pipe = &current_content_with_ws
                                [..colon_pos + 1 + after_colon[..pipe_pos].len() + 1];
                            format!("{}\n{}", key_with_pipe.trim_end(), indented_content)
                        } else {
                            // Single line string, treat as regular key-value pair
                            format!("{} {}", key_part, new_value_str)
                        }
                    } else {
                        // Not a string value, treat as regular key-value pair
                        format!("{} {}", key_part, new_value_str)
                    }
                } else {
                    // Regular key-value pair
                    format!("{} {}", key_part, new_value_str)
                }
            } else {
                // This is just a value, replace it directly
                let leading_whitespace =
                    extract_leading_whitespace(content, feature.location.byte_span.0);
                if current_content.contains('\n') {
                    indent_multiline_yaml(&new_value_str, &leading_whitespace)
                } else {
                    new_value_str.to_string()
                }
            };

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

        YamlPatchOperation::Add { path, key, value } => {
            if path == "/" {
                // Handle root-level additions specially
                return handle_root_level_addition(content, &key, &value);
            }

            let query = parse_json_pointer_to_query(&path)?;
            let feature = doc.query(&query)?;

            // Convert the new value to YAML string
            let new_value_str = serialize_yaml_value(&value)?;
            let new_value_str = new_value_str.trim_end(); // Remove trailing newline

            // Check if we're adding to a list item by examining the path
            let is_list_item = path
                .split('/')
                .last()
                .unwrap_or("")
                .parse::<usize>()
                .is_ok();

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
                let indented_value = indent_multiline_yaml(&new_value_str, &indent);
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

            // Insert the new entry
            let mut result = content.to_string();
            result.insert_str(insertion_point, &final_entry);
            Ok(result)
        }

        YamlPatchOperation::MergeInto { path, key, value } => {
            if path == "/" {
                // Handle root-level merges specially
                return handle_root_level_merge(content, &key, &value);
            }

            let query = parse_json_pointer_to_query(&path)?;
            let feature = doc.query(&query)?;

            // Check if the key already exists in the target mapping
            let existing_key_path = format!("{}/{}", path, key);
            let existing_key_query = parse_json_pointer_to_query(&existing_key_path);

            if let Ok(existing_query) = existing_key_query {
                if let Ok(existing_feature) = doc.query(&existing_query) {
                    // Key exists, check if we need to merge mappings
                    if let serde_yaml::Value::Mapping(new_mapping) = &value {
                        // Try to parse the existing value as YAML to see if it's also a mapping
                        let existing_content = doc.extract(&existing_feature);
                        if let Ok(existing_value) =
                            serde_yaml::from_str::<serde_yaml::Value>(&existing_content)
                        {
                            // The extracted content includes the key, so we need to get the value
                            let actual_existing_value =
                                if let serde_yaml::Value::Mapping(outer_mapping) = existing_value {
                                    // If the extracted content is like "env: { ... }", get the value part
                                    if let Some(inner_value) =
                                        outer_mapping.get(&serde_yaml::Value::String(key.clone()))
                                    {
                                        inner_value.clone()
                                    } else {
                                        // Fallback: use the outer mapping directly
                                        serde_yaml::Value::Mapping(outer_mapping)
                                    }
                                } else {
                                    existing_value
                                };

                            if let serde_yaml::Value::Mapping(existing_mapping) =
                                actual_existing_value
                            {
                                // Both are mappings, merge them
                                let mut merged_mapping = existing_mapping.clone();
                                for (k, v) in new_mapping {
                                    merged_mapping.insert(k.clone(), v.clone());
                                }

                                // Use a custom replacement that preserves the key structure
                                return apply_mapping_replacement(
                                    content,
                                    &existing_key_path,
                                    &key,
                                    &serde_yaml::Value::Mapping(merged_mapping),
                                );
                            }
                        }
                    }

                    // Not both mappings, or parsing failed, just replace
                    return apply_single_operation(
                        content,
                        YamlPatchOperation::Replace {
                            path: existing_key_path,
                            value: value.clone(),
                        },
                    );
                }
            }

            // Key doesn't exist, add it using Add operation
            apply_single_operation(
                content,
                YamlPatchOperation::Add {
                    path: path.clone(),
                    key: key.clone(),
                    value: value.clone(),
                },
            )
        }

        YamlPatchOperation::Remove { path } => {
            if path == "/" {
                return Err(YamlPatchError::InvalidOperation(
                    "Cannot remove root document".to_string(),
                ));
            }
            let query = parse_json_pointer_to_query(&path)?;
            let feature = doc.query(&query)?;

            // For removal, we need to remove the entire line including leading whitespace
            let start_pos = find_line_start(content, feature.location.byte_span.0);
            let end_pos = find_line_end(content, feature.location.byte_span.1);

            let mut result = content.to_string();
            result.replace_range(start_pos..end_pos, "");
            Ok(result)
        }
    }
}

/// Convert a JSON Pointer path (like "/permissions/contents") to a yamlpath Query
pub fn parse_json_pointer_to_query(path: &str) -> Result<yamlpath::Query, YamlPatchError> {
    if !path.starts_with('/') {
        return Err(YamlPatchError::InvalidPath(format!(
            "Path must start with '/': {}",
            path
        )));
    }

    let components = path[1..] // Skip the leading '/'
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|component| {
            // Try to parse as integer (for array indices)
            if let Ok(index) = component.parse::<usize>() {
                yamlpath::Component::Index(index)
            } else {
                // Decode URI encoding if present
                let decoded = component.replace("~1", "/").replace("~0", "~");
                yamlpath::Component::Key(decoded)
            }
        })
        .collect();

    yamlpath::Query::new(components)
        .ok_or_else(|| YamlPatchError::InvalidPath("Empty path".to_string()))
}

/// Serialize a serde_yaml::Value to a YAML string, handling different types appropriately
fn serialize_yaml_value(value: &serde_yaml::Value) -> Result<String, YamlPatchError> {
    match value {
        serde_yaml::Value::String(s) => {
            // For strings, we may need to quote them if they contain special characters
            if needs_quoting(s) {
                Ok(serde_yaml::to_string(value)?)
            } else {
                Ok(s.clone())
            }
        }
        _ => {
            let yaml_str = serde_yaml::to_string(value)?;
            Ok(yaml_str.trim_end().to_string()) // Remove trailing newline
        }
    }
}

/// Check if a string needs to be quoted in YAML
fn needs_quoting(s: &str) -> bool {
    s.is_empty()
        || s.contains(':')
        || s.contains('#')
        || s.contains('\n')
        || s.starts_with(' ')
        || s.ends_with(' ')
        || s.chars().all(|c| c.is_ascii_digit() || c == '.')
        || matches!(
            s.to_lowercase().as_str(),
            "true" | "false" | "null" | "yes" | "no" | "on" | "off"
        )
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

/// Find the end of actual step content, excluding trailing comments
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

/// Handle root-level additions by finding the best insertion point at the document root
fn handle_root_level_addition(
    content: &str,
    key: &str,
    value: &serde_yaml::Value,
) -> Result<String, YamlPatchError> {
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
    path: &str,
    key: &str,
    value: &serde_yaml::Value,
) -> Result<String, YamlPatchError> {
    let doc = yamlpath::Document::new(content)?;
    let query = parse_json_pointer_to_query(path)?;
    let feature = doc.query(&query)?;

    // Convert the new value to YAML string
    let new_value_str = serialize_yaml_value(value)?;
    let new_value_str = new_value_str.trim_end(); // Remove trailing newline

    // Extract the current content to see what we're replacing
    let current_content = doc.extract(&feature);
    let current_content_with_ws = doc.extract_with_leading_whitespace(&feature);

    // For mapping values, we need to preserve the key part
    let replacement = if let Some(colon_pos) = current_content_with_ws.find(':') {
        // This is a key-value pair, preserve the key and whitespace
        let key_part = &current_content_with_ws[..colon_pos + 1];

        // Format as a proper mapping
        if let serde_yaml::Value::Mapping(mapping) = value {
            if mapping.is_empty() {
                // For empty mappings, format inline
                format!("{} {}", key_part, "{}")
            } else {
                // For non-empty mappings, format as a nested structure
                let leading_whitespace =
                    extract_leading_whitespace(content, feature.location.byte_span.0);
                let content_indent = format!("{}  ", leading_whitespace); // Key indent + 2 spaces for content

                let mut result = format!("{}", key_part.trim_end());
                for (k, v) in mapping {
                    let key_str = match k {
                        serde_yaml::Value::String(s) => s.clone(),
                        _ => serialize_yaml_value(k)?.trim().to_string(),
                    };
                    let value_str = serialize_yaml_value(v)?;
                    let value_str = value_str.trim_end();
                    result.push('\n');
                    result.push_str(&content_indent);
                    result.push_str(&key_str);
                    result.push_str(": ");
                    result.push_str(&value_str);
                }
                result
            }
        } else {
            // Regular key-value pair
            format!("{} {}", key_part, new_value_str)
        }
    } else {
        // This is just a value, replace it directly
        let leading_whitespace = extract_leading_whitespace(content, feature.location.byte_span.0);
        if current_content.contains('\n') {
            indent_multiline_yaml(&new_value_str, &leading_whitespace)
        } else {
            new_value_str.to_string()
        }
    };

    // Find the span to replace - use the span with leading whitespace if it's a key-value pair
    let (start_span, end_span) = if current_content_with_ws.contains(':') {
        // Replace the entire key-value pair span
        let ws_start =
            feature.location.byte_span.0 - (current_content_with_ws.len() - current_content.len());
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

/// Handle root-level merges by finding the best insertion point at the document root
fn handle_root_level_merge(
    content: &str,
    key: &str,
    value: &serde_yaml::Value,
) -> Result<String, YamlPatchError> {
    // Convert the new value to YAML string
    let new_value_str = serialize_yaml_value(value)?;
    let new_value_str = new_value_str.trim_end(); // Remove trailing newline

    // For root-level merges, we want to insert at the end of the document
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

/// Macro for creating comment-preserving YAML patches
///
/// This macro creates a function that can be used with the Fix system to apply
/// YAML patch operations while preserving comments and formatting.
///
/// # Example
///
/// ```rust
/// let fix = Fix {
///     title: "Update permission".to_string(),
///     description: "Change permission from write to read".to_string(),
///     apply: apply_yaml_patch!(vec![
///         YamlPatchOperation::Replace {
///             path: "/permissions/contents".to_string(),
///             value: serde_yaml::Value::String("read".to_string()),
///         }
///     ]),
/// };
/// ```
#[macro_export]
macro_rules! apply_yaml_patch {
    ($operations:expr) => {{
        let operations = $operations;
        Box::new(move |old_content: &str| -> anyhow::Result<Option<String>> {
            match crate::yaml_patch::apply_yaml_patch(old_content, operations.clone()) {
                Ok(new_content) => Ok(Some(new_content)),
                Err(e) => Err(anyhow::anyhow!("YAML patch failed: {}", e)),
            }
        })
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let operations = vec![YamlPatchOperation::Replace {
            path: "/permissions/contents".to_string(),
            value: serde_yaml::Value::String("write".to_string()),
        }];

        let result = apply_yaml_patch(original, operations).unwrap();

        // The result should preserve all comments
        assert!(result.contains("# This is a workflow file"));
        assert!(result.contains("# This configures permissions"));
        assert!(result.contains("# Only read access"));
        assert!(result.contains("# Write access for actions"));

        // But should change the value
        assert!(result.contains("contents: write"));
        assert!(!result.contains("contents: read"));
    }

    #[test]
    fn test_yaml_patch_add_preserves_formatting() {
        let original = r#"
permissions:
  contents: read
  actions: write
"#;

        let operations = vec![YamlPatchOperation::Add {
            path: "/permissions".to_string(),
            key: "issues".to_string(),
            value: serde_yaml::Value::String("read".to_string()),
        }];

        let result = apply_yaml_patch(original, operations).unwrap();

        // Should preserve original content and add new key
        assert!(result.contains("contents: read"));
        assert!(result.contains("actions: write"));
        assert!(result.contains("issues: read"));

        // Should maintain proper indentation
        assert!(result.contains("  issues: read"));
    }

    #[test]
    fn test_yaml_patch_remove_preserves_structure() {
        let original = r#"
permissions:
  contents: read  # Keep this comment
  actions: write  # Remove this line
  issues: read
"#;

        let operations = vec![YamlPatchOperation::Remove {
            path: "/permissions/actions".to_string(),
        }];

        let result = apply_yaml_patch(original, operations).unwrap();

        // Should preserve other content and comments
        assert!(result.contains("contents: read"));
        assert!(result.contains("# Keep this comment"));
        assert!(result.contains("issues: read"));

        // Should remove the target line
        assert!(!result.contains("actions: write"));
        assert!(!result.contains("# Remove this line"));
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
            YamlPatchOperation::Replace {
                path: "/permissions/contents".to_string(),
                value: serde_yaml::Value::String("write".to_string()),
            },
            YamlPatchOperation::Add {
                path: "/permissions".to_string(),
                key: "issues".to_string(),
                value: serde_yaml::Value::String("write".to_string()),
            },
        ];

        let result = apply_yaml_patch(original, operations).unwrap();

        // All comments should be preserved
        assert!(result.contains("# Main configuration"));
        assert!(result.contains("# Trigger on push"));
        assert!(result.contains("# Security settings"));
        assert!(result.contains("# Main job"));

        // Changes should be applied
        assert!(result.contains("contents: write"));
        assert!(result.contains("issues: write"));
        assert!(!result.contains("contents: read"));
    }

    #[test]
    fn test_json_pointer_parsing() {
        // Test basic path parsing
        let query = parse_json_pointer_to_query("/permissions/contents");
        assert!(query.is_ok());

        // Test array index parsing
        let query = parse_json_pointer_to_query("/jobs/0/steps/1");
        assert!(query.is_ok());

        // Test URI encoding
        let query = parse_json_pointer_to_query("/path/with~1slash/and~0tilde");
        assert!(query.is_ok());

        // Test error cases
        assert!(parse_json_pointer_to_query("no-leading-slash").is_err());
        assert!(parse_json_pointer_to_query("").is_err());
    }

    #[test]
    fn test_string_quoting_detection() {
        assert!(!needs_quoting("simple"));
        assert!(!needs_quoting("snake_case"));
        assert!(!needs_quoting("kebab-case"));

        assert!(needs_quoting(""));
        assert!(needs_quoting("has: colon"));
        assert!(needs_quoting("has # hash"));
        assert!(needs_quoting(" leading space"));
        assert!(needs_quoting("trailing space "));
        assert!(needs_quoting("true"));
        assert!(needs_quoting("false"));
        assert!(needs_quoting("null"));
        assert!(needs_quoting("123"));
        assert!(needs_quoting("3.14"));
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
            YamlPatchOperation::Replace {
                path: "/permissions/contents".to_string(),
                value: serde_yaml::Value::String("write".to_string()),
            },
            YamlPatchOperation::Add {
                path: "/permissions".to_string(),
                key: "packages".to_string(),
                value: serde_yaml::Value::String("read".to_string()),
            },
        ];

        let result = apply_yaml_patch(original_yaml, operations).unwrap();

        // Verify all comments are preserved
        assert!(result.contains("# GitHub Actions Workflow"));
        assert!(result.contains("# Security permissions"));
        assert!(result.contains("# This section defines permissions"));
        assert!(result.contains("# Only read access to repository contents"));
        assert!(result.contains("# Write access for GitHub Actions"));
        assert!(result.contains("# Read access to issues"));

        // Verify changes were applied
        assert!(result.contains("contents: write"));
        assert!(result.contains("packages: read"));
        assert!(!result.contains("contents: read"));

        println!("Full demo test passed!");
        println!("📝 Original YAML had comments preserved while applying transformations");
    }

    #[test]
    fn test_empty_mapping_formatting() {
        let original = r#"name: Test
jobs:
  test:
    runs-on: ubuntu-latest"#;

        // Test empty mapping formatting
        let empty_mapping = serde_yaml::Mapping::new();
        let operations = vec![YamlPatchOperation::Add {
            path: "/jobs/test".to_string(),
            key: "permissions".to_string(),
            value: serde_yaml::Value::Mapping(empty_mapping),
        }];

        let result = apply_yaml_patch(original, operations).unwrap();

        // Empty mapping should be formatted inline
        assert!(result.contains("    permissions: {}"));
        assert!(!result.contains("permissions:\n      {}"));
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

        let operations = vec![YamlPatchOperation::Add {
            path: "/jobs/test".to_string(),
            key: "permissions".to_string(),
            value: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        }];

        let result = apply_yaml_patch(&original_with_newline, operations).unwrap();

        // Should not have empty lines between content and new addition
        assert!(!result.contains("\"test\"\n\n    permissions"));
        assert!(result.contains("\"test\"\n    permissions: {}"));

        // Should have proper structure without extra empty lines
        let lines: Vec<&str> = result.lines().collect();
        let steps_line = lines
            .iter()
            .position(|&line| line.contains("- run: echo \"test\""))
            .unwrap();
        let permissions_line = lines
            .iter()
            .position(|&line| line.contains("permissions: {}"))
            .unwrap();

        // permissions should come immediately after the step (no empty line in between)
        assert_eq!(permissions_line, steps_line + 1);
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
        let checkout_query =
            crate::yaml_patch::parse_json_pointer_to_query("/jobs/test/steps/0").unwrap();
        let checkout_feature = doc.query(&checkout_query).unwrap();

        println!("Checkout step extraction:");
        println!("Exact span: '{}'", doc.extract(&checkout_feature));
        println!(
            "With leading whitespace: '{}'",
            doc.extract_with_leading_whitespace(&checkout_feature)
        );
        println!("Byte span: {:?}", checkout_feature.location.byte_span);

        // Test what yamlpath extracts for the test job
        let job_query = crate::yaml_patch::parse_json_pointer_to_query("/jobs/test").unwrap();
        let job_feature = doc.query(&job_query).unwrap();

        println!("\nJob extraction:");
        println!("Exact span: '{}'", doc.extract(&job_feature));
        println!(
            "With leading whitespace: '{}'",
            doc.extract_with_leading_whitespace(&job_feature)
        );
        println!("Byte span: {:?}", job_feature.location.byte_span);

        // Show what's around the insertion points
        let checkout_end = checkout_feature.location.byte_span.1;
        let job_end = job_feature.location.byte_span.1;

        println!("\nAround checkout insertion point:");
        let start = checkout_end.saturating_sub(20);
        let end = (checkout_end + 20).min(original.len());
        println!("Context: '{}'", &original[start..end]);
        println!(
            "Insertion point character: {:?}",
            original.chars().nth(checkout_end - 1)
        );

        println!("\nAround job insertion point:");
        let start = job_end.saturating_sub(20);
        let end = (job_end + 20).min(original.len());
        println!("Context: '{}'", &original[start..end]);
        println!(
            "Insertion point character: {:?}",
            original.chars().nth(job_end - 1)
        );
    }

    #[test]
    fn test_step_insertion_with_comments() {
        let original = r#"steps:
  - name: Checkout
    uses: actions/checkout@v4
    # This is a comment after the step

  - name: Build
    run: echo "build""#;

        let operations = vec![YamlPatchOperation::Add {
            path: "/steps/0".to_string(),
            key: "with".to_string(),
            value: serde_yaml::Value::Mapping({
                let mut map = serde_yaml::Mapping::new();
                map.insert(
                    serde_yaml::Value::String("persist-credentials".to_string()),
                    serde_yaml::Value::Bool(false),
                );
                map
            }),
        }];

        let result = apply_yaml_patch(original, operations).unwrap();
        println!("Result:\n{}", result);

        // The with section should be added to the first step correctly
        assert!(result.contains("uses: actions/checkout@v4"));
        assert!(result.contains("with:"));
        assert!(result.contains("persist-credentials: false"));
        assert!(result.contains("# This is a comment after the step"));

        // Should not break the structure
        assert!(result.contains("- name: Build"));
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
        let step0_query = crate::yaml_patch::parse_json_pointer_to_query("/steps/0").unwrap();
        let step0_feature = doc.query(&step0_query).unwrap();

        println!("Step 0 extraction:");
        println!("'{}'", doc.extract(&step0_feature));
        println!("Byte span: {:?}", step0_feature.location.byte_span);

        // See what yamlpath extracts for step 1
        let step1_query = crate::yaml_patch::parse_json_pointer_to_query("/steps/1").unwrap();
        let step1_feature = doc.query(&step1_query).unwrap();

        println!("\nStep 1 extraction:");
        println!("'{}'", doc.extract(&step1_feature));
        println!("Byte span: {:?}", step1_feature.location.byte_span);

        // Check for overlaps
        if step0_feature.location.byte_span.1 > step1_feature.location.byte_span.0 {
            println!("\n⚠️  OVERLAP DETECTED!");
            println!("Step 0 ends at: {}", step0_feature.location.byte_span.1);
            println!("Step 1 starts at: {}", step1_feature.location.byte_span.0);
        }

        // Show the characters around the boundaries
        let content_between =
            &original[step0_feature.location.byte_span.1..step1_feature.location.byte_span.0];
        println!("\nContent between step spans: '{}'", content_between);
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

        let operations = vec![YamlPatchOperation::Add {
            path: "/".to_string(),
            key: "permissions".to_string(),
            value: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        }];

        let result = apply_yaml_patch(original, operations).unwrap();

        // Should preserve all comments and structure
        assert!(result.contains("# GitHub Actions Workflow"));
        assert!(result.contains("name: CI"));
        assert!(result.contains("on: push"));

        // Should add permissions at the root level exactly once
        assert!(result.contains("permissions: {}"));

        // Should NOT have duplicated permissions (check that it only appears once)
        let permissions_count = result.matches("permissions:").count();
        assert_eq!(permissions_count, 1, "permissions should only appear once");

        // Should maintain proper structure
        assert!(result.contains("jobs:"));
        assert!(result.contains("  test:"));
        assert!(result.contains("    runs-on: ubuntu-latest"));

        println!("Root-level addition result:\n{}", result);
    }

    #[test]
    fn test_root_level_path_handling() {
        // Test that root path "/" is handled correctly
        let original = r#"name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest"#;

        let operations = vec![YamlPatchOperation::Add {
            path: "/".to_string(),
            key: "permissions".to_string(),
            value: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        }];

        let result = apply_yaml_patch(original, operations);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.contains("permissions: {}"));
        assert!(result.contains("name: Test"));
        assert!(result.contains("on: push"));
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

        let operations = vec![YamlPatchOperation::Add {
            path: "/steps/0".to_string(),
            key: "with".to_string(),
            value: serde_yaml::Value::Mapping({
                let mut map = serde_yaml::Mapping::new();
                map.insert(
                    serde_yaml::Value::String("persist-credentials".to_string()),
                    serde_yaml::Value::Bool(false),
                );
                map
            }),
        }];

        let result = apply_yaml_patch(original, operations).unwrap();
        println!("Result:\n{}", result);

        // The with section should be added to the first step correctly, not mixed with comments
        assert!(result.contains("uses: actions/checkout@v4"));
        assert!(result.contains("with:"));
        assert!(result.contains("persist-credentials: false"));
        assert!(result.contains("# Comment after step1"));
        assert!(result.contains("# Comment before step2"));
        assert!(result.contains("- name: Step2"));

        // Verify the structure is correct - with should come right after uses
        let lines: Vec<&str> = result.lines().collect();
        let uses_line = lines
            .iter()
            .position(|&line| line.contains("uses: actions/checkout@v4"))
            .unwrap();
        let with_line = lines
            .iter()
            .position(|&line| line.contains("with:"))
            .unwrap();

        // with should come immediately after uses (or with one comment line in between)
        assert!(with_line > uses_line && with_line <= uses_line + 2);

        // Step2 should still be intact
        let step2_line = lines
            .iter()
            .position(|&line| line.contains("- name: Step2"))
            .unwrap();
        assert!(step2_line > with_line);
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

        let operations = vec![YamlPatchOperation::MergeInto {
            path: "/jobs/test/steps/0".to_string(),
            key: "env".to_string(),
            value: serde_yaml::Value::Mapping({
                let mut map = serde_yaml::Mapping::new();
                map.insert(
                    serde_yaml::Value::String("TEST_VAR".to_string()),
                    serde_yaml::Value::String("test_value".to_string()),
                );
                map
            }),
        }];

        let result = apply_yaml_patch(original, operations).unwrap();
        println!("MergeInto new key result:\n{}", result);

        // Should add the env section
        assert!(result.contains("env:"));
        assert!(result.contains("TEST_VAR: test_value"));
        assert!(result.contains("run: echo \"hello\""));
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

        let operations = vec![YamlPatchOperation::MergeInto {
            path: "/jobs/test/steps/0".to_string(),
            key: "env".to_string(),
            value: serde_yaml::Value::Mapping({
                let mut map = serde_yaml::Mapping::new();
                map.insert(
                    serde_yaml::Value::String("NEW_VAR".to_string()),
                    serde_yaml::Value::String("new_value".to_string()),
                );
                map
            }),
        }];

        let result = apply_yaml_patch(original, operations).unwrap();
        println!("MergeInto existing key result:\n{}", result);

        // Should replace the entire env section with the new mapping
        assert!(result.contains("env:"));
        assert!(result.contains("NEW_VAR: new_value"));
        // Note: This replaces the entire env mapping, so EXISTING_VAR won't be there
        // This is the expected behavior for our use case
        assert!(!result.contains("EXISTING_VAR"));
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
          EXISTING_VAR: existing_value"#;

        // Apply MergeInto operation for env key (should replace existing)
        let operations = vec![YamlPatchOperation::MergeInto {
            path: "/jobs/test/steps/0".to_string(),
            key: "env".to_string(),
            value: serde_yaml::Value::Mapping({
                let mut map = serde_yaml::Mapping::new();
                map.insert(
                    serde_yaml::Value::String("NEW_VAR".to_string()),
                    serde_yaml::Value::String("new_value".to_string()),
                );
                map
            }),
        }];

        let result = apply_yaml_patch(original, operations).unwrap();
        println!("MergeInto duplicate prevention result:\n{}", result);

        // Should only have one env: key
        let env_count = result.matches("env:").count();
        assert_eq!(env_count, 1, "Should only have one env: key");

        // Should have the new value (replaces existing)
        assert!(result.contains("NEW_VAR: new_value"));
        assert!(!result.contains("EXISTING_VAR")); // Previous value gets replaced
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

        let operations = vec![YamlPatchOperation::MergeInto {
            path: "/jobs/test/steps/0".to_string(),
            key: "env".to_string(),
            value: serde_yaml::Value::Mapping({
                let mut map = serde_yaml::Mapping::new();
                map.insert(
                    serde_yaml::Value::String("GITHUB_REF_NAME".to_string()),
                    serde_yaml::Value::String("${{ github.ref_name }}".to_string()),
                );
                map
            }),
        }];

        let result = apply_yaml_patch(original, operations).unwrap();
        println!("MergeInto with env result:\n{}", result);

        // Should have env key
        assert!(result.contains("env:"));
        assert!(result.contains("GITHUB_REF_NAME: ${{ github.ref_name }}"));

        // Should only have one env key
        assert_eq!(result.matches("env:").count(), 1);
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

        println!("Original YAML:");
        println!("{}", original);
        println!("\n{}\n", "=".repeat(50));

        // Test yamlpath extraction
        let doc = yamlpath::Document::new(original).unwrap();
        let step_query = parse_json_pointer_to_query("/jobs/build/steps/0").unwrap();
        let step_feature = doc.query(&step_query).unwrap();

        println!("Step feature extraction:");
        println!("Exact: '{}'", doc.extract(&step_feature));
        println!(
            "With leading whitespace: '{}'",
            doc.extract_with_leading_whitespace(&step_feature)
        );
        println!("Byte span: {:?}", step_feature.location.byte_span);

        // Test indentation calculation
        let feature_with_ws = doc.extract_with_leading_whitespace(&step_feature);
        println!("\nFeature with whitespace lines:");
        for (i, line) in feature_with_ws.lines().enumerate() {
            println!("Line {}: '{}'", i, line);
        }

        // Check if we're adding to a list item
        let path = "/jobs/build/steps/0";
        let is_list_item = path
            .split('/')
            .last()
            .unwrap_or("")
            .parse::<usize>()
            .is_ok();
        println!("\nIs list item: {}", is_list_item);

        if let Some(first_line) = feature_with_ws.lines().next() {
            if let Some(_colon_pos) = first_line.find(':') {
                let key_indent = &first_line[..first_line.len() - first_line.trim_start().len()];
                println!("\nKey indent: '{}'", key_indent);
                println!("Key indent length: {}", key_indent.len());
                let final_indent = format!("{}  ", key_indent);
                println!("Final indent: '{}'", final_indent);
                println!("Final indent length: {}", final_indent.len());
            }
        }

        // Test leading whitespace extraction
        let leading_ws = extract_leading_whitespace(original, step_feature.location.byte_span.0);
        println!("\nLeading whitespace: '{}'", leading_ws);
        println!("Leading whitespace length: {}", leading_ws.len());

        // Test the actual MergeInto operation
        let operations = vec![YamlPatchOperation::MergeInto {
            path: "/jobs/build/steps/0".to_string(),
            key: "shell".to_string(),
            value: serde_yaml::Value::String("bash".to_string()),
        }];

        let result = apply_yaml_patch(original, operations).unwrap();
        println!("\nResult after MergeInto:");
        println!("{}", result);

        // Check if the result is valid YAML
        match serde_yaml::from_str::<serde_yaml::Value>(&result) {
            Ok(_) => println!("\nResult is valid YAML"),
            Err(e) => println!("\nResult is invalid YAML: {}", e),
        }
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

        println!("Original YAML:");
        println!("{}", original);
        println!("\n{}\n", "=".repeat(50));

        // Test yamlpath extraction of the env section
        let doc = yamlpath::Document::new(original).unwrap();
        let env_query = parse_json_pointer_to_query("/jobs/test/steps/0/env").unwrap();

        if let Ok(env_feature) = doc.query(&env_query) {
            let env_content = doc.extract(&env_feature);
            println!("Extracted env content: '{}'", env_content);

            // Try to parse it as YAML
            match serde_yaml::from_str::<serde_yaml::Value>(&env_content) {
                Ok(value) => {
                    println!("Successfully parsed as YAML: {:?}", value);
                    if let serde_yaml::Value::Mapping(mapping) = value {
                        println!("It's a mapping with {} entries", mapping.len());
                        for (k, v) in &mapping {
                            println!("  - {:?}: {:?}", k, v);
                        }
                    } else {
                        println!("Not a mapping: {:?}", value);
                    }
                }
                Err(e) => {
                    println!("Failed to parse as YAML: {}", e);
                }
            }
        } else {
            println!("Failed to query env section");
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

        let operations = vec![YamlPatchOperation::MergeInto {
            path: "/jobs/test/steps/0".to_string(),
            key: "env".to_string(),
            value: serde_yaml::Value::Mapping(new_env),
        }];

        match apply_yaml_patch(original, operations) {
            Ok(result) => {
                println!("\nMergeInto succeeded:");
                println!("{}", result);

                // Verify the result is valid YAML
                assert!(serde_yaml::from_str::<serde_yaml::Value>(&result).is_ok());

                // Verify both env variables are present
                assert!(result.contains("IDENTITY: ${{ secrets.IDENTITY }}"));
                assert!(result.contains("STEPS_META_OUTPUTS_TAGS: ${{ steps.meta.outputs.tags }}"));

                // Verify only one env: key exists
                assert_eq!(result.matches("env:").count(), 1);
            }
            Err(e) => {
                println!("\nMergeInto failed: {}", e);
                panic!("MergeInto should succeed");
            }
        }
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

        let operations = vec![YamlPatchOperation::MergeInto {
            path: "/jobs/test/steps/0".to_string(),
            key: "env".to_string(),
            value: serde_yaml::Value::Mapping(new_env),
        }];

        let result = apply_yaml_patch(original, operations).unwrap();
        println!("Complex env merge result:\n{}", result);

        // Verify the result is valid YAML
        assert!(serde_yaml::from_str::<serde_yaml::Value>(&result).is_ok());

        // Should merge all environment variables
        assert!(result.contains("IDENTITY: ${{ secrets.IDENTITY }}"));
        assert!(result.contains("OIDC_ISSUER_URL: ${{ secrets.OIDC_ISSUER_URL }}"));
        assert!(result.contains("STEPS_META_OUTPUTS_TAGS: ${{ steps.meta.outputs.tags }}"));

        // Should only have one env: key
        assert_eq!(result.matches("env:").count(), 1);
    }
}
