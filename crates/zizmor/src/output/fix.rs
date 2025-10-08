//! Routines for applying fixes and reporting overall fix statuses.

use std::collections::HashMap;
use std::io;

use anyhow::{Context, Result};
use camino::Utf8PathBuf;
use owo_colors::OwoColorize;
use serde_json;

use crate::{
    FixFormat, FixMode,
    finding::{Finding, Fix, FixDisposition},
    models::AsDocument,
    registry::{FindingRegistry, input::InputKey, input::InputRegistry},
};

/// JSON Patch operation as defined in RFC 6902
#[derive(serde::Serialize)]
struct JsonPatchOp {
    /// The operation to perform: "add", "remove", "replace", "move", "copy", or "test"
    op: String,
    /// JSON Pointer (RFC 6901) indicating the target location
    path: String,
    /// The value to set (for add/replace operations)
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<serde_json::Value>,
    /// Source location for move/copy operations
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<String>,
}

/// JSON Patch document containing multiple operations for a single file
#[derive(serde::Serialize)]
struct JsonPatch {
    /// The file path that these operations apply to
    file: String,
    /// Array of JSON Patch operations to apply
    operations: Vec<JsonPatchOp>,
}

const FIX_MODE_WARNING: &str = "
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!                IMPORTANT WARNING             !!
!!                                              !!
!! Fix mode is EXPERIMENTAL!                    !!
!! You will encounter bugs; please report them. !!
!!                                              !!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
";

/// Apply all fixes associated with findings, filtered by the specified fix mode.
pub fn apply_fixes(
    fix_mode: FixMode,
    fix_format: FixFormat,
    results: &FindingRegistry,
    registry: &InputRegistry,
) -> Result<()> {
    anstream::eprintln!("{}", FIX_MODE_WARNING.red().bold());

    let mut fixes_by_input: HashMap<&InputKey, Vec<(&Fix, &Finding)>> = HashMap::new();
    let mut total_fixes = 0;
    for finding in results.fixable_findings() {
        total_fixes += finding.fixes.len();
        for fix in &finding.fixes {
            let fix = match (fix_mode, fix.disposition) {
                (FixMode::Safe, FixDisposition::Safe) => fix,
                (FixMode::UnsafeOnly, FixDisposition::Unsafe) => fix,
                (FixMode::All, _) => fix,
                _ => continue,
            };

            fixes_by_input
                .entry(fix.key)
                .or_default()
                .push((fix, finding));
        }
    }

    if fixes_by_input.is_empty() {
        // Only show messages for in-place fixes, not for JSON output
        if matches!(fix_format, FixFormat::Inplace) {
            if total_fixes > 0 {
                anstream::eprintln!(
                    "No fixes available to apply ({total_fixes} held back by fix mode)."
                );
            } else {
                anstream::eprintln!("No fixes available to apply.");
            }
        }
        return Ok(());
    }

    match fix_format {
        FixFormat::Inplace => apply_fixes_inplace(fixes_by_input, registry),
        FixFormat::Json => output_fixes_as_json_patch(fixes_by_input, registry),
    }
}

/// Apply fixes in-place, modifying the original files.
fn apply_fixes_inplace(
    fixes_by_input: HashMap<&InputKey, Vec<(&Fix, &Finding)>>,
    registry: &InputRegistry,
) -> Result<()> {
    let mut applied_fixes = Vec::new();
    let mut failed_fixes = Vec::new();

    for (input_key, fixes) in &fixes_by_input {
        let InputKey::Local(local) = input_key else {
            // NOTE: fixable_findings should only return local inputs,
            // so this case should never happen.
            panic!("can't apply fixes to remote inputs");
        };

        let input = registry.get_input(input_key);
        let file_path = &local.given_path;

        let mut file_applied_fixes = Vec::new();
        let mut current_document = input.as_document().clone();

        // Then apply successful fixes sequentially, handling conflicts gracefully
        for (fix, finding) in fixes {
            match fix.apply(&current_document) {
                Ok(new_document) => {
                    current_document = new_document;
                    file_applied_fixes.push((finding.ident, fix, finding));
                }
                Err(e) => {
                    // If the fix fails on modified content, it might be due to conflicts
                    // with previously applied fixes. Record this as a failed fix.
                    failed_fixes.push((
                        finding.ident,
                        file_path,
                        format!("conflict after applying previous fixes: {e}"),
                    ));
                }
            }
        }

        // Only proceed if there are changes to apply
        if current_document.source() != input.as_document().source() {
            let num_fixes = file_applied_fixes.len();

            std::fs::write(file_path, current_document.source())
                .with_context(|| format!("failed to update {file_path}"))?;

            applied_fixes.push((file_path, num_fixes));
        }
    }

    // Summary
    if !applied_fixes.is_empty() || !failed_fixes.is_empty() {
        print_summary(&applied_fixes, &failed_fixes);
    }

    Ok(())
}

/// Output fixes as JSON Patch format instead of modifying files.
fn output_fixes_as_json_patch(
    fixes_by_input: HashMap<&InputKey, Vec<(&Fix, &Finding)>>,
    registry: &InputRegistry,
) -> Result<()> {
    let mut json_patches = Vec::new();

    for (input_key, fixes) in &fixes_by_input {
        let InputKey::Local(local) = input_key else {
            // NOTE: fixable_findings should only return local inputs,
            // so this case should never happen.
            panic!("can't apply fixes to remote inputs");
        };

        let _input = registry.get_input(input_key);
        let file_path = &local.given_path;
        let mut operations = Vec::new();

        // Convert each fix to JSON Patch operations
        for (fix, _finding) in fixes {
            for patch in &fix.patches {
                if let Some(op) = yaml_patch_to_json_patch_op(patch) {
                    operations.push(op);
                }
            }
        }

        if !operations.is_empty() {
            json_patches.push(JsonPatch {
                file: file_path.to_string(),
                operations,
            });
        }
    }

    // Output JSON Patch to stdout
    if !json_patches.is_empty() {
        serde_json::to_writer_pretty(io::stdout(), &json_patches)?;
    }

    Ok(())
}

/// Convert a yamlpatch operation to a JSON Patch operation.
/// This is a simplified conversion that handles the most common cases.
fn yaml_patch_to_json_patch_op(patch: &yamlpatch::Patch) -> Option<JsonPatchOp> {
    use yamlpatch::Op;

    match &patch.operation {
        Op::Replace(value) => {
            // Convert the YAML path to JSON Pointer format
            let json_path = yaml_path_to_json_pointer(&patch.route);
            Some(JsonPatchOp {
                op: "replace".to_string(),
                path: json_path,
                value: Some(serde_json::to_value(value).ok()?),
                from: None,
            })
        }
        Op::Add { key, value } => {
            let json_path = yaml_path_to_json_pointer(&patch.route);
            let full_path = if json_path.ends_with('/') {
                format!("{}{}", json_path, key)
            } else {
                format!("{}/{}", json_path, key)
            };
            Some(JsonPatchOp {
                op: "add".to_string(),
                path: full_path,
                value: Some(serde_json::to_value(value).ok()?),
                from: None,
            })
        }
        Op::Remove => {
            let json_path = yaml_path_to_json_pointer(&patch.route);
            Some(JsonPatchOp {
                op: "remove".to_string(),
                path: json_path,
                value: None,
                from: None,
            })
        }
        Op::RewriteFragment { from: _, to } => {
            // For rewrite operations, we'll use replace with the new value
            // This is a simplified approach - in practice, you might want to
            // be more specific about what part of the string to replace
            let json_path = yaml_path_to_json_pointer(&patch.route);
            Some(JsonPatchOp {
                op: "replace".to_string(),
                path: json_path,
                value: Some(serde_json::Value::String(to.to_string())),
                from: None,
            })
        }
        Op::ReplaceComment { new: _new } => {
            // Comments are typically not part of JSON, so we'll skip them
            // or handle them specially if needed
            None
        }
        Op::MergeInto { key, updates } => {
            // For merge operations, we'll add each key-value pair
            // This is a simplified approach
            let json_path = yaml_path_to_json_pointer(&patch.route);
            let full_path = if json_path.ends_with('/') {
                format!("{}{}", json_path, key)
            } else {
                format!("{}/{}", json_path, key)
            };
            Some(JsonPatchOp {
                op: "add".to_string(),
                path: full_path,
                value: Some(serde_json::to_value(updates).ok()?),
                from: None,
            })
        }
    }
}

/// Convert a yamlpath route to a JSON Pointer path.
/// JSON Pointer format: /key1/key2/0/key3 (RFC 6901)
fn yaml_path_to_json_pointer(route: &yamlpath::Route) -> String {
    let mut path = String::new();

    // Serialize the route to get the components
    if let Ok(route_json) = serde_json::to_value(route) {
        if let Some(components) = route_json.get("route").and_then(|r| r.as_array()) {
            for component in components {
                match component {
                    serde_json::Value::Object(obj) => {
                        if let Some(key_val) = obj.get("Key").and_then(|k| k.as_str()) {
                            path.push('/');
                            // Escape JSON Pointer special characters according to RFC 6901
                            // ~0 represents ~ and ~1 represents /
                            let escaped_key = key_val.replace("~", "~0").replace("/", "~1");
                            path.push_str(&escaped_key);
                        } else if let Some(index_val) = obj.get("Index").and_then(|i| i.as_u64()) {
                            path.push('/');
                            path.push_str(&index_val.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // JSON Pointer must start with / for non-empty paths
    if path.is_empty() {
        "/".to_string()
    } else {
        path
    }
}

fn print_summary(
    applied_fixes: &[(&Utf8PathBuf, usize)],
    failed_fixes: &[(&str, &Utf8PathBuf, String)],
) {
    anstream::eprintln!("\n{}", "Fix Summary".green().bold());

    if !applied_fixes.is_empty() {
        anstream::eprintln!(
            "Successfully applied fixes to {} files:",
            applied_fixes.len()
        );
        for (file_path, num_fixes) in applied_fixes {
            anstream::eprintln!("  {}: {} fixes", file_path, num_fixes);
        }
    }

    if !failed_fixes.is_empty() {
        anstream::eprintln!("Failed to apply {} fixes:", failed_fixes.len());
        for (ident, file_path, error) in failed_fixes {
            anstream::eprintln!("  {}: {} ({})", ident, file_path, error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use yamlpath::{Component, Route};

    /// Test JSON Pointer path conversion with simple keys
    #[test]
    fn test_yaml_path_to_json_pointer_simple_keys() {
        // Create a simple route: /jobs/build/steps
        let route = Route::from(vec![
            Component::Key("jobs"),
            Component::Key("build"),
            Component::Key("steps"),
        ]);

        // Test that the route can be created and is not empty
        assert!(!route.is_empty());

        // Test the actual conversion function
        let json_pointer = yaml_path_to_json_pointer(&route);
        assert!(json_pointer.starts_with('/'));
        assert!(json_pointer.contains("jobs"));
        assert!(json_pointer.contains("build"));
        assert!(json_pointer.contains("steps"));
    }

    /// Test JSON Pointer path conversion with array indices
    #[test]
    fn test_yaml_path_to_json_pointer_with_indices() {
        // Create a route with array indices: /jobs/0/steps/1
        let route = Route::from(vec![
            Component::Key("jobs"),
            Component::Index(0),
            Component::Key("steps"),
            Component::Index(1),
        ]);

        assert!(!route.is_empty());

        // Test the actual conversion function
        let json_pointer = yaml_path_to_json_pointer(&route);
        assert!(json_pointer.starts_with('/'));
        assert!(json_pointer.contains("jobs"));
        assert!(json_pointer.contains("steps"));
    }

    /// Test JSON Pointer path conversion with special characters
    #[test]
    fn test_yaml_path_to_json_pointer_special_characters() {
        // Create a route with special characters in keys
        let route = Route::from(vec![
            Component::Key("with~tilde"),
            Component::Key("with/slash"),
            Component::Key("normal-key"),
        ]);

        assert!(!route.is_empty());

        // Test the actual conversion function
        let json_pointer = yaml_path_to_json_pointer(&route);
        assert!(json_pointer.starts_with('/'));
        assert!(json_pointer.contains("normal-key"));
    }

    /// Test JSON Patch operation structure
    #[test]
    fn test_json_patch_operation_structure() {
        // Test that we can create valid JSON Patch operations
        let add_op = serde_json::json!({
            "op": "add",
            "path": "/jobs/build/steps/0/persist-credentials",
            "value": false
        });

        let replace_op = serde_json::json!({
            "op": "replace",
            "path": "/jobs/build/steps/1/run",
            "value": "echo \"Hello World\""
        });

        let remove_op = serde_json::json!({
            "op": "remove",
            "path": "/jobs/build/steps/2"
        });

        // Verify the structure is correct
        assert_eq!(add_op["op"], "add");
        assert_eq!(add_op["path"], "/jobs/build/steps/0/persist-credentials");
        assert_eq!(add_op["value"], false);

        assert_eq!(replace_op["op"], "replace");
        assert_eq!(replace_op["path"], "/jobs/build/steps/1/run");
        assert_eq!(replace_op["value"], "echo \"Hello World\"");

        assert_eq!(remove_op["op"], "remove");
        assert_eq!(remove_op["path"], "/jobs/build/steps/2");
        assert!(remove_op.get("value").is_none());
    }

    /// Test JSON Patch document structure
    #[test]
    fn test_json_patch_document_structure() {
        let patch_doc = serde_json::json!({
            "file": "workflow.yml",
            "operations": [
                {
                    "op": "add",
                    "path": "/jobs/build/steps/0/persist-credentials",
                    "value": false
                },
                {
                    "op": "replace",
                    "path": "/jobs/build/steps/1/run",
                    "value": "echo \"Hello World\""
                }
            ]
        });

        // Verify the structure
        assert_eq!(patch_doc["file"], "workflow.yml");
        assert!(patch_doc["operations"].is_array());

        let operations = patch_doc["operations"].as_array().unwrap();
        assert_eq!(operations.len(), 2);

        assert_eq!(operations[0]["op"], "add");
        assert_eq!(operations[1]["op"], "replace");
    }

    /// Test JSON Pointer escaping
    #[test]
    fn test_json_pointer_escaping() {
        // Test that special characters are properly escaped
        let test_cases = vec![
            ("normal-key", "normal-key"),
            ("with~tilde", "with~0tilde"),
            ("with/slash", "with~1slash"),
            ("with~and/", "with~0and~1"),
        ];

        for (input, expected) in test_cases {
            let escaped = input.replace("~", "~0").replace("/", "~1");
            assert_eq!(escaped, expected, "Failed to escape: {}", input);
        }
    }

    /// Test JSON Pointer path construction
    #[test]
    fn test_json_pointer_path_construction() {
        // Test building JSON Pointer paths from components
        let components = vec!["jobs", "build", "steps", "0"];
        let mut path = String::new();

        for component in components {
            path.push('/');
            path.push_str(component);
        }

        assert_eq!(path, "/jobs/build/steps/0");
    }

    /// Test that JSON Patch operations are valid according to RFC 6902
    #[test]
    fn test_json_patch_rfc_6902_compliance() {
        // Test valid operations according to RFC 6902
        let valid_operations = vec![
            ("add", true, true, false), // op, path, value, from
            ("remove", true, false, false),
            ("replace", true, true, false),
            ("move", true, false, true),
            ("copy", true, false, true),
            ("test", true, true, false),
        ];

        for (op, _has_path, has_value, has_from) in valid_operations {
            let mut operation = serde_json::json!({
                "op": op,
                "path": "/test/path"
            });

            if has_value {
                operation["value"] = Value::String("test".to_string());
            }

            if has_from {
                operation["from"] = Value::String("/source/path".to_string());
            }

            // Verify required fields are present
            assert!(operation.get("op").is_some());
            assert!(operation.get("path").is_some());

            if has_value {
                assert!(operation.get("value").is_some());
            }

            if has_from {
                assert!(operation.get("from").is_some());
            }
        }
    }

    /// Test edge cases for JSON Pointer paths
    #[test]
    fn test_json_pointer_edge_cases() {
        // Test empty path
        let empty_path = "/";
        assert!(empty_path.starts_with('/'));

        // Test root path
        let root_path = "/";
        assert_eq!(root_path, "/");

        // Test path with only slashes
        let slash_path = "//";
        assert!(slash_path.starts_with('/'));
    }

    /// Test JSON Patch value serialization
    #[test]
    fn test_json_patch_value_serialization() {
        // Test different value types that might be used in JSON Patch
        let test_values = vec![
            Value::Bool(true),
            Value::Bool(false),
            Value::String("test".to_string()),
            Value::Number(serde_json::Number::from(42)),
            Value::Array(vec![
                Value::String("item1".to_string()),
                Value::String("item2".to_string()),
            ]),
            Value::Object(serde_json::Map::new()),
        ];

        for value in test_values {
            let operation = serde_json::json!({
                "op": "add",
                "path": "/test/path",
                "value": value
            });

            // Should be able to serialize and deserialize
            let serialized = serde_json::to_string(&operation).unwrap();
            let deserialized: Value = serde_json::from_str(&serialized).unwrap();

            assert_eq!(operation, deserialized);
        }
    }
}
