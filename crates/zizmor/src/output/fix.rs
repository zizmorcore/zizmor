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
        if total_fixes > 0 {
            anstream::eprintln!(
                "No fixes available to apply ({total_fixes} held back by fix mode)."
            );
        } else {
            anstream::eprintln!("No fixes available to apply.");
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
