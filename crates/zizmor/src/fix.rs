use std::collections::HashMap;

use anyhow::Result;
use owo_colors::OwoColorize;

use crate::{
    finding::{Finding, Fix},
    models::AsDocument,
    registry::{FindingRegistry, InputRegistry},
};

/// Apply fixes to files based on the provided configuration
pub fn apply_fixes(results: &FindingRegistry, registry: &InputRegistry) -> Result<()> {
    // Collect all applicable fixes grouped by file
    let mut file_fixes: HashMap<String, Vec<(&'static str, &Finding, &Fix)>> = HashMap::new();

    for finding in results.findings() {
        if let Some(location) = finding.locations.first() {
            let file_path = location.symbolic.key.presentation_path().to_string();
            if !finding.fixes.is_empty() {
                for fix in &finding.fixes {
                    file_fixes.entry(file_path.clone()).or_default().push((
                        finding.ident,
                        finding,
                        fix,
                    ));
                }
            }
        }
    }

    if file_fixes.is_empty() {
        println!("No fixes available to apply.");
        return Ok(());
    }

    // Process each file
    let mut applied_fixes = Vec::new();
    let mut failed_fixes = Vec::new();

    for (file_path, fixes) in &file_fixes {
        // Get the original content from the registry instead of reading from disk
        let input_key = fixes
            .first()
            .unwrap()
            .1
            .locations
            .first()
            .unwrap()
            .symbolic
            .key;
        let input = registry.get_input(input_key);
        let original_content = input.as_document().source();

        let mut current_content = original_content.to_string();
        let mut file_applied_fixes = Vec::new();
        let mut successful_fixes = Vec::new();

        // First, try to apply each fix independently to the original content
        // to collect which fixes can be applied successfully
        for (ident, finding, fix) in fixes {
            match fix.apply_to_content(original_content) {
                Ok(Some(_)) => {
                    successful_fixes.push((*ident, *fix, *finding));
                }
                Ok(None) => {
                    // Fix didn't apply (no changes needed)
                }
                Err(e) => {
                    failed_fixes.push((*ident, file_path.clone(), format!("{}", e)));
                }
            }
        }

        // Then apply successful fixes sequentially, handling conflicts gracefully
        for (ident, fix, finding) in successful_fixes {
            match fix.apply_to_content(&current_content) {
                Ok(Some(new_content)) => {
                    current_content = new_content;
                    file_applied_fixes.push((ident, fix, finding));
                }
                Ok(None) => {
                    // Fix didn't apply to modified content (possibly due to conflicts)
                }
                Err(e) => {
                    // If the fix fails on modified content, it might be due to conflicts
                    // with previously applied fixes. Record this as a failed fix.
                    failed_fixes.push((
                        ident,
                        file_path.clone(),
                        format!("conflict after applying previous fixes: {}", e),
                    ));
                }
            }
        }

        // Only proceed if there are changes to apply
        if current_content != original_content {
            println!("{}", "\nFixes".to_string().green().bold());
            let num_fixes = file_applied_fixes.len();
            for (ident, fix, finding) in file_applied_fixes {
                let line_info = format!(" at line {}", get_primary_line_number(finding));
                println!(
                    "  - {}{}: {}",
                    format_severity_and_rule(&finding.determinations.severity, ident),
                    line_info,
                    fix.title
                );
            }

            match std::fs::write(file_path, &current_content) {
                Ok(_) => {
                    applied_fixes.push((file_path.to_string(), num_fixes));
                    println!("Applied {} fixes to {}", num_fixes, file_path);
                }
                Err(e) => {
                    eprintln!("Failed to write {}: {}", file_path, e);
                }
            }
        }
    }

    // Summary
    if !applied_fixes.is_empty() || !failed_fixes.is_empty() {
        print_summary(&applied_fixes, &failed_fixes);
    }

    Ok(())
}

fn print_summary(applied_fixes: &[(String, usize)], failed_fixes: &[(&str, String, String)]) {
    println!("\n{}", "Fix Summary".green().bold());

    if !applied_fixes.is_empty() {
        println!(
            "Successfully applied fixes to {} files:",
            applied_fixes.len()
        );
        for (file_path, num_fixes) in applied_fixes {
            println!("  {}: {} fixes", file_path, num_fixes);
        }
    }

    if !failed_fixes.is_empty() {
        println!("Failed to apply {} fixes:", failed_fixes.len());
        for (ident, file_path, error) in failed_fixes {
            println!("  {}: {} ({})", ident, file_path, error);
        }
    }
}

/// Format severity and rule name with appropriate color based on the same scheme used in plain output
pub fn format_severity_and_rule(severity: &crate::finding::Severity, rule_name: &str) -> String {
    use owo_colors::OwoColorize;
    let severity_name = match severity {
        crate::finding::Severity::Unknown => "note",
        crate::finding::Severity::Informational => "info",
        crate::finding::Severity::Low => "help",
        crate::finding::Severity::Medium => "warning",
        crate::finding::Severity::High => "error",
    };

    let formatted = format!("{}[{}]", severity_name, rule_name);

    match severity {
        crate::finding::Severity::Unknown => formatted,
        crate::finding::Severity::Informational => formatted.purple().to_string(),
        crate::finding::Severity::Low => formatted.cyan().to_string(),
        crate::finding::Severity::Medium => formatted.yellow().to_string(),
        crate::finding::Severity::High => formatted.red().to_string(),
    }
}

/// Get the primary line number for a finding
/// Since finding builder APIs enforce the presence of a primary location, this is safe to unwrap
pub fn get_primary_line_number(finding: &Finding) -> usize {
    finding
        .locations
        .iter()
        .find(|loc| loc.symbolic.is_primary())
        .or_else(|| finding.locations.first())
        .map(|loc| loc.concrete.location.start_point.row + 1) // Convert to 1-based line number
        .unwrap()
}
