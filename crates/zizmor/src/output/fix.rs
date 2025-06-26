//! Routines for applying fixes and reporting overall fix statuses.

use std::collections::HashMap;

use anyhow::{Context, Result};
use camino::Utf8PathBuf;
use owo_colors::OwoColorize;

use crate::{
    FixMode,
    finding::{Finding, Fix, FixDisposition},
    models::AsDocument,
    registry::{FindingRegistry, InputKey, InputRegistry},
};

/// Apply all fixes associated with findings, filtered by the specified fix mode.
pub fn apply_fixes(
    fix_mode: FixMode,
    results: &FindingRegistry,
    registry: &InputRegistry,
) -> Result<()> {
    let mut fixes_by_input: HashMap<&InputKey, Vec<(&Fix, &Finding)>> = HashMap::new();
    for finding in results.findings() {
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
        anstream::println!("No fixes available to apply.");
        return Ok(());
    }

    // Process each file
    let mut applied_fixes = Vec::new();
    let mut failed_fixes = Vec::new();

    for (input_key, fixes) in &fixes_by_input {
        let InputKey::Local(local) = input_key else {
            // We don't currently have the ability to apply fixes
            // to remote inputs.
            continue;
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
                        format!("conflict after applying previous fixes: {}", e),
                    ));
                }
            }
        }

        // Only proceed if there are changes to apply
        if current_document.source() != input.as_document().source() {
            anstream::println!("{}", "\nFixes".to_string().green().bold());
            let num_fixes = file_applied_fixes.len();
            for (ident, fix, finding) in file_applied_fixes {
                let line_info = format!(
                    " at line {}",
                    finding.primary_location().concrete.location.start_point.row + 1
                );
                anstream::println!(
                    "  - {}{}: {}",
                    format_severity_and_rule(&finding.determinations.severity, ident),
                    line_info,
                    fix.title
                );
            }

            std::fs::write(file_path, current_document.source())
                .with_context(|| format!("failed to update {file_path}"))?;

            anstream::println!("Applied {} fixes to {}", num_fixes, file_path);
            applied_fixes.push((file_path, num_fixes));
        }
    }

    // Summary
    if !applied_fixes.is_empty() || !failed_fixes.is_empty() {
        print_summary(&applied_fixes, &failed_fixes);
    }

    Ok(())
}

fn print_summary(
    applied_fixes: &[(&Utf8PathBuf, usize)],
    failed_fixes: &[(&str, &Utf8PathBuf, String)],
) {
    anstream::println!("\n{}", "Fix Summary".green().bold());

    if !applied_fixes.is_empty() {
        anstream::println!(
            "Successfully applied fixes to {} files:",
            applied_fixes.len()
        );
        for (file_path, num_fixes) in applied_fixes {
            anstream::println!("  {}: {} fixes", file_path, num_fixes);
        }
    }

    if !failed_fixes.is_empty() {
        anstream::println!("Failed to apply {} fixes:", failed_fixes.len());
        for (ident, file_path, error) in failed_fixes {
            anstream::println!("  {}: {} ({})", ident, file_path, error);
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
