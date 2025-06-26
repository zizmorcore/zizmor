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

    // Process each file
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
                        format!("conflict after applying previous fixes: {}", e),
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
