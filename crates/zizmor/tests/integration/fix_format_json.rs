//! Tests for the --fix-format json functionality.
//!
//! These tests verify that the JSON Patch output is correctly formatted
//! and contains the expected operations for different types of fixes.

use crate::common::{input_under_test, zizmor};
use anyhow::Result;

/// Test JSON Patch output for artipacked fixes (persist-credentials issue)
#[test]
fn test_artipacked_fixes_json_patch() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("artipacked.yml"))
            .args(["--fix=all", "--fix-format=json", "--quiet"])
            .run()?
    );

    Ok(())
}

/// Test JSON Patch output for template injection fixes
#[test]
fn test_template_injection_fixes_json_patch() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection.yml"))
            .args(["--fix=all", "--fix-format=json", "--quiet"])
            .run()?
    );

    Ok(())
}

/// Test JSON Patch output for cache poisoning fixes
#[test]
fn test_cache_poisoning_fixes_json_patch() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("fix-scenarios/cache-poisoning-fixes.yml"))
            .args(["--fix=all", "--fix-format=json", "--quiet"])
            .run()?
    );

    Ok(())
}

/// Test JSON Patch output for unsound condition fixes
#[test]
fn test_unsound_condition_fixes_json_patch() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "fix-scenarios/unsound-condition-fixes.yml"
            ))
            .args(["--fix=all", "--fix-format=json", "--quiet"])
            .run()?
    );

    Ok(())
}

/// Test JSON Patch output for mixed fix types
#[test]
fn test_mixed_fixes_json_patch() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("fix-scenarios/mixed-fixes.yml"))
            .args(["--fix=all", "--fix-format=json", "--quiet"])
            .run()?
    );

    Ok(())
}

/// Test that no fixes produces empty output (only version banner)
#[test]
fn test_no_fixes_produces_empty_output() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("fix-scenarios/no-fixes.yml"))
            .args(["--fix=all", "--fix-format=json", "--quiet"])
            .run()?
    );

    Ok(())
}

/// Test that different fix modes work with JSON format
#[test]
fn test_fix_modes_with_json() -> Result<()> {
    // Test safe fixes only
    insta::assert_snapshot!(
        "safe_fixes_only",
        zizmor()
            .input(input_under_test("fix-scenarios/mixed-fixes.yml"))
            .args(["--fix=safe", "--fix-format=json", "--quiet"])
            .run()?
    );

    // Test unsafe fixes only
    insta::assert_snapshot!(
        "unsafe_fixes_only",
        zizmor()
            .input(input_under_test("fix-scenarios/mixed-fixes.yml"))
            .args(["--fix=unsafe-only", "--fix-format=json", "--quiet"])
            .run()?
    );

    // Test all fixes
    insta::assert_snapshot!(
        "all_fixes",
        zizmor()
            .input(input_under_test("fix-scenarios/mixed-fixes.yml"))
            .args(["--fix=all", "--fix-format=json", "--quiet"])
            .run()?
    );

    Ok(())
}

/// Test that multiple files produce multiple patches in deterministic order
#[test]
fn test_multiple_files_produce_multiple_patches() -> Result<()> {
    // Use files with predictable, simple fixes to ensure deterministic output
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("artipacked.yml"))
            .input(input_under_test("template-injection.yml"))
            .args(["--fix=all", "--fix-format=json", "--quiet"])
            .run()?
    );

    Ok(())
}

/// Test that multiple file processing is deterministic
#[test]
fn test_multiple_files_deterministic_output() -> Result<()> {
    // Run the same test twice to ensure deterministic output
    let output1 = zizmor()
        .input(input_under_test("artipacked.yml"))
        .input(input_under_test("template-injection.yml"))
        .args(["--fix=all", "--fix-format=json", "--quiet"])
        .run()?;

    let output2 = zizmor()
        .input(input_under_test("artipacked.yml"))
        .input(input_under_test("template-injection.yml"))
        .args(["--fix=all", "--fix-format=json", "--quiet"])
        .run()?;

    // The outputs should be identical
    assert_eq!(
        output1, output2,
        "Multiple file processing should be deterministic"
    );

    Ok(())
}
