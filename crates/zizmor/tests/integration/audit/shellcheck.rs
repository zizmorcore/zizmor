use std::process::Command;

use anyhow::Result;

use crate::common::{input_under_test, zizmor};

fn inherited_path() -> String {
    std::env::var("PATH").unwrap_or_default()
}

fn shellcheck_available() -> bool {
    Command::new("shellcheck")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

#[test]
fn test_shellcheck_not_in_path() -> Result<()> {
    let output = zizmor()
        .input(input_under_test("shellcheck/positive.yml"))
        .setenv("PATH", "")
        .run()?;

    assert!(
        !output.contains("[shellcheck]"),
        "unexpected shellcheck finding while binary is missing: {output}"
    );

    Ok(())
}

#[test]
fn test_shellcheck_ignores_non_shell_run_steps() -> Result<()> {
    let output = zizmor()
        .input(input_under_test("shellcheck/non-shell.yml"))
        .setenv("PATH", &inherited_path())
        .run()?;

    assert!(
        !output.contains("[shellcheck]"),
        "unexpected shellcheck finding for non-shell run step: {output}"
    );

    Ok(())
}

#[test]
fn test_shellcheck_reports_when_available() -> Result<()> {
    if !shellcheck_available() {
        return Ok(());
    }

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "shellcheck/positive.yml"
            ))
            .setenv("PATH", &inherited_path())
            .run()?,
        @"
    info[shellcheck]: shellcheck finding in shell run block
      --> @@INPUT@@:17:19
       |
    14 |     runs-on: ubuntu-latest
       |     ------- shell implied by runner
    ...
    17 |         run: echo $FOO
       |                   ^^^^ SC2086: Double quote to prevent globbing and word splitting.
       |
       = note: audit confidence → High
       = tip: shellcheck rule reference: https://www.shellcheck.net/wiki/SC2086

    1 finding: 1 informational, 0 low, 0 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_shellcheck_ignore_unknown_shells() -> Result<()> {
    if !shellcheck_available() {
        return Ok(());
    }

    insta::assert_snapshot!(
        zizmor()
        .input(input_under_test("shellcheck/unknown-shell.yml"))
        .setenv("PATH", &inherited_path())
        .run()?,
        @"No findings to report. Good job!"
    );

    Ok(())
}

#[test]
fn test_shellcheck_check_unknown_shells_config() -> Result<()> {
    if !shellcheck_available() {
        return Ok(());
    }

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "shellcheck/unknown-shell.yml"
            ))
            .config(
                input_under_test("shellcheck/configs/check-unknown-shells.yml")
            )
            .setenv("PATH", &inherited_path())
            .run()?,
        @"
    info[shellcheck]: shellcheck finding in shell run block
      --> @@INPUT@@:17:19
       |
    17 |         run: echo $FOO
       |                   ^^^^ SC2086: Double quote to prevent globbing and word splitting.
       |
       = note: audit confidence → High
       = tip: shellcheck rule reference: https://www.shellcheck.net/wiki/SC2086

    info[shellcheck]: shellcheck finding in shell run block
      --> @@INPUT@@:24:19
       |
    24 |         run: echo $FOO
       |                   ^^^^ SC2086: Double quote to prevent globbing and word splitting.
       |
       = note: audit confidence → High
       = tip: shellcheck rule reference: https://www.shellcheck.net/wiki/SC2086

    2 findings: 2 informational, 0 low, 0 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_shellcheck_with_template_expressions() -> Result<()> {
    if !shellcheck_available() {
        return Ok(());
    }

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "shellcheck/template-in-run.yml"
            ))
            .setenv("PATH", &inherited_path())
            .run()?,
        @r#"
    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:13:27
       |
    12 |         run: |
       |         --- this run block
    13 |           echo "hello ${{ github.actor }}"
       |                           ^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    3 findings (2 suppressed, 1 unsafe fixes): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_shellcheck_multiple_findings() -> Result<()> {
    if !shellcheck_available() {
        return Ok(());
    }

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "shellcheck/multiple-issues.yml"
            ))
            .setenv("PATH", &inherited_path())
            .run()?,
        @"
    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:14:20
       |
    12 |         run: |
       |         --- this run block
    13 |           cd $UNQUOTED_DIR
    14 |           echo ${{ github.ref }}
       |                    ^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:15:20
       |
    12 |         run: |
       |         --- this run block
    ...
    15 |           echo ${{ github.actor }}
       |                    ^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[shellcheck]: shellcheck finding in shell run block
      --> @@INPUT@@:13:11
       |
     9 |     runs-on: ubuntu-latest
       |     ------- shell implied by runner
    ...
    13 |           cd $UNQUOTED_DIR
       |           ^^^^^^^^^^^^^^^^ SC2164: Use 'cd ... || exit' or 'cd ... || return' in case cd fails.
       |
       = note: audit confidence → High
       = tip: shellcheck rule reference: https://www.shellcheck.net/wiki/SC2164

    info[shellcheck]: shellcheck finding in shell run block
      --> @@INPUT@@:13:14
       |
     9 |     runs-on: ubuntu-latest
       |     ------- shell implied by runner
    ...
    13 |           cd $UNQUOTED_DIR
       |              ^^^^^^^^^^^^^ SC2086: Double quote to prevent globbing and word splitting.
       |
       = note: audit confidence → High
       = tip: shellcheck rule reference: https://www.shellcheck.net/wiki/SC2086

    warning[shellcheck]: shellcheck finding in shell run block
      --> @@INPUT@@:16:14
       |
     9 |     runs-on: ubuntu-latest
       |     ------- shell implied by runner
    ...
    16 |           if $@; then
       |              ^^ SC2068: Double quote array expansions to avoid re-splitting elements.
       |
       = note: audit confidence → High
       = tip: shellcheck rule reference: https://www.shellcheck.net/wiki/SC2068

    7 findings (2 suppressed, 2 unsafe fixes): 1 informational, 1 low, 1 medium, 2 high
    "
    );

    Ok(())
}
