use anyhow::Ok;

use crate::common::{OutputMode, input_under_test, zizmor};

#[test]
fn test_missing_cooldown() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "dependabot-cooldown/missing/dependabot.yml"
            ))
            .run()?,
        @r"
    warning[dependabot-cooldown]: insufficient cooldown in Dependabot updates
     --> @@INPUT@@:4:5
      |
    4 |   - package-ecosystem: pip
      |     ^^^^^^^^^^^^^^^^^^^^^^ missing cooldown configuration
      |
      = note: audit confidence → High
      = note: this finding has an auto-fix

    1 findings (1 fixable): 0 informational, 0 low, 1 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_no_default_days() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "dependabot-cooldown/no-default-days/dependabot.yml"
            ))
            .run()?,
        @r"
    warning[dependabot-cooldown]: insufficient cooldown in Dependabot updates
     --> @@INPUT@@:6:5
      |
    6 |     cooldown: {}
      |     ^^^^^^^^^^^^ no default-days configured
      |
      = note: audit confidence → High
      = note: this finding has an auto-fix

    1 findings (1 fixable): 0 informational, 0 low, 1 medium, 0 high
    ");

    Ok(())
}

#[test]
fn test_default_days_too_short() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "dependabot-cooldown/default-days-too-short/dependabot.yml"
            ))
            .run()?,
        @r"
    help[dependabot-cooldown]: insufficient cooldown in Dependabot updates
     --> @@INPUT@@:7:7
      |
    7 |       default-days: 2
      |       ^^^^^^^^^^^^^^^ insufficient default-days configured (less than 7)
      |
      = note: audit confidence → Medium
      = note: this finding has an auto-fix

    1 findings (1 fixable): 0 informational, 1 low, 0 medium, 0 high
    ");

    Ok(())
}

#[test]
fn test_config_not_number() -> anyhow::Result<()> {
    // dependabot-cooldown audit config is invalid.
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .input(input_under_test("neutral.yml"))
            .config(input_under_test("dependabot-cooldown/configs/invalid-cooldown-not-number.yml"))
            .output(OutputMode::Stderr)
            .run()?,
        @r#"
    🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@
      |
      = help: check the configuration for the 'dependabot-cooldown' rule
      = help: see: https://docs.zizmor.sh/audits/#dependabot-cooldown-configuration

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid syntax for audit `dependabot-cooldown`
        2: invalid type: string "lol", expected a nonzero usize
    "#
    );

    Ok(())
}

#[test]
fn test_invalid_config_zero_days() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .input(input_under_test("neutral.yml"))
            .config(input_under_test("dependabot-cooldown/configs/invalid-cooldown-zero-days.yml"))
            .output(OutputMode::Stderr)
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@
      |
      = help: check the configuration for the 'dependabot-cooldown' rule
      = help: see: https://docs.zizmor.sh/audits/#dependabot-cooldown-configuration

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid syntax for audit `dependabot-cooldown`
        2: invalid value: integer `0`, expected a nonzero usize
    "
    );

    Ok(())
}

#[test]
fn test_invalid_config_negative_days() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .input(input_under_test("neutral.yml"))
            .config(input_under_test("dependabot-cooldown/configs/invalid-cooldown-negative-days.yml"))
            .output(OutputMode::Stderr)
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@
      |
      = help: check the configuration for the 'dependabot-cooldown' rule
      = help: see: https://docs.zizmor.sh/audits/#dependabot-cooldown-configuration

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid syntax for audit `dependabot-cooldown`
        2: invalid value: integer `-1`, expected a nonzero usize
    "
    );

    Ok(())
}

#[test]
fn test_config_short_cooldown_permitted() -> anyhow::Result<()> {
    // A very short cooldown, but permitted by config.
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("dependabot-cooldown/default-days-too-short/dependabot.yml"))
            .config(input_under_test("dependabot-cooldown/configs/cooldown-one-day.yml"))
            .run()?,
        @"No findings to report. Good job!"
    );

    Ok(())
}
