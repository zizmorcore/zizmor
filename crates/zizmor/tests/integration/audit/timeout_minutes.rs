use crate::common::{OutputMode, input_under_test, zizmor};

#[test]
fn test_regular_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor().input(input_under_test("timeout-minutes.yml")).run()?,
        @"No findings to report. Good job! (2 suppressed)"
    );

    Ok(())
}

#[test]
fn test_pedantic_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("timeout-minutes.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @r"
    help[timeout-minutes]: missing timeout-minutes
      --> @@INPUT@@:31:3
       |
    31 | /   without-timeout:
    32 | |     name: without-timeout
    33 | |     runs-on: ubuntu-latest
    34 | |     steps:
    35 | |       - name: 4-not-ok
    36 | |         run: echo not ok
       | |________________________^ job missing timeout-minutes
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[timeout-minutes]: missing timeout-minutes
      --> @@INPUT@@:45:9
       |
    45 |         - name: 6-not-ok
       |  _________^
    46 | |         run: echo not ok
       | |_________________________^ step missing timeout-minutes
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    2 findings (2 unsafe fixes): 0 informational, 2 low, 0 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_auditor_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("timeout-minutes.yml"))
            .args(["--persona=auditor"])
            .run()?,
        @r"
    help[timeout-minutes]: missing timeout-minutes
      --> @@INPUT@@:31:3
       |
    31 | /   without-timeout:
    32 | |     name: without-timeout
    33 | |     runs-on: ubuntu-latest
    34 | |     steps:
    35 | |       - name: 4-not-ok
    36 | |         run: echo not ok
       | |________________________^ job missing timeout-minutes
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[timeout-minutes]: missing timeout-minutes
      --> @@INPUT@@:45:9
       |
    45 |         - name: 6-not-ok
       |  _________^
    46 | |         run: echo not ok
       | |_________________________^ step missing timeout-minutes
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    2 findings (2 unsafe fixes): 0 informational, 2 low, 0 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_config_not_number() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(1)
            .input(input_under_test("neutral.yml"))
            .config(input_under_test("timeout-minutes/configs/invalid-timeout-not-number.yml"))
            .output(OutputMode::Stderr)
            .run()?,
        @r#"
     INFO zizmor: 🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@
      |
      = help: check the configuration for the 'timeout-minutes' rule
      = help: see: https://docs.zizmor.sh/audits/#timeout-minutes-configuration

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid syntax for audit `timeout-minutes`
        2: invalid type: string "lol", expected a nonzero usize
    "#
    );

    Ok(())
}

#[test]
fn test_invalid_config_zero_minutes() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(1)
            .input(input_under_test("neutral.yml"))
            .config(input_under_test("timeout-minutes/configs/invalid-timeout-zero-minutes.yml"))
            .output(OutputMode::Stderr)
            .run()?,
        @r"
     INFO zizmor: 🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@
      |
      = help: check the configuration for the 'timeout-minutes' rule
      = help: see: https://docs.zizmor.sh/audits/#timeout-minutes-configuration

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid syntax for audit `timeout-minutes`
        2: invalid value: integer `0`, expected a nonzero usize
    "
    );

    Ok(())
}

#[test]
fn test_invalid_config_negative_minutes() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(1)
            .input(input_under_test("neutral.yml"))
            .config(input_under_test("timeout-minutes/configs/invalid-timeout-negative-minutes.yml"))
            .output(OutputMode::Stderr)
            .run()?,
        @r"
     INFO zizmor: 🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@
      |
      = help: check the configuration for the 'timeout-minutes' rule
      = help: see: https://docs.zizmor.sh/audits/#timeout-minutes-configuration

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid syntax for audit `timeout-minutes`
        2: invalid value: integer `-1`, expected a nonzero usize
    "
    );

    Ok(())
}

#[test]
fn test_valid_config() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("neutral.yml"))
            .config(input_under_test("timeout-minutes/configs/timeout-42-minutes.yml"))
            .run()?,
             @"No findings to report. Good job! (1 suppressed)"

    );

    Ok(())
}
