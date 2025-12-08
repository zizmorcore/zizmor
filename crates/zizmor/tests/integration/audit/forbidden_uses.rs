use crate::common::{OutputMode, input_under_test, zizmor};
use anyhow::Result;

#[test]
fn test_allow_all() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .config(input_under_test("forbidden-uses/configs/allow-all.yml"))
            .input(input_under_test(
                "forbidden-uses/forbidden-uses-menagerie.yml"
            ))
            .run()?,
        @"No findings to report. Good job! (1 suppressed)"
    );

    Ok(())
}

#[test]
fn test_deny_all() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .config(input_under_test("forbidden-uses/configs/deny-all.yml"))
            .input(input_under_test(
                "forbidden-uses/forbidden-uses-menagerie.yml"
            ))
            .run()?,
        @r"
    error[forbidden-uses]: forbidden action used
      --> @@INPUT@@:13:15
       |
    13 |       - uses: actions/setup-python@v4
       |               ^^^^^^^^^^^^^^^^^^^^^^^ use of this action is forbidden
       |
       = note: audit confidence → High

    error[forbidden-uses]: forbidden action used
      --> @@INPUT@@:14:15
       |
    14 |       - uses: pypa/gh-action-pypi-publish@release/v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ use of this action is forbidden
       |
       = note: audit confidence → High

    error[forbidden-uses]: forbidden action used
      --> @@INPUT@@:15:15
       |
    15 |       - uses: actions/checkout@v4
       |               ^^^^^^^^^^^^^^^^^^^ use of this action is forbidden
       |
       = note: audit confidence → High

    4 findings (1 suppressed): 0 informational, 0 low, 0 medium, 3 high
    "
    );

    Ok(())
}

#[test]
fn test_allow_some() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .config(input_under_test("forbidden-uses/configs/allow-some.yml"))
            .input(input_under_test(
                "forbidden-uses/forbidden-uses-menagerie.yml"
            ))
            .run()?,
        @r"
    error[forbidden-uses]: forbidden action used
      --> @@INPUT@@:13:15
       |
    13 |       - uses: actions/setup-python@v4
       |               ^^^^^^^^^^^^^^^^^^^^^^^ use of this action is forbidden
       |
       = note: audit confidence → High

    2 findings (1 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

#[test]
fn test_deny_some() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .config(input_under_test("forbidden-uses/configs/deny-some.yml"))
            .input(input_under_test(
                "forbidden-uses/forbidden-uses-menagerie.yml"
            ))
            .run()?,
        @r"
    error[forbidden-uses]: forbidden action used
      --> @@INPUT@@:14:15
       |
    14 |       - uses: pypa/gh-action-pypi-publish@release/v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ use of this action is forbidden
       |
       = note: audit confidence → High

    error[forbidden-uses]: forbidden action used
      --> @@INPUT@@:15:15
       |
    15 |       - uses: actions/checkout@v4
       |               ^^^^^^^^^^^^^^^^^^^ use of this action is forbidden
       |
       = note: audit confidence → High

    3 findings (1 suppressed): 0 informational, 0 low, 0 medium, 2 high
    "
    );

    Ok(())
}

#[test]
fn test_deny_some_refs() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .config(input_under_test("forbidden-uses/configs/deny-some-refs.yml"))
            .input(input_under_test(
                "forbidden-uses/forbidden-uses-menagerie.yml"
            ))
            .run()?,
        @r"
    error[forbidden-uses]: forbidden action used
      --> @@INPUT@@:13:15
       |
    13 |       - uses: actions/setup-python@v4
       |               ^^^^^^^^^^^^^^^^^^^^^^^ use of this action is forbidden
       |
       = note: audit confidence → High

    error[forbidden-uses]: forbidden action used
      --> @@INPUT@@:14:15
       |
    14 |       - uses: pypa/gh-action-pypi-publish@release/v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ use of this action is forbidden
       |
       = note: audit confidence → High

    3 findings (1 suppressed): 0 informational, 0 low, 0 medium, 2 high
    "
    );

    Ok(())
}

#[test]
fn test_allow_some_refs() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .config(input_under_test("forbidden-uses/configs/allow-some-refs.yml"))
            .input(input_under_test(
                "forbidden-uses/forbidden-uses-menagerie.yml"
            ))
            .run()?,
        @r"
    error[forbidden-uses]: forbidden action used
      --> @@INPUT@@:15:15
       |
    15 |       - uses: actions/checkout@v4
       |               ^^^^^^^^^^^^^^^^^^^ use of this action is forbidden
       |
       = note: audit confidence → High

    2 findings (1 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

#[test]
fn test_config_invalid_pattern() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .input(input_under_test("neutral.yml"))
            .config(input_under_test(
                "forbidden-uses/configs/invalid-pattern.yml"
            ))
            .output(OutputMode::Stderr)
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@
      |
      = help: check the configuration for the 'forbidden-uses' rule
      = help: see: https://docs.zizmor.sh/audits/#forbidden-uses-configuration

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid syntax for audit `forbidden-uses`
        2: invalid pattern: */*
    "
    );

    Ok(())
}

#[test]
fn test_config_invalid_variant() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .input(input_under_test("neutral.yml"))
            .config(input_under_test(
                "forbidden-uses/configs/invalid-variant.yml"
            ))
            .output(OutputMode::Stderr)
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@
      |
      = help: check the configuration for the 'forbidden-uses' rule
      = help: see: https://docs.zizmor.sh/audits/#forbidden-uses-configuration

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid syntax for audit `forbidden-uses`
        2: unknown variant `mystery-variant`, expected `allow` or `deny`
    "
    );

    Ok(())
}
