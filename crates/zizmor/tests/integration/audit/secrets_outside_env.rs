use anyhow::Result;

use crate::common::{OutputMode, input_under_test, zizmor};

#[test]
fn test_secrets_outside_env() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("secrets-outside-env.yml"))
            .run()?,
        @"
    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:12:23
       |
     6 |   test:
       |   ---- this job
    ...
    12 |         run: echo ${{ secrets.FOO }}
       |                       ^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    4 findings (3 suppressed): 0 informational, 0 low, 1 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_config_invalid_variant() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
        .expects_failure(1)
        .input(input_under_test("neutral.yml"))
        .config(input_under_test("secrets-outside-env/configs/invalid-variant.yml"))
        .output(OutputMode::Stderr)
        .run()?,
        @"
    🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@
      |
      = help: check the configuration for the 'secrets-outside-env' rule
      = help: see: https://docs.zizmor.sh/audits/#secrets-outside-env-configuration

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid syntax for audit `secrets-outside-env`
        2: unknown field `mystery-variant`, expected `allow`
    "
    );
    Ok(())
}

#[test]
fn test_config_allow_none() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
        .input(input_under_test("secrets-outside-env/multiple-secrets.yml"))
        .config(input_under_test("secrets-outside-env/configs/allow-none.yml"))
        .run()?,
        @"
    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:12:23
       |
     6 |   test:
       |   ---- this job
    ...
    12 |         run: echo ${{ secrets.NOT_SO_SECRET }}
       |                       ^^^^^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:15:23
       |
     6 |   test:
       |   ---- this job
    ...
    15 |         run: echo ${{ secrets.not_so_secret }}
       |                       ^^^^^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:18:23
       |
     6 |   test:
       |   ---- this job
    ...
    18 |         run: echo ${{ secrets['not_so_secret'] }}
       |                       ^^^^^^^^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:21:23
       |
     6 |   test:
       |   ---- this job
    ...
    21 |         run: echo ${{ secrets.ALSO_NOT_SO_SECRET }}
       |                       ^^^^^^^^^^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    13 findings (9 suppressed): 0 informational, 0 low, 4 medium, 0 high
    "
    );
    Ok(())
}

#[test]
fn test_config_allow_one() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
        .input(input_under_test("secrets-outside-env/multiple-secrets.yml"))
        .config(input_under_test("secrets-outside-env/configs/allow-one.yml"))
        .run()?,
        @"
    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:21:23
       |
     6 |   test:
       |   ---- this job
    ...
    21 |         run: echo ${{ secrets.ALSO_NOT_SO_SECRET }}
       |                       ^^^^^^^^^^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    10 findings (9 suppressed): 0 informational, 0 low, 1 medium, 0 high
    "
    );
    Ok(())
}

#[test]
fn test_config_allow_some() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
        .input(input_under_test("secrets-outside-env/multiple-secrets.yml"))
        .config(input_under_test("secrets-outside-env/configs/allow-some.yml"))
        .run()?,
        @"No findings to report. Good job! (9 suppressed)"
    );
    Ok(())
}
