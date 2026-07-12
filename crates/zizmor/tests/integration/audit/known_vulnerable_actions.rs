use anyhow::Result;

use crate::common::{NetworkMode, input_under_test, zizmor};

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_default_persona() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(NetworkMode::AssertOnline)
            .input(input_under_test("known-vulnerable-actions/setup-php.yml"))
            .run()?,
        @"
    warning[known-vulnerable-actions]: action has a known vulnerability
      --> @@INPUT@@:17:9
       |
    17 |       - uses: shivammathur/setup-php@accd6127cb78bee3e8082180cb391013d204ef9f # 2.37.0
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ GHSA-5wxr-w449-57cm
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    warning[known-vulnerable-actions]: action has a known vulnerability
      --> @@INPUT@@:17:9
       |
    17 |       - uses: shivammathur/setup-php@accd6127cb78bee3e8082180cb391013d204ef9f # 2.37.0
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ GHSA-pqwm-q9pv-ph8r
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    2 findings (2 unsafe fixes): 0 informational, 0 low, 2 medium, 0 high
    "
    );

    Ok(())
}

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_config_allow() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(NetworkMode::AssertOnline)
            .input(input_under_test("known-vulnerable-actions/setup-php.yml"))
            .config(input_under_test(
                "known-vulnerable-actions/configs/allow.yml"
            ))
            .run()?,
        @"No findings to report. Good job!"
    );

    Ok(())
}
