use crate::common::{input_under_test, zizmor};
use anyhow::Result;

#[test]
fn test_unpinned_uses_pedantic() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses.yml"))
            .args(["--pedantic"])
            .run()?,
        @r"
    warning[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:21:24
       |
    21 |       - uses: docker://ubuntu
       |                        ^^^^^^ image is not pinned to a tag, branch, or hash ref
       |
       = note: audit confidence → High

    warning[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:27:24
       |
    27 |       - uses: docker://ghcr.io/pypa/gh-action-pypi-publish
       |                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ image is not pinned to a tag, branch, or hash ref
       |
       = note: audit confidence → High

    2 findings: 0 informational, 0 low, 2 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_unpinned_uses_default() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses.yml"))
            .run()?,
        @r"
    warning[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:21:24
       |
    21 |       - uses: docker://ubuntu
       |                        ^^^^^^ image is not pinned to a tag, branch, or hash ref
       |
       = note: audit confidence → High

    warning[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:27:24
       |
    27 |       - uses: docker://ghcr.io/pypa/gh-action-pypi-publish
       |                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ image is not pinned to a tag, branch, or hash ref
       |
       = note: audit confidence → High

    2 findings: 0 informational, 0 low, 2 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_action_pedantic() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses/action.yml"))
            .args(["--pedantic"])
            .run()?,
        @r"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:12:13
       |
    12 |       uses: asdf-vm/actions/setup@v3
       |             ^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:15:13
       |
    15 |       uses: asdf-vm/actions/setup@main
       |             ^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    2 findings: 0 informational, 0 low, 0 medium, 2 high
    "
    );

    Ok(())
}

#[test]
fn test_issue_433_repro() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses/issue-433-repro.yml"))
            .args(["--pedantic"])
            .run()?,
        @"No findings to report. Good job!"
    );

    Ok(())
}

/// Should not crash.
#[test]
fn test_issue_659_repro() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses/issue-659-repro.yml"))
            .args(["--pedantic"])
            .run()?,
        @"No findings to report. Good job!"
    );

    Ok(())
}

/// Default policies (no explicit config).
#[test]
fn test_default_config() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @r"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:22:15
       |
    22 |       - uses: pypa/gh-action-pypi-publish@release/v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    2 findings (1 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

/// Require all uses to be hash-pinned.
#[test]
fn test_hash_pin_everything_config() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .config(input_under_test(
                "unpinned-uses/configs/hash-pin-everything.yml"
            ))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @r"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:12:15
       |
    12 |       - uses: actions/setup-python@v4
       |               ^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:14:15
       |
    14 |       - uses: actions/checkout@v3
       |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:22:15
       |
    22 |       - uses: pypa/gh-action-pypi-publish@release/v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:24:15
       |
    24 |       - uses: github/codeql-action/init@v3
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:26:15
       |
    26 |       - uses: github/codeql-action/upload-sarif@v3
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    6 findings (1 suppressed): 0 informational, 0 low, 0 medium, 5 high
    "
    );

    Ok(())
}

/// Require all uses to be ref-pinned.
#[test]
fn test_ref_pin_everything_config() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .config(input_under_test(
                "unpinned-uses/configs/ref-pin-everything.yml"
            ))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @"No findings to report. Good job! (1 suppressed)"
    );

    Ok(())
}

#[test]
fn test_composite_config() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .config(input_under_test("unpinned-uses/configs/composite.yml"))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @r"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:12:15
       |
    12 |       - uses: actions/setup-python@v4
       |               ^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by actions/setup-python policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:24:15
       |
    24 |       - uses: github/codeql-action/init@v3
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:26:15
       |
    26 |       - uses: github/codeql-action/upload-sarif@v3
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    4 findings (1 suppressed): 0 informational, 0 low, 0 medium, 3 high
    "
    );

    Ok(())
}

#[test]
fn test_composite_config_2() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .config(input_under_test("unpinned-uses/configs/composite-2.yml"))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @r"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:24:15
       |
    24 |       - uses: github/codeql-action/init@v3
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by github/codeql-action/init policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:26:15
       |
    26 |       - uses: github/codeql-action/upload-sarif@v3
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by github/codeql-action/upload-sarif policy)
       |
       = note: audit confidence → High

    3 findings (1 suppressed): 0 informational, 0 low, 0 medium, 2 high
    "
    );

    Ok(())
}

#[test]
fn test_empty_config() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .config(input_under_test("unpinned-uses/configs/empty.yml"))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @r"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:12:15
       |
    12 |       - uses: actions/setup-python@v4
       |               ^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:14:15
       |
    14 |       - uses: actions/checkout@v3
       |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:22:15
       |
    22 |       - uses: pypa/gh-action-pypi-publish@release/v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:24:15
       |
    24 |       - uses: github/codeql-action/init@v3
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:26:15
       |
    26 |       - uses: github/codeql-action/upload-sarif@v3
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    6 findings (1 suppressed): 0 informational, 0 low, 0 medium, 5 high
    "
    );

    Ok(())
}

#[test]
fn test_invalid_wrong_policy_object() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .config(input_under_test(
                "unpinned-uses/configs/invalid-wrong-policy-object.yml"
            ))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@
      |
      = help: check the configuration for the 'unpinned-uses' rule
      = help: see: https://docs.zizmor.sh/audits/#unpinned-uses-configuration

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid syntax for audit `unpinned-uses`
        2: invalid type: sequence, expected a map
    "
    );

    Ok(())
}

#[test]
fn test_invalid_policy_syntax_1() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .config(input_under_test(
                "unpinned-uses/configs/invalid-policy-syntax-1.yml"
            ))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@
      |
      = help: check the configuration for the 'unpinned-uses' rule
      = help: see: https://docs.zizmor.sh/audits/#unpinned-uses-configuration

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid syntax for audit `unpinned-uses`
        2: invalid pattern: lol
    "
    );

    Ok(())
}

#[test]
fn test_invalid_policy_syntax_2() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .config(input_under_test(
                "unpinned-uses/configs/invalid-policy-syntax-2.yml"
            ))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@
      |
      = help: check the configuration for the 'unpinned-uses' rule
      = help: see: https://docs.zizmor.sh/audits/#unpinned-uses-configuration

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid syntax for audit `unpinned-uses`
        2: invalid pattern: foo/
    "
    );

    Ok(())
}

#[test]
fn test_invalid_policy_syntax_3() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .config(input_under_test(
                "unpinned-uses/configs/invalid-policy-syntax-3.yml"
            ))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@
      |
      = help: check the configuration for the 'unpinned-uses' rule
      = help: see: https://docs.zizmor.sh/audits/#unpinned-uses-configuration

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid syntax for audit `unpinned-uses`
        2: invalid pattern: */foo
    "
    );

    Ok(())
}

#[test]
fn test_invalid_policy_syntax_4() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .config(input_under_test(
                "unpinned-uses/configs/invalid-policy-syntax-4.yml"
            ))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@
      |
      = help: check the configuration for the 'unpinned-uses' rule
      = help: see: https://docs.zizmor.sh/audits/#unpinned-uses-configuration

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid syntax for audit `unpinned-uses`
        2: invalid pattern: foo/b*r
    "
    );

    Ok(())
}

#[test]
fn test_invalid_policy_syntax_5() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .config(input_under_test(
                "unpinned-uses/configs/invalid-policy-syntax-5.yml"
            ))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@
      |
      = help: check the configuration for the 'unpinned-uses' rule
      = help: see: https://docs.zizmor.sh/audits/#unpinned-uses-configuration

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid syntax for audit `unpinned-uses`
        2: unknown variant `does not exist`, expected one of `any`, `ref-pin`, `hash-pin`
    "
    );

    Ok(())
}

#[test]
fn test_invalid_policy_syntax_6() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .config(input_under_test(
                "unpinned-uses/configs/invalid-policy-syntax-6.yml"
            ))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid `unpinned-uses` config
        2: cannot use exact ref patterns here: `foo/bar@v1`
    "
    );

    Ok(())
}
