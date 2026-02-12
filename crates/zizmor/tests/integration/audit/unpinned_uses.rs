use crate::common::{input_under_test, zizmor};
use anyhow::Result;

#[test]
fn test_unpinned_uses_pedantic() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses.yml"))
            .args(["--pedantic"])
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:16:15
       |
    16 |       - uses: actions/checkout@v3
       |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

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

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:11:3
       |
    11 | /   unpinned-0:
    12 | |     name: unpinned-0
    13 | |     runs-on: ubuntu-latest
    14 | |     steps:
    ...  |
    29 | |           entrypoint: /bin/echo
    30 | |           args: hello!
       | |_______________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    4 findings: 0 informational, 1 low, 2 medium, 1 high
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
        @"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:16:15
       |
    16 |       - uses: actions/checkout@v3
       |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

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

    4 findings (1 suppressed): 0 informational, 0 low, 2 medium, 1 high
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
        @"
    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:14:3
       |
    14 | /   issue-433-repro:
    15 | |     name: issue-433-repro
    16 | |     runs-on: ubuntu-latest
    17 | |     steps:
    ...  |
    23 | |         # no pedantic finding for tag-pinned local workflows
    24 | |         uses: ./.github/workflows/reusable.yml@tag
       | |___________________________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    1 finding: 0 informational, 1 low, 0 medium, 0 high
    "
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
        @"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:24:15
       |
    24 |         uses: actions/setup-node@v4
       |               ^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:14:3
       |
    14 | /   test-itg:
    15 | |     name: test-itg
    16 | |     runs-on: ${{ matrix.os }}
    17 | |     strategy:
    ...  |
    25 | |         with:
    26 | |           node-version: ${{ env.NODE_VERSION }}
       | |________________________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    2 findings: 0 informational, 1 low, 0 medium, 1 high
    "
    );

    Ok(())
}

/// Reproduction case for #1543:
/// `uses:` clauses that use block-style YAML strings should be handled
/// correctly and shouldn't cause crashes in subfeature extraction.
#[test]
fn test_issue_1543_repro() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses/issue-1543-repro.yml"))
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:18:11
       |
    18 |           actions/checkout@v4
       |           ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    3 findings (2 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "
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
        @"
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

    7 findings (2 suppressed): 0 informational, 0 low, 0 medium, 5 high
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
        @"
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

    7 findings (2 suppressed): 0 informational, 0 low, 0 medium, 5 high
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
        @"No findings to report. Good job! (2 suppressed)"
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
        @"
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

    5 findings (2 suppressed): 0 informational, 0 low, 0 medium, 3 high
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
        @"
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

    4 findings (2 suppressed): 0 informational, 0 low, 0 medium, 2 high
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
        @"
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

    7 findings (2 suppressed): 0 informational, 0 low, 0 medium, 5 high
    "
    );

    Ok(())
}

#[test]
fn test_invalid_wrong_policy_object() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(1)
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
            .expects_failure(1)
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
            .expects_failure(1)
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
            .expects_failure(1)
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
            .expects_failure(1)
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
            .expects_failure(1)
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
            .expects_failure(1)
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

#[test]
fn test_reusable_workflow_unpinned() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses/reusable-workflow-unpinned.yml"))
            .run()?,
        @r"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:17:11
       |
    17 |     uses: owner/repo/.github/workflows/reusable.yml@main
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:21:11
       |
    21 |     uses: owner/repo/.github/workflows/reusable.yml@v1
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    2 findings: 0 informational, 0 low, 0 medium, 2 high
    "
    );

    Ok(())
}
