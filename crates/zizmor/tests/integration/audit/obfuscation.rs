use crate::common::{input_under_test, zizmor};
use anyhow::Result;

#[test]
fn test_obfuscation() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("obfuscation.yml"))
            .run()?,
        @"
    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:13:9
       |
    13 |       - uses: actions/checkout/@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ actions reference contains empty component
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:16:9
       |
    16 |       - uses: actions/checkout////@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
       |         |
       |         actions reference contains empty component
       |         actions reference contains empty component
       |         actions reference contains empty component
       |         actions reference contains empty component
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:19:9
       |
    19 |       - uses: github/codeql-action/./init@b8d3b6e8af63cde30bdc382c0bc28114f4346c88 # v2.28.1
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ actions reference contains '.'
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:20:9
       |
    20 |       - uses: actions/checkout/.@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ actions reference contains '.'
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:23:9
       |
    23 |       - uses: actions/cache/save/../save@0057852bfaa89a56745cba8c7296529d2fc39830 # v4.3.0
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ actions reference contains '..'
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:26:9
       |
    26 |       - uses: actions/cache/../../save@0057852bfaa89a56745cba8c7296529d2fc39830 # v4.3.0
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
       |         |
       |         actions reference contains '..'
       |         actions reference contains '..'
       |
       = note: audit confidence → High

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:34:20
       |
    34 |           echo ${{ '' }}
       |                    ^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:35:20
       |
    35 |           echo ${{ 'a' }}
       |                    ^^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:36:20
       |
    36 |           echo ${{ true }}
       |                    ^^^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:37:20
       |
    37 |           echo ${{ true && false }}
       |                    ^^^^^^^^^^^^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:38:20
       |
    38 |           echo ${{ true || false }}
       |                    ^^^^^^^^^^^^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:39:20
       |
    39 |           echo ${{ 1 > 2 || true }}
       |                    ^^^^^^^^^^^^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:40:20
       |
    40 |           echo ${{ 1 != 2}}
       |                    ^^^^^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:44:20
       |
    44 |           echo ${{ format('{0}', 'abc') }}
       |                    ^^^^^^^^^^^^^^^^^^^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:45:20
       |
    45 |           echo ${{ format('{0} {1}', 'abc', 'def') }}
       |                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:46:20
       |
    46 |           echo ${{ format('{0} {1}', 'abc', format('{0}', 'def')) }}
       |                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:47:20
       |
    47 |           echo ${{ startsWith('abc', 'a') }}
       |                    ^^^^^^^^^^^^^^^^^^^^^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:48:20
       |
    48 |           echo ${{ ENDSWITH('abc', 'c') }}
       |                    ^^^^^^^^^^^^^^^^^^^^ can be replaced by its static evaluation
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:53:60
       |
    53 |           echo ${{ format('{0}, {1}', github.event.number, format('{0}', 'abc')) }}
       |                                                            ^^^^^^^^^^^^^^^^^^^^ can be reduced to a constant
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:55:99
       |
    55 |           echo ${{ format('{0}, {1}', github.event.number, format('{0} {1}', github.event.number, true || false)) }}
       |                                                                                                   ^^^^^^^^^^^^^ can be reduced to a constant
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    40 findings (1 ignored, 19 suppressed, 19 fixable): 0 informational, 20 low, 0 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_computed_indices_pedantic() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("obfuscation/computed-indices.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @r#"
    help[obfuscation]: obfuscated usage of GitHub Actions features
      --> @@INPUT@@:18:23
       |
    18 |       - if: ${{ inputs[inputs.foo] }}
       |                       ^^^^^^^^^^^^ index expression is computed
       |
       = note: audit confidence → High

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:11:3
       |
    11 | /   computed-indices:
    12 | |     name: computed-indices
    13 | |     runs-on: ubuntu-latest
    ...  |
    19 | |         run: |
    20 | |           echo "hello"
       | |_______________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    2 findings: 0 informational, 2 low, 0 medium, 0 high
    "#
    );

    Ok(())
}

#[test]
fn test_issue_1177_repro_pedantic() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("obfuscation/issue-1177-repro.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @r#"
    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:13:3
       |
    13 | /   issue-1177-repro:
    14 | |     # we should not flag this as an obfuscation finding, since it's
    15 | |     # not actually constant reducible to `!contains(Array, ...)`
    16 | |     if: ${{ !contains(fromJSON('["push", "pull_request"]'), github.event_name) }}
    ...  |
    19 | |     steps:
    20 | |       - run: true
       | |__________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    1 finding: 0 informational, 1 low, 0 medium, 0 high
    "#
    );

    Ok(())
}
