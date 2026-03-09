//! End-to-end tests for YAML anchor handling in zizmor.

use anyhow::Result;

use crate::common::{input_under_test, zizmor};

/// Basic sanity test for anchor handling.
///
/// This test reveals duplicate findings, since zizmor doesn't
/// (yet) de-duplicate findings that arise from YAML anchors.
#[test]
fn test_basic() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "anchors/basic.yml"
            ))
            .run()?,
        @r#"
    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:13:31
       |
    12 |       - run: &run |
       |         --- this run block
    13 |           "doing a thing: ${{ github.event.issue.title }}"
       |                               ^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:13:31
       |
    13 |           "doing a thing: ${{ github.event.issue.title }}"
       |                               ^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
    14 |
    15 |       - run: *run
       |         --- this run block
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:18:49
       |
    18 |         run: &print-info echo "Building ref ${{ github.ref }}"
       |         --- this run block                      ^^^^^^^^^^ may expand into attacker-controllable code
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:18:49
       |
    18 |         run: &print-info echo "Building ref ${{ github.ref }}"
       |                                                 ^^^^^^^^^^ may expand into attacker-controllable code
    ...
    21 |         run: *print-info
       |         --- this run block
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    5 findings (1 suppressed, 4 fixable): 0 informational, 0 low, 0 medium, 4 high
    "#
    );

    Ok(())
}
