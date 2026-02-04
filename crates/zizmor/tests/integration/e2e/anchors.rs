//! End-to-end tests for YAML anchor handling in zizmor.

use anyhow::Result;

use crate::common::{input_under_test, zizmor};

/// Basic sanity test for anchor handling.
///
/// This test verifies that zizmor correctly de-duplicates findings
/// that arise from YAML anchors (same concrete location, different symbolic routes).
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

    3 findings (2 suppressed, 1 fixable): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}
