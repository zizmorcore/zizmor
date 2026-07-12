//! End-to-end tests for parallel step support in zizmor.

use anyhow::Result;

use crate::common::{OutputMode, input_under_test, zizmor};

/// Basic sanity test for parallel steps handling.
///
/// Ensures that we (1) don't fail on inputs that use `parallel:`
/// and (2) we properly surface findings in steps under `parallel:`.
#[test]
fn test_basic() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .output(OutputMode::Both)
            .input(input_under_test(
                "parallel-steps/basic.yml"
            ))
            .run()?,
        @r#"
     INFO zizmor: 🌈 zizmor v@@VERSION@@
     WARN audit:audit{input=Workflow(file://@@INPUT@@)}: zizmor::models::workflow: one or more inputs contains parallel steps; zizmor's support for these is currently experimental. see https://docs.zizmor.sh/usage/#parallel-step for details
     INFO audit: zizmor: 🌈 completed @@INPUT@@
    error[template-injection]: code injection via template expansion
      --> @@INPUT@@:16:28
       |
    16 |             run: echo "${{ github.event.pull_request.title }}"
       |             ---            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ may expand into attacker-controllable code
       |             |
       |             this run block
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    3 findings (2 suppressed, 1 unsafe fixes): 0 informational, 0 low, 0 medium, 1 high
    "#);

    Ok(())
}
