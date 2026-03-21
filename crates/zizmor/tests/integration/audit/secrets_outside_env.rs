use anyhow::Result;

use crate::common::{input_under_test, zizmor};

#[test]
fn test_secrets_outside_env() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("secrets-outside-env.yml"))
            .args(["--persona=auditor"])
            .run()?,
        @"
    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:20:20
       |
    12 |   test:
       |   ---- this job
    ...
    20 |           FOO: ${{ secrets.FOO }}
       |                    ^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    1 finding: 0 informational, 0 low, 1 medium, 0 high
    "
    );

    Ok(())
}
