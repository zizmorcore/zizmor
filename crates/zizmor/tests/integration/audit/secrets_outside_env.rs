use anyhow::Result;

use crate::common::{input_under_test, zizmor};

#[test]
fn test_secrets_outside_env() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("secrets-outside-env.yml"))
            .run()?,
        @r"
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
