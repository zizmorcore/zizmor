use crate::common::{input_under_test, zizmor};

#[test]
fn overprovisioned_secrets() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("overprovisioned-secrets.yml"))
            .run()?,
        @r"
    warning[overprovisioned-secrets]: excessively provisioned secrets
      --> @@INPUT@@:16:18
       |
    16 |           stuff: ${{ format('{0}', toJSON(secrets)) }}
       |                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ injects the entire secrets context into the runner
       |
       = note: audit confidence → High

    warning[overprovisioned-secrets]: excessively provisioned secrets
      --> @@INPUT@@:25:25
       |
    25 |           secrets_json: ${{ toJSON(secrets) }}
       |                         ^^^^^^^^^^^^^^^^^^^^^^ injects the entire secrets context into the runner
       |
       = note: audit confidence → High

    4 findings (1 ignored, 1 suppressed): 0 informational, 0 low, 2 medium, 0 high
    "
    );

    Ok(())
}
