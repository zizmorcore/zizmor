use crate::common::{input_under_test, zizmor};

#[test]
fn test_normal_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unredacted-secrets.yml"))
            .run()?,
        @r"
    warning[unredacted-secrets]: leaked secret values
      --> @@INPUT@@:17:18
       |
    17 |           stuff: ${{ fromJSON(secrets.password) }}
       |                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ bypasses secret redaction
       |
       = note: audit confidence → High

    warning[unredacted-secrets]: leaked secret values
      --> @@INPUT@@:20:23
       |
    20 |           otherstuff: ${{ fromJson(secrets.otherstuff).field }}
       |                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ bypasses secret redaction
       |
       = note: audit confidence → High

    3 findings (1 suppressed): 0 informational, 0 low, 2 medium, 0 high
    "
    );

    Ok(())
}
