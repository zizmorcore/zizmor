use crate::common::{input_under_test, zizmor};

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_pedantic_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("stale-action-refs.yml"))
            .offline(false)
            .args(["--persona=pedantic"])
            .run()?,
        @r"
    help[stale-action-refs]: commit hash does not point to a Git tag
      --> @@INPUT@@:34:13
       |
    34 |     - uses: actions/checkout@009b9ae9e446ad8d9b8c809870b0fbcc5e03573e
       |             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
       |
       = note: audit confidence → High

    1 finding: 0 informational, 1 low, 0 medium, 0 high
    "
    );

    Ok(())
}
