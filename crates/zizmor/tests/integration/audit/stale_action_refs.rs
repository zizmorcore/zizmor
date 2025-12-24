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
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:15:13
       |
    15 |     - uses: actions/checkout@main
       |             ^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:18:13
       |
    18 |     - uses: actions/checkout@v4
       |             ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:21:13
       |
    21 |     - uses: actions/checkout@v4.2.2
       |             ^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    help[stale-action-refs]: commit hash does not point to a Git tag
      --> @@INPUT@@:34:13
       |
    34 |     - uses: actions/checkout@009b9ae9e446ad8d9b8c809870b0fbcc5e03573e
       |             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
       |
       = note: audit confidence → High

    4 findings: 0 informational, 1 low, 0 medium, 3 high
    "
    );

    Ok(())
}
