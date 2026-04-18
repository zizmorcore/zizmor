use crate::common::{input_under_test, zizmor};

#[test]
fn test_regular_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(zizmor().input(input_under_test("unpinned-tools.yml")).run()?, @"
    warning[unpinned-tools]: unpinned underlying tools used by action are potentially vulnerable
      --> @@INPUT@@:16:9
       |
    16 |       - uses: aquasecurity/trivy-action@b6643a29fecd7f34b3597bc6acb0a98b03d33ff8 # 0.33.1
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this action's tool version is not pinned
       |
       = note: audit confidence → High

    warning[unpinned-tools]: unpinned underlying tools used by action are potentially vulnerable
      --> @@INPUT@@:19:11
       |
    17 |       - uses: aquasecurity/trivy-action@b6643a29fecd7f34b3597bc6acb0a98b03d33ff8 # 0.33.1
       |         ------------------------------------------------------------------------ this action
    18 |         with:
    19 |           version: latest
       |           ^^^^^^^^^^^^^^^ specifies `version: latest` which is unpinned
       |
       = note: audit confidence → High

    warning[unpinned-tools]: unpinned underlying tools used by action are potentially vulnerable
      --> @@INPUT@@:20:9
       |
    20 |       - uses: 1password/load-secrets-action@92467eb28f72e8255933372f1e0707c567ce2259 # v4.0.0
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this action's tool version is not pinned
       |
       = note: audit confidence → High

    warning[unpinned-tools]: unpinned underlying tools used by action are potentially vulnerable
      --> @@INPUT@@:23:11
       |
    21 |       - uses: 1password/load-secrets-action@92467eb28f72e8255933372f1e0707c567ce2259 # v4.0.0
       |         ---------------------------------------------------------------------------- this action
    22 |         with:
    23 |           version: latest
       |           ^^^^^^^^^^^^^^^ specifies `version: latest` which is unpinned
       |
       = note: audit confidence → High

    4 findings: 0 informational, 0 low, 4 medium, 0 high
    ");

    Ok(())
}
