use crate::common::{input_under_test, zizmor};
use anyhow::Result;

/// Test with pedantic persona (should find issues)
#[test]
fn test_undocumented_permissions_pedantic() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("undocumented-permissions.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @r"
    help[undocumented-permissions]: permissions without explanatory comments
     --> @@INPUT@@:8:3
      |
    8 |   packages: read
      |   ^^^^^^^^^^^^^^ needs an explanatory comment
      |
      = note: audit confidence → High

    help[undocumented-permissions]: permissions without explanatory comments
      --> @@INPUT@@:33:7
       |
    33 |       contents: write
       |       ^^^^^^^^^^^^^^^ needs an explanatory comment
    34 |       packages: write
       |       ^^^^^^^^^^^^^^^ needs an explanatory comment
    35 |       actions: write
       |       ^^^^^^^^^^^^^^ needs an explanatory comment
       |
       = note: audit confidence → High

    help[undocumented-permissions]: permissions without explanatory comments
      --> @@INPUT@@:48:7
       |
    48 |       packages: write #
       |       ^^^^^^^^^^^^^^^ needs an explanatory comment
    49 |       actions: write #
       |       ^^^^^^^^^^^^^^ needs an explanatory comment
       |
       = note: audit confidence → High

    help[undocumented-permissions]: permissions without explanatory comments
      --> @@INPUT@@:60:7
       |
    60 |       metadata: read
       |       ^^^^^^^^^^^^^^ needs an explanatory comment
    61 |       packages: write #
       |       ^^^^^^^^^^^^^^^ needs an explanatory comment
       |
       = note: audit confidence → High

    5 findings (1 ignored): 0 informational, 4 low, 0 medium, 0 high
    "
    );

    Ok(())
}

/// Test with regular persona (should not find issues)
#[test]
fn test_undocumented_permissions_default() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("undocumented-permissions.yml"))
            .run()?,
        @"No findings to report. Good job! (5 suppressed)"
    );

    Ok(())
}

/// Test with properly documented permissions (should not find issues even with pedantic)
#[test]
fn test_documented_permissions_pedantic() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("undocumented-permissions/documented.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @r"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:23:15
       |
    23 |       - uses: actions/checkout@v4
       |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:37:15
       |
    37 |       - uses: actions/checkout@v4
       |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:50:15
       |
    50 |       - uses: actions/checkout@v4
       |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    4 findings (1 ignored): 0 informational, 0 low, 0 medium, 3 high
    "
    );

    Ok(())
}

/// Test with only "contents: read" (should not trigger rule)
#[test]
fn test_contents_read_only_pedantic() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "undocumented-permissions/contents-read-only.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?,
        @r"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:21:15
       |
    21 |       - uses: actions/checkout@v4
       |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    1 finding: 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

/// Test with empty permissions (should not trigger rule)
#[test]
fn test_empty_permissions_pedantic() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "undocumented-permissions/empty-permissions.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?,
        @r"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:19:15
       |
    19 |       - uses: actions/checkout@v4
       |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    1 finding: 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

/// Test with contents: read plus other permissions (should trigger rule)
#[test]
fn test_contents_read_with_other_pedantic() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "undocumented-permissions/contents-read-with-other.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?,
        @r"
    error[excessive-permissions]: overly broad permissions
     --> @@INPUT@@:8:3
      |
    8 |   issues: write
      |   ^^^^^^^^^^^^^ issues: write is overly broad at the workflow level
      |
      = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:19:15
       |
    19 |       - uses: actions/checkout@v4
       |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    help[undocumented-permissions]: permissions without explanatory comments
     --> @@INPUT@@:8:3
      |
    8 |   issues: write
      |   ^^^^^^^^^^^^^ needs an explanatory comment
      |
      = note: audit confidence → High

    3 findings: 0 informational, 1 low, 0 medium, 2 high
    "
    );

    Ok(())
}

/// Test with partially documented permissions (should ideally only flag undocumented ones)
#[test]
fn test_partially_documented_pedantic() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "undocumented-permissions/partially-documented.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?,
        @r"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:25:15
       |
    25 |       - uses: actions/checkout@v4
       |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:38:15
       |
    38 |       - uses: actions/checkout@v4
       |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    help[undocumented-permissions]: permissions without explanatory comments
     --> @@INPUT@@:8:3
      |
    8 |   packages: read
      |   ^^^^^^^^^^^^^^ needs an explanatory comment
      |
      = note: audit confidence → High

    help[undocumented-permissions]: permissions without explanatory comments
      --> @@INPUT@@:22:7
       |
    22 |       actions: write
       |       ^^^^^^^^^^^^^^ needs an explanatory comment
       |
       = note: audit confidence → High

    help[undocumented-permissions]: permissions without explanatory comments
      --> @@INPUT@@:35:7
       |
    35 |       contents: write
       |       ^^^^^^^^^^^^^^^ needs an explanatory comment
    36 |       issues: read
       |       ^^^^^^^^^^^^ needs an explanatory comment
       |
       = note: audit confidence → High

    7 findings (2 ignored): 0 informational, 3 low, 0 medium, 2 high
    "
    );

    Ok(())
}
