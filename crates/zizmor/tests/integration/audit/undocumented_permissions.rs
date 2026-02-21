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
        @r#"
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

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:15:3
       |
    15 | /   test-job-1:
    16 | |     name: Test Job 1
    17 | |     runs-on: ubuntu-latest
    18 | |     # This job's permissions block has a comment explaining why
    ...  |
    25 | |           persist-credentials: false
    26 | |       - run: echo "Test"
       | |________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:28:3
       |
    28 | /   test-job-2:
    29 | |     name: Test Job 2
    30 | |     runs-on: ubuntu-latest
    31 | |     # Missing individual permission comments
    ...  |
    39 | |           persist-credentials: false
    40 | |       - run: echo "Test"
       | |________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:42:3
       |
    42 | /   test-job-3:
    43 | |     name: Test Job 3 - Empty Comments
    44 | |     runs-on: ubuntu-latest
    45 | |     # Permissions have empty comments
    ...  |
    53 | |           persist-credentials: false
    54 | |       - run: echo "Test"
       | |________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:56:3
       |
    56 | /   test-job-4:
    57 | |     name: Test Job 4 - Mixed Documentation
    58 | |     runs-on: ubuntu-latest
    59 | |     permissions:
    ...  |
    66 | |           persist-credentials: false
    67 | |       - run: echo "Test"
       | |________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:69:3
       |
    69 | /   test-job-5:
    70 | |     name: Test Job 5 - read contents
    71 | |     runs-on: ubuntu-latest
    72 | |     # Only one `contents: read` permission, no comment needed
    ...  |
    78 | |           persist-credentials: false
    79 | |       - run: echo "Test"
       | |_________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    10 findings (1 ignored): 0 informational, 9 low, 0 medium, 0 high
    "#
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
        @"No findings to report. Good job! (10 suppressed)"
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
        @r#"
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

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:15:3
       |
    15 | /   test-job-1:
    16 | |     name: Test Job 1
    17 | |     runs-on: ubuntu-latest
    18 | |     # Override workflow permissions for this specific job
    ...  |
    25 | |           persist-credentials: false
    26 | |       - run: echo "Test"
       | |________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:28:3
       |
    28 | /   test-job-2:
    29 | |     name: Test Job 2
    30 | |     runs-on: ubuntu-latest
    31 | |     # Specific permissions documented for admin operations
    ...  |
    39 | |           persist-credentials: false
    40 | |       - run: echo "Test"
       | |________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:42:3
       |
    42 | /   test-job-3:
    43 | |     name: Test Job 3
    44 | |     runs-on: ubuntu-latest
    45 | |     # Specific permissions documented for analysis job
    ...  |
    52 | |           persist-credentials: false
    53 | |       - run: echo "Test"
       | |_________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    7 findings (1 ignored): 0 informational, 3 low, 0 medium, 3 high
    "#
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
        @r#"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:21:15
       |
    21 |       - uses: actions/checkout@v4
       |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:14:3
       |
    14 | /   test-job:
    15 | |     name: Test Job
    16 | |     runs-on: ubuntu-latest
    17 | |     # This should also NOT trigger the rule
    ...  |
    23 | |           persist-credentials: false
    24 | |       - run: echo "Test"
       | |________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    2 findings: 0 informational, 1 low, 0 medium, 1 high
    "#
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
        @r#"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:19:15
       |
    19 |       - uses: actions/checkout@v4
       |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:13:3
       |
    13 | /   test-job:
    14 | |     name: Test Job
    15 | |     runs-on: ubuntu-latest
    16 | |     # This should also NOT trigger the rule
    ...  |
    21 | |           persist-credentials: false
    22 | |       - run: echo "Test"
       | |________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    2 findings: 0 informational, 1 low, 0 medium, 1 high
    "#
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
        @r#"
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

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:15:3
       |
    15 | /   test-job:
    16 | |     name: Test Job
    17 | |     runs-on: ubuntu-latest
    18 | |     steps:
    ...  |
    21 | |           persist-credentials: false
    22 | |       - run: echo "Test"
       | |_________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    4 findings: 0 informational, 2 low, 0 medium, 2 high
    "#
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
        @r#"
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

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:16:3
       |
    16 | /   test-job-1:
    17 | |     name: Test Job 1
    18 | |     runs-on: ubuntu-latest
    19 | |     # Job with partial documentation
    ...  |
    27 | |           persist-credentials: false
    28 | |       - run: echo "Test"
       | |________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:30:3
       |
    30 | /   test-job-2:
    31 | |     name: Test Job 2
    32 | |     runs-on: ubuntu-latest
    33 | |     # Job with no documentation at all
    ...  |
    40 | |           persist-credentials: false
    41 | |       - run: echo "Test"
       | |_________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    9 findings (2 ignored): 0 informational, 5 low, 0 medium, 2 high
    "#
    );

    Ok(())
}
