use crate::common::{input_under_test, zizmor};
use anyhow::Result;

#[test]
fn test_issue_336_repro() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/issue-336-repro.yml"
            ))
            .run()?,
        @"No findings to report. Good job! (1 suppressed)"
    );

    Ok(())
}

#[test]
fn test_issue_336_repro_pedantic() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/issue-336-repro.yml"
            ))
            .args(["--pedantic"])
            .run()?,
        @r"
    error[excessive-permissions]: overly broad permissions
     --> @@INPUT@@:6:3
      |
    6 |   contents: write  # Needed for the workflow
      |   ^^^^^^^^^^^^^^^ contents: write is overly broad at the workflow level
      |
      = note: audit confidence → High

    1 finding: 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

#[test]
fn test_workflow_default_perms_pedantic() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/workflow-default-perms.yml"
            ))
            .args(["--pedantic"])
            .run()?,
        @r"
    warning[excessive-permissions]: overly broad permissions
      --> @@INPUT@@:5:1
       |
     5 | / on: push
     6 | |
     7 | | name: workflow-default-perms
    ...  |
    19 | |         with:
    20 | |           persist-credentials: false
       | |_____________________________________^ default permissions used due to no permissions: block
       |
       = note: audit confidence → Medium

    warning[excessive-permissions]: overly broad permissions
      --> @@INPUT@@:14:3
       |
    14 | /   single:
    15 | |     name: single
    16 | |     runs-on: ubuntu-latest
    17 | |     steps:
    18 | |       - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
    19 | |         with:
    20 | |           persist-credentials: false
       | |                                     ^
       | |                                     |
       | |_____________________________________this job
       |                                       default permissions used due to no permissions: block
       |
       = note: audit confidence → Medium

    2 findings: 0 informational, 0 low, 2 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_workflow_read_all() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/workflow-read-all.yml"
            ))
            .run()?,
        @r"
    warning[excessive-permissions]: overly broad permissions
     --> @@INPUT@@:5:1
      |
    5 | permissions: read-all
      | ^^^^^^^^^^^^^^^^^^^^^ uses read-all permissions
      |
      = note: audit confidence → High

    3 findings (2 suppressed): 0 informational, 0 low, 1 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_workflow_write_all() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/workflow-write-all.yml"
            ))
            .run()?,
        @r"
    error[excessive-permissions]: overly broad permissions
     --> @@INPUT@@:5:1
      |
    5 | permissions: write-all
      | ^^^^^^^^^^^^^^^^^^^^^^ uses write-all permissions
      |
      = note: audit confidence → High

    3 findings (2 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

#[test]
fn test_workflow_empty_perms() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/workflow-empty-perms.yml"
            ))
            .run()?,
        @"No findings to report. Good job! (2 suppressed)"
    );

    Ok(())
}

#[test]
fn test_jobs_broaden_permissions() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/jobs-broaden-permissions.yml"
            ))
            .run()?,
        @r"
    warning[excessive-permissions]: overly broad permissions
      --> @@INPUT@@:11:5
       |
     8 | /   job1:
     9 | |     name: job1
    10 | |     runs-on: ubuntu-latest
    11 | |     permissions: read-all
       | |     ^^^^^^^^^^^^^^^^^^^^^ uses read-all permissions
    ...  |
    14 | |         with:
    15 | |           persist-credentials: false
       | |____________________________________- this job
       |
       = note: audit confidence → High

    error[excessive-permissions]: overly broad permissions
      --> @@INPUT@@:20:5
       |
    17 | /   job2:
    18 | |     name: job2
    19 | |     runs-on: ubuntu-latest
    20 | |     permissions: write-all
       | |     ^^^^^^^^^^^^^^^^^^^^^^ uses write-all permissions
    ...  |
    23 | |         with:
    24 | |           persist-credentials: false
       | |_____________________________________- this job
       |
       = note: audit confidence → High

    4 findings (2 suppressed): 0 informational, 0 low, 1 medium, 1 high
    "
    );

    Ok(())
}

#[test]
fn test_workflow_write_explicit() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/workflow-write-explicit.yml"
            ))
            .run()?,
        @r"
    error[excessive-permissions]: overly broad permissions
     --> @@INPUT@@:7:3
      |
    7 |   contents: write
      |   ^^^^^^^^^^^^^^^ contents: write is overly broad at the workflow level
      |
      = note: audit confidence → High

    error[excessive-permissions]: overly broad permissions
     --> @@INPUT@@:8:3
      |
    8 |   id-token: write
      |   ^^^^^^^^^^^^^^^ id-token: write is overly broad at the workflow level
      |
      = note: audit confidence → High

    warning[excessive-permissions]: overly broad permissions
     --> @@INPUT@@:9:3
      |
    9 |   nonexistent: write
      |   ^^^^^^^^^^^^^^^^^^ nonexistent: write is overly broad at the workflow level
      |
      = note: audit confidence → High

    7 findings (4 suppressed): 0 informational, 0 low, 1 medium, 2 high
    "
    );

    Ok(())
}

#[test]
fn test_workflow_default_perms_all_jobs_explicit() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/workflow-default-perms-all-jobs-explicit.yml"
            ))
            .run()?,
        @"No findings to report. Good job! (5 suppressed)"
    );

    Ok(())
}

#[test]
fn test_issue_472_repro() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/issue-472-repro.yml"
            ))
            .run()?,
        @r"
    warning[excessive-permissions]: overly broad permissions
      --> @@INPUT@@:20:3
       |
    20 | /   job2:
    21 | |     name: job2
    22 | |     # normal permissions finding here, since callers are always
    23 | |     # responsible for setting permissions, even if the workflow
    24 | |     # is reusable-only
    25 | |     uses: ./.github/workflows/fake.yml
       | |                                       ^
       | |                                       |
       | |_______________________________________this job
       |                                         default permissions used due to no permissions: block
       |
       = note: audit confidence → Medium

    4 findings (3 suppressed): 0 informational, 0 low, 1 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_reusable_workflow_call() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/reusable-workflow-call.yml"
            ))
            .run()?,
        @r"
    warning[excessive-permissions]: overly broad permissions
      --> @@INPUT@@:7:3
       |
     7 | /   job1:
     8 | |     name: job1
     9 | |     # finding: reusable jobs should always specify their permissions
    10 | |     uses: ./.github/workflows/zizmor-child.yml
       | |                                               ^
       | |                                               |
       | |_______________________________________________this job
       |                                                 default permissions used due to no permissions: block
       |
       = note: audit confidence → Medium

    2 findings (1 suppressed): 0 informational, 0 low, 1 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_reusable_workflow_other_triggers() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/reusable-workflow-other-triggers.yml"
            ))
            .run()?,
        @r"
    warning[excessive-permissions]: overly broad permissions
      --> @@INPUT@@:1:1
       |
     1 | / name: reusable-workflow-other-triggers
     2 | |
     3 | | on:
     4 | |   workflow_call:
    ...  |
    22 | |     # responsible for setting permissions
    23 | |     uses: ./.github/workflows/fake.yml
       | |_______________________________________^ default permissions used due to no permissions: block
       |
       = note: audit confidence → Medium

    warning[excessive-permissions]: overly broad permissions
      --> @@INPUT@@:11:3
       |
    11 | /   job1:
    12 | |     name: job1
    13 | |     # regular job-level finding, since we can be triggered by
    14 | |     # either a workflow call or a push
    15 | |     runs-on: ubuntu-24.04
    16 | |     steps:
    17 | |       - run: echo hello
       | |                       ^
       | |                       |
       | |_______________________this job
       |                         default permissions used due to no permissions: block
       |
       = note: audit confidence → Medium

    warning[excessive-permissions]: overly broad permissions
      --> @@INPUT@@:19:3
       |
    19 | /   job2:
    20 | |     name: job2
    21 | |     # normal permissions finding here, since callers are always
    22 | |     # responsible for setting permissions
    23 | |     uses: ./.github/workflows/fake.yml
       | |                                       ^
       | |                                       |
       | |_______________________________________this job
       |                                         default permissions used due to no permissions: block
       |
       = note: audit confidence → Medium

    4 findings (1 suppressed): 0 informational, 0 low, 3 medium, 0 high
    "
    );

    Ok(())
}
