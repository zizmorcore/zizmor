use crate::common::{input_under_test, zizmor};

/// Note: per #1302, we intentionally don't produce findings here.
#[test]
fn test_cancel_false() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "concurrency-limits/cancel-false.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?,
        @"
    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:10:3
       |
    10 | /   job:
    11 | |     name: some-job
    12 | |     runs-on: ubuntu-latest
    13 | |     steps:
    14 | |     - name: 1-ok
    15 | |       run: echo ok
       | |___________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    1 finding: 0 informational, 1 low, 0 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_missing() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "concurrency-limits/missing.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?,
        @"
    help[concurrency-limits]: insufficient job-level concurrency limits
      --> @@INPUT@@:1:1
       |
     1 | / name: Workflow without concurrency
     2 | | on: push
     3 | | permissions: {}
    ...  |
    10 | |     - name: 1-ok
    11 | |       run: echo ok
       | |___________________^ missing concurrency setting
       |
       = note: audit confidence → High

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:6:3
       |
     6 | /   job:
     7 | |     name: some-job
     8 | |     runs-on: ubuntu-latest
     9 | |     steps:
    10 | |     - name: 1-ok
    11 | |       run: echo ok
       | |___________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    2 findings: 0 informational, 2 low, 0 medium, 0 high
    "
    );
    Ok(())
}

#[test]
fn test_no_cancel() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "concurrency-limits/no-cancel.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?,
        @"
    help[concurrency-limits]: insufficient job-level concurrency limits
     --> @@INPUT@@:5:1
      |
    5 | concurrency: group
      | ^^^^^^^^^^^^^^^^^^ workflow concurrency is missing cancel-in-progress
      |
      = note: audit confidence → High

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:8:3
       |
     8 | /   job:
     9 | |     name: some-job
    10 | |     runs-on: ubuntu-latest
    11 | |     steps:
    12 | |     - name: 1-ok
    13 | |       run: echo ok
       | |___________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    2 findings: 0 informational, 2 low, 0 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_jobs_missing_no_cancel() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "concurrency-limits/jobs-missing-no-cancel.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?,
        @"
    help[concurrency-limits]: insufficient job-level concurrency limits
     --> @@INPUT@@:9:5
      |
    9 |     concurrency: group
      |     ^^^^^^^^^^^^^^^^^^ job concurrency is missing cancel-in-progress
      |
      = note: audit confidence → High

    help[concurrency-limits]: insufficient job-level concurrency limits
      --> @@INPUT@@:1:1
       |
     1 | / name: Workflow with job 1 missing cancel-in-progress and job 2 missing concurrency
     2 | | on: push
     3 | | permissions: {}
    ...  |
    17 | |     - name: 2-ok
    18 | |       run: echo ok
       | |___________________^ missing concurrency setting
       |
       = note: audit confidence → High

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:6:3
       |
     6 | /   job1:
     7 | |     name: job-1
     8 | |     runs-on: ubuntu-latest
     9 | |     concurrency: group
    10 | |     steps:
    11 | |     - name: 1-ok
    12 | |       run: echo ok
       | |__________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:13:3
       |
    13 | /   job2:
    14 | |     name: job-2
    15 | |     runs-on: ubuntu-latest
    16 | |     steps:
    17 | |     - name: 2-ok
    18 | |       run: echo ok
       | |___________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    4 findings: 0 informational, 4 low, 0 medium, 0 high
    "
    );

    Ok(())
}

/// Bug #1511: reusable-only workflows were being incorrectly flagged as needing concurrency limits.
#[test]
fn test_issue_1511() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "concurrency-limits/issue-1511-repro.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?,
        @"
    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:11:3
       |
    11 | /   job:
    12 | |     name: some-job
    13 | |     runs-on: ubuntu-latest
    14 | |     steps:
    15 | |       - name: 1-ok
    16 | |         run: echo ok
       | |_____________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    1 finding: 0 informational, 1 low, 0 medium, 0 high
    "
    );

    Ok(())
}
