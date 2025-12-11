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
        @"No findings to report. Good job!"
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
        @r"
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

    1 finding: 0 informational, 1 low, 0 medium, 0 high
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
        @r"
    help[concurrency-limits]: insufficient job-level concurrency limits
     --> @@INPUT@@:5:1
      |
    5 | concurrency: group
      | ^^^^^^^^^^^^^^^^^^ workflow concurrency is missing cancel-in-progress
      |
      = note: audit confidence → High

    1 finding: 0 informational, 1 low, 0 medium, 0 high
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
        @r"
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

    2 findings: 0 informational, 2 low, 0 medium, 0 high
    "
    );

    Ok(())
}
