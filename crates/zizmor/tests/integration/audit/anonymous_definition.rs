use crate::common::{input_under_test, zizmor};

/// No findings with the regular persona.
#[test]
fn test_regular_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("anonymous-definition.yml"))
            .run()?,
        @"No findings to report. Good job! (4 suppressed)"
    );

    Ok(())
}

#[test]
fn test_pedantic_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("anonymous-definition.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @r#"
    help[anonymous-definition]: workflow or action definition without a name
      --> @@INPUT@@:5:1
       |
     5 | / on:
     6 | |   issues:
     7 | |
     8 | | permissions: {}
    ...  |
    23 | |     steps:
    24 | |       - run: "echo this job will trigger"
       | |__________________________________________^ this workflow
       |
       = note: audit confidence → High
       = tip: use 'name: ...' to give this workflow a name

    info[anonymous-definition]: workflow or action definition without a name
      --> @@INPUT@@:21:3
       |
    21 |   will-trigger:
       |   ^^^^^^^^^^^^ this job
       |
       = note: audit confidence → High
       = tip: use 'name: ...' to give this job a name

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:15:3
       |
    15 | /   no-trigger:
    16 | |     name: This is a test job that will not trigger 
    17 | |     runs-on: ubuntu-latest
    18 | |     steps:
    19 | |       - run: "echo this job will not trigger"
       | |_____________________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:21:3
       |
    21 | /   will-trigger:
    22 | |     runs-on: ubuntu-latest
    23 | |     steps:
    24 | |       - run: "echo this job will trigger"
       | |__________________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    4 findings: 1 informational, 3 low, 0 medium, 0 high
    "#
    );

    Ok(())
}
