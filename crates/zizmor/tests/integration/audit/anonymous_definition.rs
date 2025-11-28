use crate::common::{input_under_test, zizmor};

/// No findings with the regular persona.
#[test]
fn test_regular_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("anonymous-definition.yml"))
            .run()?,
        @r"No findings to report. Good job! (2 suppressed)"
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

    info[anonymous-definition]: workflow or action definition without a name
      --> @@INPUT@@:21:3
       |
    21 | /   will-trigger:
    22 | |     runs-on: ubuntu-latest
    23 | |     steps:
    24 | |       - run: "echo this job will trigger"
       | |__________________________________________^ this job
       |
       = note: audit confidence → High

    2 findings: 1 informational, 1 low, 0 medium, 0 high
    "#
    );

    Ok(())
}
