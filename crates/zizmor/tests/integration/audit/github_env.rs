use crate::common::{OutputMode, input_under_test, zizmor};
use anyhow::Result;

#[test]
fn test_action() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("github-env/action.yml"))
            .run()?,
        @r#"
    error[github-env]: dangerous use of environment file
      --> @@INPUT@@:10:7
       |
    10 | /       run: |
    11 | |         echo "foo=$(bar)" >> $GITHUB_ENV
       | |________________________________________^ write to GITHUB_ENV may allow code execution
       |
       = note: audit confidence → Low

    error[github-env]: dangerous use of environment file
      --> @@INPUT@@:15:7
       |
    15 | /       run: |
    16 | |         echo "foo=$env:BAR" >> $env:GITHUB_ENV
       | |______________________________________________^ write to $env:GITHUB_ENV may allow code execution
       |
       = note: audit confidence → Low

    error[github-env]: dangerous use of environment file
      --> @@INPUT@@:20:7
       |
    20 | /       run: |
    21 | |         echo LIBRARY=%LIBRARY% >> %GITHUB_ENV%
       | |______________________________________________^ write to GITHUB_ENV may allow code execution
       |
       = note: audit confidence → Low

    4 findings (1 ignored): 0 informational, 0 low, 0 medium, 3 high
    "#
    );

    Ok(())
}

#[test]
fn test_github_path() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("github-env/github-path.yml"))
            .run()?,
        @r#"
    error[github-env]: dangerous use of environment file
      --> @@INPUT@@:17:9
       |
    17 | /         run: |
    18 | |           message=$(echo "$TITLE" | grep -oP '[{\[][^}\]]+[}\]]' | sed 's/{\|}\|\[\|\]//g')
    19 | |           echo "$message" >> $GITHUB_PATH
       | |__________________________________________^ write to GITHUB_PATH may allow code execution
       |
       = note: audit confidence → Low

    3 findings (1 ignored, 1 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_issue_397_repro() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("github-env/issue-397-repro.yml"))
            .run()?,
        @r#"
    error[github-env]: dangerous use of environment file
      --> @@INPUT@@:17:9
       |
    17 | /         run: |
    18 | |           message=$(echo "$TITLE" | grep -oP '[{\[][^}\]]+[}\]]' | sed 's/{\|}\|\[\|\]//g')
    19 | |           echo "$message" >> $GITHUB_PATH
       | |_________________________________________^ write to GITHUB_PATH may allow code execution
       |
       = note: audit confidence → Low

    3 findings (1 ignored, 1 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

/// Ensures that we produce a reasonable warning if the user gives us a
/// `shell:` clause containing an expression.
#[test]
fn test_issue_1333() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .output(OutputMode::Both)
            .setenv("RUST_LOG", "warn")
            .input(input_under_test("github-env/issue-1333/action.yml"))
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
     WARN zizmor::audit::github_env: github-env: couldn't determine shell type for @@INPUT@@ step 0; assuming bash
    No findings to report. Good job!
    "
    );

    Ok(())
}
