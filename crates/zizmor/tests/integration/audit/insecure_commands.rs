use crate::common::{input_under_test, zizmor};
use anyhow::Result;

#[test]
fn test_insecure_commands_auditor() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("insecure-commands.yml"))
            .args(["--persona=auditor"])
            .run()?,
        @r"
    error[insecure-commands]: execution of insecure workflow commands is enabled
      --> @@INPUT@@:15:5
       |
    15 | /     env:
    16 | |       ACTIONS_ALLOW_UNSECURE_COMMANDS: true
       | |___________________________________________^ insecure commands enabled here
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[insecure-commands]: execution of insecure workflow commands is enabled
      --> @@INPUT@@:30:9
       |
    30 |         env: ${{ matrix.env }}
       |         ^^^^^^^^^^^^^^^^^^^^^^ non-static environment may contain ACTIONS_ALLOW_UNSECURE_COMMANDS
       |
       = note: audit confidence → Low

    2 findings (1 fixable): 0 informational, 0 low, 0 medium, 2 high
    "
    );

    Ok(())
}

#[test]
fn test_insecure_commands_default() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("insecure-commands.yml"))
            .run()?,
        @r"
    error[insecure-commands]: execution of insecure workflow commands is enabled
      --> @@INPUT@@:15:5
       |
    15 | /     env:
    16 | |       ACTIONS_ALLOW_UNSECURE_COMMANDS: true
       | |___________________________________________^ insecure commands enabled here
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    2 findings (1 suppressed, 1 fixable): 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

#[test]
fn test_action_auditor() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("insecure-commands/action.yml"))
            .args(["--persona=auditor"])
            .run()?,
        @r"
    error[insecure-commands]: execution of insecure workflow commands is enabled
      --> @@INPUT@@:18:7
       |
    18 | /       env:
    19 | |         ACTIONS_ALLOW_UNSECURE_COMMANDS: true
       | |_____________________________________________^ insecure commands enabled here
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[insecure-commands]: execution of insecure workflow commands is enabled
      --> @@INPUT@@:25:7
       |
    25 | /       env:
    26 | |         ACTIONS_ALLOW_UNSECURE_COMMANDS: true
       | |_____________________________________________^ insecure commands enabled here
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[insecure-commands]: execution of insecure workflow commands is enabled
      --> @@INPUT@@:32:7
       |
    32 |       env: ${{ mystery }}
       |       ^^^^^^^^^^^^^^^^^^^ non-static environment may contain ACTIONS_ALLOW_UNSECURE_COMMANDS
       |
       = note: audit confidence → Low

    3 findings (2 fixable): 0 informational, 0 low, 0 medium, 3 high
    "
    );

    Ok(())
}

#[test]
fn test_issue_839_repro() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("insecure-commands/issue-839-repro.yml"))
            .args(["--persona=auditor"])
            .run()?,
        @r#"
    error[insecure-commands]: execution of insecure workflow commands is enabled
      --> @@INPUT@@:15:5
       |
    15 | /     env:
    16 | |       ACTIONS_ALLOW_UNSECURE_COMMANDS: "true"
       | |_____________________________________________^ insecure commands enabled here
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[insecure-commands]: execution of insecure workflow commands is enabled
      --> @@INPUT@@:30:9
       |
    30 |         env: ${{ matrix.env }}
       |         ^^^^^^^^^^^^^^^^^^^^^^ non-static environment may contain ACTIONS_ALLOW_UNSECURE_COMMANDS
       |
       = note: audit confidence → Low

    2 findings (1 fixable): 0 informational, 0 low, 0 medium, 2 high
    "#
    );

    Ok(())
}
