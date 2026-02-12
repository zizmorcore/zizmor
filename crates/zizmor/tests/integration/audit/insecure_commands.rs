use crate::common::{input_under_test, zizmor};
use anyhow::Result;

#[test]
fn test_insecure_commands_auditor() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("insecure-commands.yml"))
            .args(["--persona=auditor"])
            .run()?,
        @r#"
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

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:12:3
       |
    12 | /   some-dangerous-job:
    13 | |     name: some-dangerous-job
    14 | |     runs-on: ubuntu-latest
    15 | |     env:
    16 | |       ACTIONS_ALLOW_UNSECURE_COMMANDS: true
    17 | |     steps:
    18 | |       - run: echo "don't do this"
       | |_________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:20:3
       |
    20 | /   env-via-matrix:
    21 | |     name: env-via-matrix
    22 | |     runs-on: ubuntu-latest
    23 | |     strategy:
    ...  |
    29 | |       - run: echo "don't do this"
    30 | |         env: ${{ matrix.env }}
       | |_______________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    4 findings (1 fixable): 0 informational, 2 low, 0 medium, 2 high
    "#
    );

    Ok(())
}

#[test]
fn test_insecure_commands_default() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("insecure-commands.yml"))
            .run()?,
        @"
    error[insecure-commands]: execution of insecure workflow commands is enabled
      --> @@INPUT@@:15:5
       |
    15 | /     env:
    16 | |       ACTIONS_ALLOW_UNSECURE_COMMANDS: true
       | |___________________________________________^ insecure commands enabled here
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    4 findings (3 suppressed, 1 fixable): 0 informational, 0 low, 0 medium, 1 high
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

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:12:3
       |
    12 | /   some-dangerous-job:
    13 | |     name: some-dangerous-job
    14 | |     runs-on: ubuntu-latest
    15 | |     env:
    16 | |       ACTIONS_ALLOW_UNSECURE_COMMANDS: "true"
    17 | |     steps:
    18 | |       - run: echo "don't do this"
       | |_________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:20:3
       |
    20 | /   env-via-matrix:
    21 | |     name: env-via-matrix
    22 | |     runs-on: ubuntu-latest
    23 | |     strategy:
    ...  |
    29 | |       - run: echo "don't do this"
    30 | |         env: ${{ matrix.env }}
       | |______________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:32:3
       |
    32 | /   this-is-ok-1:
    33 | |     name: this-is-ok-1
    34 | |     runs-on: ubuntu-latest
    35 | |     steps:
    36 | |       - run: echo "this is ok"
    37 | |         env:
    38 | |           ACTIONS_ALLOW_UNSECURE_COMMANDS: false
       | |________________________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:40:3
       |
    40 | /   this-is-ok-2:
    41 | |     name: this-is-ok-2
    42 | |     runs-on: ubuntu-latest
    43 | |     steps:
    44 | |       - run: echo "this is ok"
    45 | |         env:
    46 | |           ACTIONS_ALLOW_UNSECURE_COMMANDS: "false"
       | |__________________________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:48:3
       |
    48 | /   this-is-ok-3:
    49 | |     name: this-is-ok-3
    50 | |     runs-on: ubuntu-latest
    51 | |     steps:
    52 | |       - run: echo "this is ok"
    53 | |         env:
    54 | |           ACTIONS_ALLOW_UNSECURE_COMMANDS: yes # does not evaluate to true
       | |___________________________________________________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    7 findings (1 fixable): 0 informational, 5 low, 0 medium, 2 high
    "#
    );

    Ok(())
}
