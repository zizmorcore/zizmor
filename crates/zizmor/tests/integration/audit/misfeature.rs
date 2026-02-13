use crate::common::{input_under_test, zizmor};

#[test]
fn test_setup_python_pip_install() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("misfeature/setup-python-pip-install.yml"))
            .run()?,
        @"
    help[misfeature]: usage of GitHub Actions misfeatures
      --> @@INPUT@@:14:11
       |
    12 |       - uses: actions/setup-python@83679a892e2d95755f2dac6acb0bfd1e9ac5d548 # v6.1.0
       |               ------------------------------------------------------------- this action
    13 |         with:
    14 |           pip-install: -r requirements.txt
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ installs packages in a brittle manner
       |
       = note: audit confidence → High
       = tip: always use a virtual environment to manage Python packages

    4 findings (3 suppressed): 0 informational, 1 low, 0 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_non_well_known_shell() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("misfeature/non-well-known-shell.yml"))
            .args(["--persona=auditor"])
            .run()?,
        @"
    help[misfeature]: usage of GitHub Actions misfeatures
      --> @@INPUT@@:18:9
       |
    18 |         shell: tcc -run {0}
       |         ^^^^^^^^^^^^^^^^^^^ shell defined here
    19 |         run: |
       |         --- uses a non-well-known shell
       |
       = note: audit confidence → High
       = tip: use a shell that's well-known to GitHub Actions, like 'bash' or 'pwsh'

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:13:3
       |
    13 | /   some-job:
    14 | |     name: non-well-known-shell
    15 | |     runs-on: ubuntu-latest
    16 | |     steps:
    ...  |
    23 | |             return 0;
    24 | |           }
       | |____________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    2 findings: 0 informational, 2 low, 0 medium, 0 high
    "
    );

    Ok(())
}

/// Reproduces issue #1414: the misfeature audit should not crash if the
/// user has `shell: cmd` defined as a job or workflow default rather than
/// at the step level.
///
/// See: https://github.com/zizmorcore/zizmor/issues/1414
#[test]
fn test_issue_1414_repro() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("misfeature/issue-1414-repro.yml"))
            .run()?,
        @"
    help[misfeature]: usage of GitHub Actions misfeatures
      --> @@INPUT@@:13:9
       |
    13 |         shell: cmd
       |         ^^^^^^^^^^ job default shell defined here
    14 |     steps:
    15 |       - name: say hi
       |         ------------ Windows CMD shell limits analysis
       |
       = note: audit confidence → High
       = tip: use 'shell: pwsh' or 'shell: bash' for improved analysis

    4 findings (3 suppressed): 0 informational, 1 low, 0 medium, 0 high
    "
    );

    // Like #1414, but with `shell: cmd` defined at the workflow level.
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("misfeature/workflow-cmd-default-shell.yml"))
            .run()?,
        @"
    help[misfeature]: usage of GitHub Actions misfeatures
      --> @@INPUT@@:10:5
       |
    10 |     shell: cmd
       |     ^^^^^^^^^^ workflow default shell defined here
    ...
    16 |       - name: say hi
       |         ------------ Windows CMD shell limits analysis
       |
       = note: audit confidence → High
       = tip: use 'shell: pwsh' or 'shell: bash' for improved analysis

    4 findings (3 suppressed): 0 informational, 1 low, 0 medium, 0 high
    "
    );

    Ok(())
}
