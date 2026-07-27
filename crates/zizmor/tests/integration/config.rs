//! Configuration discovery and functionality tests.

use crate::common::{OutputMode, WorkspaceBuilder, input_under_test, zizmor};

/// Ensures we correctly discover a configuration file at the root
/// of a given input directory, i.e. `config-in-root/zizmor.yml` in
/// this case.
#[test]
fn test_discovers_config_in_root() -> anyhow::Result<()> {
    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.copy(&*input_under_test("config-scenarios/config-in-root"), ".");

    insta::assert_snapshot!(
        zizmor()
            .input(workspace.path())
            .setenv("RUST_LOG", "zizmor::config=debug")
            .output(OutputMode::Both)
            .run()?,
        @r#"
    DEBUG zizmor::config: discovering config for local input `@@INPUT@@` (root: `Some("@@INPUT@@")`)
    DEBUG discover_in_dir{path="@@INPUT@@" root=Some("@@INPUT@@")}: zizmor::config: attempting config discovery for `@@INPUT@@` (root: `Some("@@INPUT@@")`)
    DEBUG discover_in_dir{path="@@INPUT@@" root=Some("@@INPUT@@")}:happy path: zizmor::config: found config candidate at `@@INPUT@@/zizmor.yml`
    No findings to report. Good job! (1 ignored, 1 suppressed)
    "#
    );

    Ok(())
}

/// Ensures we correctly discover a configuration file in the root
/// directory from an input filename, i.e. going from
/// `config-in-root/.github/workflows/hackme.yml`
/// to `config-in-root/zizmor.yml` in this case.
#[test]
fn test_discovers_config_in_root_from_file_input() -> anyhow::Result<()> {
    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.copy(&*input_under_test("config-scenarios/config-in-root/"), ".");

    insta::assert_snapshot!(
        zizmor()
            .input(workspace.path().join(".github/workflows/hackme.yml"))
            .setenv("RUST_LOG", "zizmor::config=debug")
            .output(OutputMode::Both)
            .run()?,
        @r#"
    DEBUG zizmor::config: discovering config for local input `@@INPUT@@` (root: `Some("@@REPO_ROOT@@")`)
    DEBUG discover_in_dir{path="@@REPO_ROOT@@/.github/workflows" root=Some("@@REPO_ROOT@@")}: zizmor::config: attempting config discovery for `@@REPO_ROOT@@/.github/workflows` (root: `Some("@@REPO_ROOT@@")`)
    DEBUG discover_in_dir{path="@@REPO_ROOT@@/.github/workflows" root=Some("@@REPO_ROOT@@")}:happy path: zizmor::config: found config candidate at `@@REPO_ROOT@@/zizmor.yml`
    No findings to report. Good job! (1 ignored, 1 suppressed)
    "#
    );

    Ok(())
}

/// Ensures we correctly discover a configuration file in the root
/// directory from a child input directory, i.e. going from
/// `config-in-root/.github/workflows/` to `config-in-root/zizmor.yml`
/// in this case.
#[test]
fn test_discovers_config_in_root_from_child_dir() -> anyhow::Result<()> {
    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.copy(&*input_under_test("config-scenarios/config-in-root/"), ".");

    insta::assert_snapshot!(
        zizmor()
            .input(workspace.path().join(".github/workflows"))
            .setenv("RUST_LOG", "zizmor::config=debug")
            .output(OutputMode::Both)
            .run()?,
        @r#"
    DEBUG zizmor::config: discovering config for local input `@@INPUT@@` (root: `Some("@@REPO_ROOT@@")`)
    DEBUG discover_in_dir{path="@@INPUT@@" root=Some("@@REPO_ROOT@@")}: zizmor::config: attempting config discovery for `@@INPUT@@` (root: `Some("@@REPO_ROOT@@")`)
    DEBUG discover_in_dir{path="@@INPUT@@" root=Some("@@REPO_ROOT@@")}:happy path: zizmor::config: found config candidate at `@@REPO_ROOT@@/zizmor.yml`
    No findings to report. Good job! (1 ignored, 1 suppressed)
    "#
    );

    Ok(())
}

/// Ensures we ignore a configuration file in the root of a given
/// input directory when `--no-config` is specified.
#[test]
fn test_ignores_config_in_root() -> anyhow::Result<()> {
    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.copy(&*input_under_test("config-scenarios/config-in-root/"), ".");

    insta::assert_snapshot!(
        zizmor()
            .no_config(true)
            .input(workspace.path())
            .setenv("RUST_LOG", "zizmor::config=debug")
            .output(OutputMode::Stderr)
            .run()?,
        @"DEBUG zizmor::config: skipping config discovery: explicitly disabled"
    );

    Ok(())
}

/// Ensures we ignore a configuration file in the root directory
/// from an input filename when `--no-config` is specified.
#[test]
fn test_ignores_config_in_root_from_file_input() -> anyhow::Result<()> {
    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.copy(&*input_under_test("config-scenarios/config-in-root/"), ".");

    insta::assert_snapshot!(
        zizmor()
            .no_config(true)
            .input(workspace.path().join(".github/workflows/hackme.yml"))
            .setenv("RUST_LOG", "zizmor::config=debug")
            .output(OutputMode::Stderr)
            .run()?,
        @"DEBUG zizmor::config: skipping config discovery: explicitly disabled"
    );

    Ok(())
}

/// Ensures we ignore a configuration file in the root directory
/// from a child input directory when `--no-config` is specified.
#[test]
fn test_ignores_config_in_root_from_child_dir() -> anyhow::Result<()> {
    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.copy(&*input_under_test("config-scenarios/config-in-root/"), ".");

    insta::assert_snapshot!(
        zizmor()
            .no_config(true)
            .input(workspace.path().join(".github/workflows"))
            .setenv("RUST_LOG", "zizmor::config=debug")
            .output(OutputMode::Stderr)
            .run()?,
        @"DEBUG zizmor::config: skipping config discovery: explicitly disabled"
    );

    Ok(())
}

/// Ensures we correctly discover a configuration file in a `.github`
/// subdirectory of a given input directory, i.e.
/// `config-in-dotgithub/.github/zizmor.yml` in this case.
#[test]
fn test_discovers_config_in_dotgithub() -> anyhow::Result<()> {
    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.copy(
        &*input_under_test("config-scenarios/config-in-dotgithub/"),
        ".",
    );

    insta::assert_snapshot!(
        zizmor()
            .input(workspace.path())
            .setenv("RUST_LOG", "zizmor::config=debug")
            .output(OutputMode::Both)
            .run()?,
        @r#"
    DEBUG zizmor::config: discovering config for local input `@@INPUT@@` (root: `Some("@@INPUT@@")`)
    DEBUG discover_in_dir{path="@@INPUT@@" root=Some("@@INPUT@@")}: zizmor::config: attempting config discovery for `@@INPUT@@` (root: `Some("@@INPUT@@")`)
    DEBUG discover_in_dir{path="@@INPUT@@" root=Some("@@INPUT@@")}:happy path: zizmor::config: found config candidate at `@@INPUT@@/.github/zizmor.yml`
    No findings to report. Good job! (1 ignored, 1 suppressed)
    "#,
    );

    Ok(())
}

/// Ensures we correctly discover a `zizmor.yaml` configuration file in a `.github`
/// subdirectory of a given input directory, i.e.
/// `config-in-dotgithub/.github/zizmor.yaml` in this case.
///
/// This tests that both `.yml` and `.yaml` extensions are supported.
#[test]
fn test_discovers_dotyaml_config_in_dotgithub() -> anyhow::Result<()> {
    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.copy(
        &*input_under_test("config-scenarios/dotyaml-config-in-dotgithub/"),
        ".",
    );

    insta::assert_snapshot!(
        zizmor()
            .input(workspace.path())
            .setenv("RUST_LOG", "zizmor::config=debug")
            .output(OutputMode::Both)
            .run()?,
        @r#"
    DEBUG zizmor::config: discovering config for local input `@@INPUT@@` (root: `Some("@@INPUT@@")`)
    DEBUG discover_in_dir{path="@@INPUT@@" root=Some("@@INPUT@@")}: zizmor::config: attempting config discovery for `@@INPUT@@` (root: `Some("@@INPUT@@")`)
    DEBUG discover_in_dir{path="@@INPUT@@" root=Some("@@INPUT@@")}:happy path: zizmor::config: found config candidate at `@@INPUT@@/.github/zizmor.yaml`
    No findings to report. Good job! (1 ignored, 1 suppressed)
    "#,
    );

    Ok(())
}

/// Ensures we correctly discover a configuration file in a `.github`
/// subdirectory from an input filename, i.e. going from
/// `config-in-dotgithub/.github/workflows/hackme.yml`
/// to `config-in-dotgithub/.github/zizmor.yml` in this case.
#[test]
fn test_discovers_config_in_dotgithub_from_file_input() -> anyhow::Result<()> {
    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.copy(
        &*input_under_test("config-scenarios/config-in-dotgithub/"),
        ".",
    );

    insta::assert_snapshot!(
        zizmor()
            .input(workspace.path().join(".github/workflows/hackme.yml"))
            .setenv("RUST_LOG", "zizmor::config=debug")
            .output(OutputMode::Both)
            .run()?,
        @r#"
    DEBUG zizmor::config: discovering config for local input `@@INPUT@@` (root: `Some("@@REPO_ROOT@@")`)
    DEBUG discover_in_dir{path="@@REPO_ROOT@@/.github/workflows" root=Some("@@REPO_ROOT@@")}: zizmor::config: attempting config discovery for `@@REPO_ROOT@@/.github/workflows` (root: `Some("@@REPO_ROOT@@")`)
    DEBUG discover_in_dir{path="@@REPO_ROOT@@/.github/workflows" root=Some("@@REPO_ROOT@@")}:happy path: zizmor::config: found config candidate at `@@REPO_ROOT@@/.github/zizmor.yml`
    No findings to report. Good job! (1 ignored, 1 suppressed)
    "#
    );

    Ok(())
}

/// Ensures that we correctly discover a configuration file when the
/// target repository itself is named 'workflows'.
///
/// See: <https://github.com/zizmorcore/zizmor/issues/2229>
#[test]
fn test_discovers_config_when_repo_is_named_workflows() -> anyhow::Result<()> {
    let workspace = WorkspaceBuilder::new()
        .is_git_repo(true)
        .root_name("workflows")
        .build()?;

    workspace.add_file("zizmor.yml", "rules: {}");

    insta::assert_snapshot!(
        zizmor()
            .input(workspace.path())
            .expects_failure(3) // expected to fail, we're checking the logs here
            .setenv("RUST_LOG", "zizmor::config=trace")
            .output(OutputMode::Stderr)
            .run()?,
        @r#"
    DEBUG zizmor::config: discovering config for local input `@@INPUT@@` (root: `Some("@@INPUT@@")`)
    DEBUG discover_in_dir{path="@@INPUT@@" root=Some("@@INPUT@@")}: zizmor::config: attempting config discovery for `@@INPUT@@` (root: `Some("@@INPUT@@")`)
    DEBUG discover_in_dir{path="@@INPUT@@" root=Some("@@INPUT@@")}:happy path: zizmor::config: found config candidate at `@@INPUT@@/zizmor.yml`
    fatal: no audit was performed
    error: no inputs collected
      |
      = help: collection yielded no auditable inputs
      = help: at least one valid, auditable input must be given

    Caused by:
        no inputs collected
    "#,
    );

    // Test the sad path as well (without a repo marker).
    let workspace = WorkspaceBuilder::new()
        .is_git_repo(false)
        .root_name("workflows")
        .build()?;

    workspace.add_file("zizmor.yml", "rules: {}");

    insta::assert_snapshot!(
        zizmor()
            .input(workspace.path())
            .expects_failure(3) // expected to fail, we're checking the logs here
            .setenv("RUST_LOG", "zizmor::config=trace")
            .output(OutputMode::Stderr)
            .run()?,
        @r#"
    DEBUG zizmor::config: discovering config for local input `@@INPUT@@` (root: `None`)
    DEBUG discover_in_dir{path="@@INPUT@@" root=None}: zizmor::config: attempting config discovery for `@@INPUT@@` (root: `None`)
    DEBUG discover_in_dir{path="@@INPUT@@" root=None}:sad path: zizmor::config: config discovery: no root, falling back to search
    TRACE discover_in_dir{path="@@INPUT@@" root=None}:sad path: zizmor::config: trying config candidate path: `@@INPUT@@/.github/zizmor.yml`
    TRACE discover_in_dir{path="@@INPUT@@" root=None}:sad path: zizmor::config: trying config candidate path: `@@INPUT@@/.github/zizmor.yaml`
    TRACE discover_in_dir{path="@@INPUT@@" root=None}:sad path: zizmor::config: trying config candidate path: `@@INPUT@@/zizmor.yml`
    DEBUG discover_in_dir{path="@@INPUT@@" root=None}:sad path: zizmor::config: found config candidate at `@@INPUT@@/zizmor.yml`
    fatal: no audit was performed
    error: no inputs collected
      |
      = help: collection yielded no auditable inputs
      = help: at least one valid, auditable input must be given

    Caused by:
        no inputs collected
    "#,
    );

    Ok(())
}

/// Ensures we ignore a configuration file in a `.github` subdirectory
/// of a given input directory when `--no-config` is specified.
#[test]
fn test_ignores_config_in_dotgithub() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .no_config(true)
            .input(input_under_test("config-scenarios/config-in-dotgithub"))
            .setenv("RUST_LOG", "zizmor::config=debug")
            .output(OutputMode::Stderr)
            .run()?,
        @"DEBUG zizmor::config: skipping config discovery: explicitly disabled"
    );

    Ok(())
}

/// Ensures we ignore a configuration file in a `.github` subdirectory
/// from an input filename when `--no-config` is specified.
#[test]
fn test_ignores_config_in_dotgithub_from_file_input() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .no_config(true)
            .input(input_under_test(
                "config-scenarios/config-in-dotgithub/.github/workflows/hackme.yml"
            ))
            .setenv("RUST_LOG", "zizmor::config=debug")
            .output(OutputMode::Stderr)
            .run()?,
        @"DEBUG zizmor::config: skipping config discovery: explicitly disabled"
    );

    Ok(())
}

/// Ensures we respect the `disable: true` configuration directive.
#[test]
fn test_disablement() -> anyhow::Result<()> {
    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.copy(&*input_under_test("config-scenarios/disablement"), ".");

    insta::assert_snapshot!(
        zizmor()
            .input(workspace.path())
            .setenv("RUST_LOG", "zizmor::audit=debug")
            .output(OutputMode::Both)
            .run()?,
        @r#"
    DEBUG audit{input=Workflow(file://@@INPUT@@/.github/workflows/hackme.yml)}: zizmor::audit: skipping: template-injection is disabled in config for group Group("@@INPUT@@")
    No findings to report. Good job! (1 suppressed)
    "#
    );

    Ok(())
}

/// Various invalid config scenarios.
#[test]
fn test_invalid_configs() -> anyhow::Result<()> {
    // Top-level config schema is invalid.
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(1)
            .input(input_under_test("neutral.yml"))
            .config(input_under_test(
                "config-scenarios/zizmor.invalid-schema-1.yml"
            ))
            .output(OutputMode::Stderr)
            .run()?,
        @"
     INFO zizmor: 🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@
      |
      = help: check your configuration file for syntax errors
      = help: see: https://docs.zizmor.sh/configuration/

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid configuration syntax
        2: unknown field `rule`, expected `rules` at line 4 column 1
    "
    );

    Ok(())
}

/// Ensures that severity remapping changes the displayed severity of a finding.
/// artipacked normally produces Medium; remapped to High here.
#[test]
fn test_severity_remap() -> anyhow::Result<()> {
    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.copy(&*input_under_test("config-scenarios/severity-remap"), ".");

    insta::assert_snapshot!(
        zizmor()
            .input(workspace.path())
            .run()?,
        @"
    error[artipacked]: credential persistence through GitHub Actions artifacts
      --> @@INPUT@@/.github/workflows/hackme.yml:12:9
       |
    12 |       - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # tag=v4.2.2
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ does not set persist-credentials: false
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    2 findings (1 suppressed, 1 unsafe fixes): 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

/// Ensures that remapped severity affects --min-severity filtering.
/// A Medium finding remapped to High must survive --min-severity=high.
#[test]
fn test_severity_remap_affects_min_severity() -> anyhow::Result<()> {
    let workspace = WorkspaceBuilder::new().is_git_repo(true).build()?;
    workspace.copy(&*input_under_test("config-scenarios/severity-remap"), ".");

    insta::assert_snapshot!(
        zizmor()
            .input(workspace.path())
            .args(["--min-severity=high"])
            .run()?,
        @"
    error[artipacked]: credential persistence through GitHub Actions artifacts
      --> @@INPUT@@/.github/workflows/hackme.yml:12:9
       |
    12 |       - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # tag=v4.2.2
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ does not set persist-credentials: false
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    2 findings (1 suppressed, 1 unsafe fixes): 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

/// Without remap config, an artipacked Medium finding is filtered out by --min-severity=high.
#[test]
fn test_no_remap_filtered_by_min_severity() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .no_config(true)
            .input(input_under_test("config-scenarios/severity-remap"))
            .args(["--min-severity=high"])
            .run()?,
        @"No findings to report. Good job! (1 ignored, 1 suppressed)"
    );

    Ok(())
}

/// Ensures that even if we remap the severity of a finding, it does not affect the output when we
/// disable the configuration. This is the no-config counterpart to
/// [`test_severity_remap_affects_min_severity`].
#[test]
fn test_severity_remap_is_negated_by_no_config() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("config-scenarios/severity-remap"))
            .args(["--min-severity=high", "--no-config"])
            .run()?,
        @"No findings to report. Good job! (1 ignored, 1 suppressed)"
    );

    Ok(())
}

/// Ensures that we don't try to parse a workflow named `zizmor.yml`
/// as a zizmor configuration file, even if we're in the sad path (no Git root)
/// and the user has explicitly pointed us at `.github/workflows` instead of
/// the base of their source tree.
#[test]
fn test_config_ignores_workflow_named_zizmor() -> anyhow::Result<()> {
    let workspace = WorkspaceBuilder::new().is_git_repo(false).build()?;

    // The actual config file.
    workspace.add_file("zizmor.yml", "rules: {}");

    // A workflow that happens to share the same name as zizmor's config.
    workspace.copy(
        &*input_under_test("neutral.yml"),
        "./.github/workflows/zizmor.yml",
    );

    insta::assert_snapshot!(
        zizmor()
            .add_filter(workspace.path().as_str(), "WORKSPACE_PATH")
            .input(workspace.path().join(".github/workflows"))
            .setenv("RUST_LOG", "zizmor::config=trace")
            .output(OutputMode::Stderr)
            .run()?,
        @r#"
    DEBUG zizmor::config: discovering config for local input `@@INPUT@@` (root: `None`)
    DEBUG discover_in_dir{path="@@INPUT@@" root=None}: zizmor::config: attempting config discovery for `@@INPUT@@` (root: `None`)
    DEBUG discover_in_dir{path="@@INPUT@@" root=None}:sad path: zizmor::config: config discovery: no root, falling back to search
    TRACE discover_in_dir{path="@@INPUT@@" root=None}:sad path: zizmor::config: trying config candidate path: `@@WORKSPACE_PATH@@/.github/zizmor.yml`
    TRACE discover_in_dir{path="@@INPUT@@" root=None}:sad path: zizmor::config: trying config candidate path: `@@WORKSPACE_PATH@@/.github/zizmor.yaml`
    TRACE discover_in_dir{path="@@INPUT@@" root=None}:sad path: zizmor::config: trying config candidate path: `@@WORKSPACE_PATH@@/zizmor.yml`
    DEBUG discover_in_dir{path="@@INPUT@@" root=None}:sad path: zizmor::config: found config candidate at `@@WORKSPACE_PATH@@/zizmor.yml`
    "#
    );

    Ok(())
}
