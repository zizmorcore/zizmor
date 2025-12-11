//! Configuration discovery and functionality tests.

use crate::common::{OutputMode, input_under_test, zizmor};

/// Ensures we correctly discover a configuration file at the root
/// of a given input directory, i.e. `config-in-root/zizmor.yml` in
/// this case.
#[test]
fn test_discovers_config_in_root() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("config-scenarios/config-in-root"))
            .setenv("RUST_LOG", "zizmor::config=debug")
            .output(OutputMode::Both)
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    DEBUG zizmor::config: discovering config for local input `@@INPUT@@`
    DEBUG zizmor::config: attempting config discovery in `@@INPUT@@`
    DEBUG zizmor::config: found config candidate at `@@INPUT@@/zizmor.yml`
    No findings to report. Good job! (1 ignored, 2 suppressed)
    "
    );

    Ok(())
}

/// Ensures we correctly discover a configuration file in the root
/// directory from an input filename, i.e. going from
/// `config-in-root/.github/workflows/hackme.yml`
/// to `config-in-root/zizmor.yml` in this case.
#[test]
fn test_discovers_config_in_root_from_file_input() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "config-scenarios/config-in-root/.github/workflows/hackme.yml"
            ))
            .setenv("RUST_LOG", "zizmor::config=debug")
            .output(OutputMode::Both)
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    DEBUG zizmor::config: discovering config for local input `@@INPUT@@`
    DEBUG zizmor::config: attempting config discovery in `@@TEST_PREFIX@@/config-scenarios/config-in-root/.github/workflows`
    DEBUG zizmor::config: found config candidate at `@@TEST_PREFIX@@/config-scenarios/config-in-root/zizmor.yml`
    No findings to report. Good job! (1 ignored, 2 suppressed)
    "
    );

    Ok(())
}

/// Ensures we correctly discover a configuration file in the root
/// directory from a child input directory, i.e. going from
/// `config-in-root/.github/workflows/` to `config-in-root/zizmor.yml`
/// in this case.
#[test]
fn test_discovers_config_in_root_from_child_dir() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "config-scenarios/config-in-root/.github/workflows"
            ))
            .setenv("RUST_LOG", "zizmor::config=debug")
            .output(OutputMode::Both)
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    DEBUG zizmor::config: discovering config for local input `@@INPUT@@`
    DEBUG zizmor::config: attempting config discovery in `@@INPUT@@`
    DEBUG zizmor::config: found config candidate at `@@TEST_PREFIX@@/config-scenarios/config-in-root/zizmor.yml`
    No findings to report. Good job! (1 ignored, 2 suppressed)
    "
    );

    Ok(())
}

/// Ensures we ignore a configuration file in the root of a given
/// input directory when `--no-config` is specified.
#[test]
fn test_ignores_config_in_root() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .no_config(true)
            .input(input_under_test("config-scenarios/config-in-root"))
            .setenv("RUST_LOG", "zizmor::config=debug")
            .output(OutputMode::Stderr)
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    DEBUG zizmor::config: skipping config discovery: explicitly disabled
    "
    );

    Ok(())
}

/// Ensures we ignore a configuration file in the root directory
/// from an input filename when `--no-config` is specified.
#[test]
fn test_ignores_config_in_root_from_file_input() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .no_config(true)
            .input(input_under_test(
                "config-scenarios/config-in-root/.github/workflows/hackme.yml"
            ))
            .setenv("RUST_LOG", "zizmor::config=debug")
            .output(OutputMode::Stderr)
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    DEBUG zizmor::config: skipping config discovery: explicitly disabled
    "
    );

    Ok(())
}

/// Ensures we ignore a configuration file in the root directory
/// from a child input directory when `--no-config` is specified.
#[test]
fn test_ignores_config_in_root_from_child_dir() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .no_config(true)
            .input(input_under_test(
                "config-scenarios/config-in-root/.github/workflows"
            ))
            .setenv("RUST_LOG", "zizmor::config=debug")
            .output(OutputMode::Stderr)
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    DEBUG zizmor::config: skipping config discovery: explicitly disabled
    "
    );

    Ok(())
}

/// Ensures we correctly discover a configuration file in a `.github`
/// subdirectory of a given input directory, i.e.
/// `config-in-dotgithub/.github/zizmor.yml` in this case.
#[test]
fn test_discovers_config_in_dotgithub() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("config-scenarios/config-in-dotgithub"))
            .setenv("RUST_LOG", "zizmor::config=debug")
            .output(OutputMode::Both)
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    DEBUG zizmor::config: discovering config for local input `@@INPUT@@`
    DEBUG zizmor::config: attempting config discovery in `@@INPUT@@`
    DEBUG zizmor::config: found config candidate at `@@INPUT@@/.github/zizmor.yml`
    No findings to report. Good job! (1 ignored, 2 suppressed)
    ",
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
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("config-scenarios/dotyaml-config-in-dotgithub"))
            .setenv("RUST_LOG", "zizmor::config=debug")
            .output(OutputMode::Both)
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    DEBUG zizmor::config: discovering config for local input `@@INPUT@@`
    DEBUG zizmor::config: attempting config discovery in `@@INPUT@@`
    DEBUG zizmor::config: found config candidate at `@@INPUT@@/.github/zizmor.yaml`
    No findings to report. Good job! (1 ignored, 2 suppressed)
    ",
    );

    Ok(())
}

/// Ensures we correctly discover a configuration file in a `.github`
/// subdirectory from an input filename, i.e. going from
/// `config-in-dotgithub/.github/workflows/hackme.yml`
/// to `config-in-dotgithub/.github/zizmor.yml` in this case.
#[test]
fn test_discovers_config_in_dotgithub_from_file_input() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "config-scenarios/config-in-dotgithub/.github/workflows/hackme.yml"
            ))
            .setenv("RUST_LOG", "zizmor::config=debug")
            .output(OutputMode::Both)
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    DEBUG zizmor::config: discovering config for local input `@@INPUT@@`
    DEBUG zizmor::config: attempting config discovery in `@@TEST_PREFIX@@/config-scenarios/config-in-dotgithub/.github/workflows`
    DEBUG zizmor::config: found config candidate at `@@TEST_PREFIX@@/config-scenarios/config-in-dotgithub/.github/zizmor.yml`
    No findings to report. Good job! (1 ignored, 2 suppressed)
    "
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
        @r"
    🌈 zizmor v@@VERSION@@
    DEBUG zizmor::config: skipping config discovery: explicitly disabled
    "
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
        @r"
    🌈 zizmor v@@VERSION@@
    DEBUG zizmor::config: skipping config discovery: explicitly disabled
    "
    );

    Ok(())
}

/// Ensures we respect the `disable: true` configuration directive.
#[test]
fn test_disablement() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("config-scenarios/disablement"))
            .setenv("RUST_LOG", "zizmor::audit=debug")
            .output(OutputMode::Both)
            .run()?,
        @r#"
    🌈 zizmor v@@VERSION@@
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
            .expects_failure(true)
            .input(input_under_test("neutral.yml"))
            .config(input_under_test(
                "config-scenarios/zizmor.invalid-schema-1.yml"
            ))
            .output(OutputMode::Stderr)
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
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
