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
            .run()?
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
            .run()?
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
            .run()?
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
            .output(OutputMode::Both)
            .run()?
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
            .output(OutputMode::Both)
            .run()?
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
            .output(OutputMode::Both)
            .run()?
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
            .run()?
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
            .run()?
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
            .output(OutputMode::Both)
            .run()?
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
            .output(OutputMode::Both)
            .run()?
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
            .run()?
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
            .run()?
    );

    // forbidden-uses audit config is invalid.
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .input(input_under_test("neutral.yml"))
            .config(input_under_test(
                "config-scenarios/zizmor.invalid-schema-2.yml"
            ))
            .output(OutputMode::Stderr)
            .run()?,
    );

    // unpinned-uses audit config is invalid.
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .input(input_under_test("neutral.yml"))
            .config(input_under_test(
                "config-scenarios/zizmor.invalid-schema-3.yml"
            ))
            .output(OutputMode::Stderr)
            .run()?,
    );

    Ok(())
}
