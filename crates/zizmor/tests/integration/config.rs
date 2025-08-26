//! Configuration discovery tests.

use crate::common::{input_under_test, zizmor};

/// Ensures we correctly discover a configuration file at the root
/// of a given input directory, i.e. `config-in-root/zizmor.yml` in
/// this case.
#[test]
fn test_discovers_config_in_root() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("config-scenarios/config-in-root"))
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
            .run()?
    );

    Ok(())
}
