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
