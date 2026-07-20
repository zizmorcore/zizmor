use std::path::Path;

use pre_commit_models::config::Config;

#[test]
fn test_load_all() {
    let sample_configs = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/sample-configs");

    for sample_config in std::fs::read_dir(sample_configs).unwrap() {
        let sample_config = sample_config.unwrap().path();
        let config_contents = std::fs::read_to_string(sample_config).unwrap();
        yaml_serde::from_str::<Config>(&config_contents).unwrap();
    }
}
