use std::path::Path;

use pre_commit_models::hooks::Hooks;

#[test]
fn test_load_all() {
    let sample_hooks = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/sample-hooks");

    for sample_hook in std::fs::read_dir(sample_hooks).unwrap() {
        let sample_hook = sample_hook.unwrap().path();
        let hook_contents = std::fs::read_to_string(sample_hook).unwrap();
        yaml_serde::from_str::<Hooks>(&hook_contents).unwrap();
    }
}
