use std::{env, path::Path};

use github_actions_models::lock::Lock;

#[test]
fn test_load_all() {
    let sample_locks = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/sample-locks");

    for sample_lock in std::fs::read_dir(sample_locks).unwrap() {
        let sample_lock = sample_lock.unwrap().path();
        let lock_contents = std::fs::read_to_string(&sample_lock).unwrap();

        match yaml_serde::from_str::<Lock>(&lock_contents) {
            Ok(_) => (),
            Err(e) => panic!("{sample_lock:?}: {e}"),
        }
    }
}
