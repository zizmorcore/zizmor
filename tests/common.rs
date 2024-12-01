use std::env::current_dir;

pub fn workflow_under_test(name: &str) -> String {
    let current_dir = current_dir().expect("Cannot figure out current directory");

    let file_path = current_dir.join("tests").join("test-data").join(name);

    file_path
        .to_str()
        .expect("Cannot create string reference for file path")
        .to_string()
}
