use std::{env, path::Path};

use github_actions_models::{
    action::{Action, Runs},
    common::If,
};

fn load_action(name: &str) -> Action {
    let action_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/sample-actions")
        .join(name);
    let action_contents = std::fs::read_to_string(action_path).unwrap();
    serde_yaml::from_str(&action_contents).unwrap()
}

#[test]
fn test_load_all() {
    let sample_actions = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/sample-actions");

    for sample_action in std::fs::read_dir(sample_actions).unwrap() {
        let sample_action = sample_action.unwrap().path();
        let action_contents = std::fs::read_to_string(sample_action).unwrap();
        serde_yaml::from_str::<Action>(&action_contents).unwrap();
    }
}

#[test]
fn test_setup_python() {
    let setup_python = load_action("setup-python.yml");

    assert_eq!(setup_python.name.as_deref(), Some("Setup Python"));
    assert_eq!(
        setup_python.description.unwrap(),
        "Set up a specific version of Python and add the command-line tools to the PATH."
    );
    assert_eq!(setup_python.author.unwrap(), "GitHub");

    assert_eq!(setup_python.inputs.len(), 9);
    assert_eq!(setup_python.outputs.len(), 3);

    let Runs::JavaScript(runs) = setup_python.runs else {
        unreachable!();
    };
    assert_eq!(runs.using, "node20");
    assert_eq!(runs.main, "dist/setup/index.js");
    assert_eq!(runs.post.unwrap(), "dist/cache-save/index.js");
    assert_eq!(runs.post_if.unwrap(), If::Expr("success()".into()));
}
