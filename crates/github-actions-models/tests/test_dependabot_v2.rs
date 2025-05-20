use std::path::Path;

use github_actions_models::dependabot::v2::{
    Dependabot, Interval, PackageEcosystem, RebaseStrategy,
};
use indexmap::IndexSet;

fn load_dependabot(name: &str) -> Dependabot {
    let workflow_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/sample-dependabot/v2")
        .join(name);
    let dependabot_contents = std::fs::read_to_string(workflow_path).unwrap();
    serde_yaml::from_str(&dependabot_contents).unwrap()
}

#[test]
fn test_load_all() {
    let sample_configs = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/sample-dependabot/v2");

    for sample_config in std::fs::read_dir(sample_configs).unwrap() {
        let sample_workflow = sample_config.unwrap().path();
        let contents = std::fs::read_to_string(sample_workflow).unwrap();
        serde_yaml::from_str::<Dependabot>(&contents).unwrap();
    }
}

#[test]
fn test_contents() {
    let dependabot = load_dependabot("sigstore-python.yml");

    assert_eq!(dependabot.version, 2);
    assert_eq!(dependabot.updates.len(), 3);

    let pip = &dependabot.updates[0];
    assert_eq!(pip.package_ecosystem, PackageEcosystem::Pip);
    assert_eq!(pip.directory, "/");
    assert_eq!(pip.schedule.interval, Interval::Daily);
    assert_eq!(pip.open_pull_requests_limit, 5); // default

    let github_actions = &dependabot.updates[1];
    assert_eq!(
        github_actions.package_ecosystem,
        PackageEcosystem::GithubActions
    );
    assert_eq!(github_actions.directory, "/");
    assert_eq!(github_actions.open_pull_requests_limit, 99);
    assert_eq!(github_actions.rebase_strategy, RebaseStrategy::Disabled);
    assert_eq!(github_actions.groups.len(), 1);
    assert_eq!(
        github_actions.groups["actions"].patterns,
        IndexSet::from(["*".to_string()])
    );

    let github_actions = &dependabot.updates[2];
    assert_eq!(
        github_actions.package_ecosystem,
        PackageEcosystem::GithubActions
    );
    assert_eq!(github_actions.directory, ".github/actions/upload-coverage/");
    assert_eq!(github_actions.open_pull_requests_limit, 99);
    assert_eq!(github_actions.rebase_strategy, RebaseStrategy::Disabled);
    assert_eq!(github_actions.groups.len(), 1);
    assert_eq!(
        github_actions.groups["actions"].patterns,
        IndexSet::from(["*".to_string()])
    );
}
