use std::path::{Path, PathBuf};

use github_actions_models::dependabot::v2::{
    Day, Dependabot, Directories, Interval, PackageEcosystem, RebaseStrategy,
};
use indexmap::IndexSet;

fn sample_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/sample-dependabot/v2")
}

fn load_dependabot_result(name: &str) -> Result<Dependabot, serde_yaml::Error> {
    let workflow_path = sample_dir().join(name);
    let dependabot_contents = std::fs::read_to_string(&workflow_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", workflow_path.display()));
    serde_yaml::from_str(&dependabot_contents)
}

fn load_dependabot(name: &str) -> Dependabot {
    load_dependabot_result(name).unwrap()
}

#[test]
fn test_load_all() {
    for sample_config in std::fs::read_dir(sample_dir()).unwrap() {
        let sample_path = sample_config.unwrap().path();

        if sample_path.extension().and_then(|ext| ext.to_str()) != Some("yml") {
            continue;
        }

        let sample_name = sample_path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("sample file name not valid UTF-8");

        let result = load_dependabot_result(sample_name);

        let is_invalid = sample_name.contains(".invalid.");

        if is_invalid {
            assert!(
                result.is_err(),
                "expected {sample_name} to fail deserialization"
            );
        } else {
            result.unwrap();
        }
    }
}

#[test]
fn test_contents() {
    let dependabot = load_dependabot("sigstore-python.yml");

    assert_eq!(dependabot.version, 2);
    assert_eq!(dependabot.updates.len(), 3);

    let pip = &dependabot.updates[0];
    assert_eq!(pip.package_ecosystem, PackageEcosystem::Pip);
    assert_eq!(pip.directories, Directories::Directory("/".into()));
    assert_eq!(pip.schedule.as_ref().unwrap().interval, Interval::Daily);
    assert_eq!(pip.open_pull_requests_limit, 5); // default

    let github_actions = &dependabot.updates[1];
    assert_eq!(
        github_actions.package_ecosystem,
        PackageEcosystem::GithubActions
    );
    assert_eq!(
        github_actions.directories,
        Directories::Directory("/".into())
    );
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
    assert_eq!(
        github_actions.directories,
        Directories::Directory(".github/actions/upload-coverage/".into())
    );
    assert_eq!(github_actions.open_pull_requests_limit, 99);
    assert_eq!(github_actions.rebase_strategy, RebaseStrategy::Disabled);
    assert_eq!(github_actions.groups.len(), 1);
    assert_eq!(
        github_actions.groups["actions"].patterns,
        IndexSet::from(["*".to_string()])
    );
}

#[test]
fn test_schedule_cron_requires_expression() {
    let err = load_dependabot_result("cron-missing-cronjob.invalid.yml").unwrap_err();
    assert!(
        err.to_string()
            .contains("`schedule.cronjob` must be set when `schedule.interval` is `cron`")
    );
}

#[test]
fn test_schedule_cronjob_rejected_for_non_cron() {
    let err = load_dependabot_result("cronjob-on-daily.invalid.yml").unwrap_err();
    assert!(
        err.to_string()
            .contains("`schedule.cronjob` may only be set when `schedule.interval` is `cron`")
    );
}

#[test]
fn test_schedule_weekly_accepts_day() {
    let dependabot = load_dependabot("weekly-with-day.yml");
    assert_eq!(dependabot.updates.len(), 1);
    let schedule = &dependabot.updates[0].schedule;
    assert_eq!(schedule.as_ref().unwrap().interval, Interval::Weekly);
    assert_eq!(schedule.as_ref().unwrap().day, Some(Day::Friday));
}
