//! End-to-end integration tests for `--collect=<mode>`.

use anyhow::Result;
use zizmor_dev::{OutputMode, WorkspaceBuilder, Zizmor};

const WORKFLOW: &str = "\
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
";

const ACTION: &str = "\
name: test
description: test
runs:
  using: composite
  steps:
    - run: echo hello
      shell: bash
";

/// Ensures that root-aware collection works as expected.
/// Specifically, we only collect workflows and pre-commit inputs
/// relative to the root, while actions are collected from anywhere
/// in the directory layout.
#[test]
fn root_aware_collection() -> Result<()> {
    let workspace = WorkspaceBuilder::default().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/ci.yml", WORKFLOW);
    workspace.add_file(".github/dependabot.yaml", "version: 2\nupdates: []\n");
    workspace.add_file(".pre-commit-config.yaml", "repos: [{repo: meta}]\n");
    workspace.add_file(
        ".pre-commit-hooks.yaml",
        "- id: test\n  name: test\n  entry: echo hello\n  language: system\n",
    );
    workspace.add_file("nested/actions/action.yml", ACTION);

    // In root-aware mode, none of these invalid inputs should be discovered,
    // since they're not in their expected (root-relative) locations.
    workspace.add_file("nested/.github/workflows/ci.yml", "invalid: [");
    workspace.add_file("nested/.github/dependabot.yaml", "invalid: [");
    workspace.add_file("nested/.pre-commit-config.yaml", "invalid: [");
    workspace.add_file("nested/.pre-commit-hooks.yaml", "invalid: [");

    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(workspace.path())
            // Strict collection here ensures the test will fail if we regress
            // on *not* skipping the invalid files above.
            .args(["--strict-collection"])
            .output(OutputMode::Stderr)
            .run()?,
        @"
    INFO zizmor: 🌈 zizmor v@@VERSION@@
    INFO audit: zizmor: 🌈 completed @@INPUT@@/.github/dependabot.yaml
    INFO audit: zizmor: 🌈 completed @@INPUT@@/.github/workflows/ci.yml
    INFO audit: zizmor: 🌈 completed @@INPUT@@/.pre-commit-config.yaml
    INFO audit: zizmor: 🌈 completed @@INPUT@@/.pre-commit-hooks.yaml
    INFO audit: zizmor: 🌈 completed @@INPUT@@/nested/actions/action.yml
    "
    );

    // Disabling actions collection should prevent us from discovering
    // `nested/actions/action.yml`.
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(workspace.path())
            .args(["--strict-collection", "--collect=workflows,dependabot,pre-commit"])
            .output(OutputMode::Stderr)
            .run()?,
        @"
    INFO zizmor: 🌈 zizmor v@@VERSION@@
    INFO audit: zizmor: 🌈 completed @@INPUT@@/.github/dependabot.yaml
    INFO audit: zizmor: 🌈 completed @@INPUT@@/.github/workflows/ci.yml
    INFO audit: zizmor: 🌈 completed @@INPUT@@/.pre-commit-config.yaml
    INFO audit: zizmor: 🌈 completed @@INPUT@@/.pre-commit-hooks.yaml
    "
    );

    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(workspace.path())
            .args(["--strict-collection", "--collect=actions"])
            .output(OutputMode::Stderr)
            .run()?,
        @"
    INFO zizmor: 🌈 zizmor v@@VERSION@@
    INFO audit: zizmor: 🌈 completed @@INPUT@@/nested/actions/action.yml
    "
    );
    Ok(())
}

/// Root-aware collection honors `.gitignore` unless `--collect=all` is given.
#[test]
fn root_aware_collection_respects_gitignore() -> Result<()> {
    let workspace = WorkspaceBuilder::default().is_git_repo(true).build()?;
    workspace.add_file(".github/workflows/ci.yml", WORKFLOW);
    workspace.add_file("ignored/action.yml", ACTION);
    workspace.add_file(".gitignore", "/ignored/\n");

    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(workspace.path())
            .output(OutputMode::Stderr)
            .run()?,
        @"
    INFO zizmor: 🌈 zizmor v@@VERSION@@
    INFO audit: zizmor: 🌈 completed @@INPUT@@/.github/workflows/ci.yml
    "
    );

    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(workspace.path())
            .args(["--collect=all"])
            .output(OutputMode::Stderr)
            .run()?,
        @"
    INFO zizmor: 🌈 zizmor v@@VERSION@@
    INFO audit: zizmor: 🌈 completed @@INPUT@@/.github/workflows/ci.yml
    INFO audit: zizmor: 🌈 completed @@INPUT@@/ignored/action.yml
    "
    );
    Ok(())
}

/// Generic (non-root-aware) directory collection is recursive, including
/// workflows in nested `.github/workflows` directories.
#[test]
fn generic_dir_collection_is_recursive() -> Result<()> {
    let workspace = WorkspaceBuilder::default().is_git_repo(true).build()?;
    workspace.add_file("nested/.github/workflows/ci.yml", WORKFLOW);
    workspace.add_file("nested/example/.github/workflows/ci.yml", WORKFLOW);

    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(workspace.path().join("nested"))
            .output(OutputMode::Stderr)
            .run()?,
        @"
    INFO zizmor: 🌈 zizmor v@@VERSION@@
    INFO audit: zizmor: 🌈 completed @@INPUT@@/.github/workflows/ci.yml
    INFO audit: zizmor: 🌈 completed @@INPUT@@/example/.github/workflows/ci.yml
    "
    );
    Ok(())
}
