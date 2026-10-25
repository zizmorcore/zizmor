//! End-to-end integration tests for `--collect=<mode>`.

use anyhow::Result;
use indoc::indoc;
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

/// When a local input contains an actions lockfile, we include it during collection.
#[test]
fn local_collection_includes_lockfile() -> anyhow::Result<()> {
    let workspace = WorkspaceBuilder::default().is_git_repo(true).build()?;

    workspace.add_file(
        ".github/workflows/actions.lock",
        indoc! {"
            # This file is machine-generated by `gh actions-lock`.
            # Do not edit by hand; run `gh actions-lock` to update.
            # Docs: https://gh.io/actions-lockfile
            version: 'v0.0.3'
            workflows:
                '.github/workflows/example.yml':
                    - 'actions/checkout@v7.0.1'
            dependencies:
                'actions/checkout@v7.0.1':
                    ref: 'v7.0.1'
                    commit: 'sha1-3d3c42e5aac5ba805825da76410c181273ba90b1'
                    owner_id: 44036562
                    repo_id: 197814629
        "},
    );

    workspace.add_file(
        ".github/workflows/example.yml",
        indoc! {r#"
            name: example

            on: [push, pull_request]

            concurrency:
              group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}
              cancel-in-progress: true

            permissions: {}

            jobs:
              example:
                name: example
                runs-on: ubuntu-latest
                steps:
                  - name: checkout
                    uses: actions/checkout@v7.0.1
                    with:
                      persist-credentials: false
        "#},
    );

    // Auditing from the local Git root collects the lockfile as expected.
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(workspace.path())
            .output(OutputMode::Both)
            .setenv("RUST_LOG", "zizmor::registry::input=debug")
            .run()?,
        @r#"
    DEBUG zizmor::registry::input: collecting all eligible inputs under '@@INPUT@@'
    DEBUG collect_from_dir{path="@@INPUT@@"}:collect_from_repo_root{path="@@INPUT@@" root=Root { request_is_root: true, path: "@@INPUT@@" }}: zizmor::registry::input: performing root-aware collection because '@@INPUT@@' is a Git root
    DEBUG collect_from_dir{path="@@INPUT@@"}:collect_from_repo_root{path="@@INPUT@@" root=Root { request_is_root: true, path: "@@INPUT@@" }}: zizmor::registry::input: registering workflow input with key file://@@INPUT@@/.github/workflows/example.yml
    DEBUG zizmor::registry::input: collected a group with 1 inputs (actions lockfile=true)
     WARN zizmor::registry::input: one or more inputs uses a GitHub Actions workflow lockfile; see https://docs.zizmor.sh/usage/#workflow-lockfiles for details
    No findings to report. Good job!
    "#
    );

    // Auditing from a directory within the Git root also collects the lockfile
    // as expected.
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(workspace.path().join(".github"))
            .output(OutputMode::Both)
            .setenv("RUST_LOG", "zizmor::registry::input=debug")
            .run()?,
        @r#"
    DEBUG zizmor::registry::input: collecting all eligible inputs under '@@INPUT@@'
    DEBUG collect_from_dir{path="@@INPUT@@"}:collect_from_generic_dir{path="@@INPUT@@" root=Some(Root { request_is_root: false, path: "@@REPO_ROOT@@" })}: zizmor::registry::input: performing generic directory collection because '@@INPUT@@' is not a Git root
    DEBUG collect_from_dir{path="@@INPUT@@"}:collect_from_generic_dir{path="@@INPUT@@" root=Some(Root { request_is_root: false, path: "@@REPO_ROOT@@" })}: zizmor::registry::input: registering workflow input with key file://@@INPUT@@/workflows/example.yml
    DEBUG zizmor::registry::input: collected a group with 1 inputs (actions lockfile=true)
     WARN zizmor::registry::input: one or more inputs uses a GitHub Actions workflow lockfile; see https://docs.zizmor.sh/usage/#workflow-lockfiles for details
    No findings to report. Good job!
    "#
    );

    // Auditing a single file within the Git root also collects the lockfile.
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(workspace.path().join(".github/workflows/example.yml"))
            .output(OutputMode::Both)
            .setenv("RUST_LOG", "zizmor::registry::input=debug")
            .run()?,
        @"
    DEBUG zizmor::registry::input: collecting one input from '@@INPUT@@'
    DEBUG zizmor::registry::input: registering workflow input with key file://@@INPUT@@
    DEBUG zizmor::registry::input: collected a group with 1 inputs (actions lockfile=true)
     WARN zizmor::registry::input: one or more inputs uses a GitHub Actions workflow lockfile; see https://docs.zizmor.sh/usage/#workflow-lockfiles for details
    No findings to report. Good job!
    "
    );

    Ok(())
}

/// When a remote input contains an actions lockfile, we include it during collection.
#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn remote_collection_includes_lockfile() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .offline(zizmor_dev::NetworkMode::AssertOnline)
            .input("github/actions-lockfile@ac15883476")
            .output(OutputMode::Stderr)
            .setenv("RUST_LOG", "zizmor::registry::input=debug")
            .run()?,
        @"
    DEBUG zizmor::registry::input: collecting all eligible inputs from remote '@@INPUT@@'
    DEBUG zizmor::registry::input: registering dependabot config input with key https://github.com/github/actions-lockfile/blob/ac15883476/.github/dependabot.yml
    DEBUG zizmor::registry::input: registering workflow input with key https://github.com/github/actions-lockfile/blob/ac15883476/.github/workflows/ci.yml
    DEBUG zizmor::registry::input: registering workflow input with key https://github.com/github/actions-lockfile/blob/ac15883476/.github/workflows/dependency-review.yml
    DEBUG zizmor::registry::input: registering workflow input with key https://github.com/github/actions-lockfile/blob/ac15883476/.github/workflows/release.yml
     INFO zizmor::registry::input: collected 4 inputs from @@INPUT@@
    DEBUG zizmor::registry::input: collected a group with 4 inputs (actions lockfile=true)
     WARN zizmor::registry::input: one or more inputs uses a GitHub Actions workflow lockfile; see https://docs.zizmor.sh/usage/#workflow-lockfiles for details
    "
    );

    Ok(())
}
