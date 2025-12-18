//! End-to-end integration tests.

use anyhow::Result;

use crate::common::{OutputMode, input_under_test, zizmor};

mod anchors;
mod collect;
mod json_v1;

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn gha_hazmat() -> Result<()> {
    // Stability test against with online retrieval but no online audits.
    // Ensures that we consistently collect the same files in the default
    // configuration.
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .output(OutputMode::Both)
            .args(["--no-online-audits"])
            .input("woodruffw/gha-hazmat@83e7e24df76fe8b5c0a1748b6fb24107a0e4fa61")
            .run()?
    );
    Ok(())
}

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn issue_569() -> Result<()> {
    // Regression test for #569.
    // Ensures that we don't produce spurious warnings for unreachable
    // expressions (i.e. inside comments).
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .output(OutputMode::Both)
            .args(["--no-online-audits", "--collect=workflows"])
            .input("python/cpython@f963239ff1f986742d4c6bab2ab7b73f5a4047f6")
            .run()?
    );
    Ok(())
}

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn issue_726() -> Result<()> {
    // Regression test for #726.
    // See: https://github.com/zizmorcore/zizmor/issues/726
    // See: https://github.com/woodruffw-experiments/zizmor-bug-726
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .output(OutputMode::Both)
            .args(["--no-online-audits"])
            .input("woodruffw-experiments/zizmor-bug-726@a038d1a35")
            .run()?
    );
    Ok(())
}

#[test]
fn menagerie() -> Result<()> {
    // Respects .gitignore by default.
    insta::assert_snapshot!(
        zizmor()
            .output(OutputMode::Both)
            .input(input_under_test("e2e-menagerie"))
            .run()?
    );

    // Ignores .gitignore when --collect=all is specified.
    insta::assert_snapshot!(
        zizmor()
            .output(OutputMode::Both)
            .args(["--collect=all"])
            .input(input_under_test("e2e-menagerie"))
            .run()?,
    );

    Ok(())
}

#[test]
fn color_control_basic() -> Result<()> {
    // No terminal and not CI, so no color by default.
    let no_color_default_output = zizmor()
        .output(OutputMode::Both)
        .input(input_under_test("e2e-menagerie"))
        .run()?;
    assert!(!no_color_default_output.contains("\x1b["));

    // No terminal but CI, so color by default.
    let color_default_ci_output = zizmor()
        .setenv("CI", "true")
        .output(OutputMode::Both)
        .input(input_under_test("e2e-menagerie"))
        .run()?;
    assert!(color_default_ci_output.contains("\x1b["));

    // Force color via --color=always.
    let forced_color_via_arg_output = zizmor()
        .output(OutputMode::Both)
        .args(["--color=always"])
        .input(input_under_test("e2e-menagerie"))
        .run()?;
    assert!(forced_color_via_arg_output.contains("\x1b["));

    // Force color via FORCE_COLOR.
    let forced_color_via_force_color_env_output = zizmor()
        .output(OutputMode::Both)
        .setenv("FORCE_COLOR", "1")
        .input(input_under_test("e2e-menagerie"))
        .run()?;
    assert!(forced_color_via_force_color_env_output.contains("\x1b["));

    // Force color via CLICOLOR_FORCE.
    let forced_color_via_cli_color_env_output = zizmor()
        .output(OutputMode::Both)
        .setenv("CLICOLOR_FORCE", "1")
        .input(input_under_test("e2e-menagerie"))
        .run()?;
    assert!(forced_color_via_cli_color_env_output.contains("\x1b["));

    // Forced color outputs should be equivalent.
    assert_eq!(
        forced_color_via_arg_output,
        forced_color_via_force_color_env_output
    );
    assert_eq!(
        forced_color_via_arg_output,
        forced_color_via_cli_color_env_output
    );

    Ok(())
}

#[cfg_attr(not(feature = "tty-tests"), ignore)]
#[test]
fn color_control_tty() -> Result<()> {
    // TTY enabled, so color by default.
    let color_default_output = zizmor()
        .output(OutputMode::Both)
        .unbuffer(true)
        .input(input_under_test("e2e-menagerie"))
        .run()?;
    assert!(color_default_output.contains("\x1b["));

    // Progress bar is also rendered, since zizmor thinks it's on a TTY.
    assert!(color_default_output.contains("collect_inputs{}"));

    // TTY, but color explicitly disabled via NO_COLOR.
    let no_color_via_no_color_env_output = zizmor()
        .output(OutputMode::Both)
        .unbuffer(true)
        .setenv("NO_COLOR", "1")
        .input(input_under_test("e2e-menagerie"))
        .run()?;
    assert!(!no_color_via_no_color_env_output.contains("\x1b["));

    // Progress bar is not rendered, since NO_COLOR is set.
    assert!(!no_color_via_no_color_env_output.contains("collect_inputs{}"));

    // TTY, but color explicitly disabled via `--color=never`.
    let no_color_via_arg_output = zizmor()
        .output(OutputMode::Both)
        .unbuffer(true)
        .args(["--color=never"])
        .input(input_under_test("e2e-menagerie"))
        .run()?;
    assert!(!no_color_via_arg_output.contains("\x1b["));

    // Progress bar is not rendered, since --color=never is set.
    assert!(!no_color_via_arg_output.contains("collect_inputs{}"));

    Ok(())
}

#[cfg_attr(not(feature = "tty-tests"), ignore)]
#[test]
fn progress_bar_tty() -> Result<()> {
    // TTY enabled, so progress bar is rendered by default.
    let progress_bar_default_output = zizmor()
        .output(OutputMode::Both)
        .unbuffer(true)
        .input(input_under_test("e2e-menagerie"))
        .run()?;
    assert!(progress_bar_default_output.contains("collect_inputs{}"));

    // TTY, but progress bar explicitly disabled via `--no-progress`.
    let no_progress_via_arg_output = zizmor()
        .output(OutputMode::Both)
        .unbuffer(true)
        .args(["--no-progress"])
        .input(input_under_test("e2e-menagerie"))
        .run()?;
    assert!(!no_progress_via_arg_output.contains("collect_inputs{}"));

    Ok(())
}

#[test]
fn issue_612_repro() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("issue-612-repro/action.yml"))
            .run()?
    );

    Ok(())
}

#[test]
fn invalid_config_file() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .config(if cfg!(windows) { "NUL" } else { "/dev/null" })
            .input(input_under_test("e2e-menagerie"))
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: configuration error in @@CONFIG@@
      |
      = help: check your configuration file for syntax errors
      = help: see: https://docs.zizmor.sh/configuration/

    Caused by:
        0: configuration error in @@CONFIG@@
        1: invalid configuration syntax
        2: missing field `rules`
    "
    );

    Ok(())
}

#[test]
fn invalid_inputs() -> Result<()> {
    for workflow_tc in [
        "invalid-workflow",
        "invalid-workflow-2",
        "empty",
        "bad-yaml-1",
        "bad-yaml-2",
        "blank",
        "comment-only",
        "invalid-action-1/action",
        "invalid-action-2/action",
        "empty-action/action",
    ] {
        insta::assert_snapshot!(
            zizmor()
                .expects_failure(true)
                .input(input_under_test(&format!("invalid/{workflow_tc}.yml")))
                .args(["--strict-collection"])
                .run()?
        );
    }

    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .input(input_under_test("invalid/empty/"))
            .args(["--strict-collection"])
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: no inputs collected
      |
      = help: collection yielded no auditable inputs
      = help: inputs must contain at least one valid workflow, action, or Dependabot config

    Caused by:
        no inputs collected
    "
    );

    Ok(())
}

/// Reproduction test for #1395.
///
/// Ensures that we produce a useful error message when the user gives us an
/// invalid YAML input (specifically, one with duplicate mapping keys).
#[test]
fn test_issue_1394() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .input(input_under_test(
                "invalid/issue-1395-repro-duplicate-mapping-keys.yml"
            ))
            .args(["--strict-collection"])
            .run()?,
        @r#"
    🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    failed to load file://@@INPUT@@ as workflow

    Caused by:
        0: invalid YAML syntax: jobs.demo.steps[0]: duplicate entry with key "env" at line 10 column 9
        1: jobs.demo.steps[0]: duplicate entry with key "env" at line 10 column 9
    "#
    );

    // Without --strict-collection, we get a warning and then a collection failure error.
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .input(input_under_test(
                "invalid/issue-1395-repro-duplicate-mapping-keys.yml"
            ))
            .run()?,
        @r#"
    🌈 zizmor v@@VERSION@@
     WARN collect_inputs: zizmor::registry::input: failed to parse input: jobs.demo.steps[0]: duplicate entry with key "env" at line 10 column 9
    fatal: no audit was performed
    error: no inputs collected
      |
      = help: collection yielded no auditable inputs
      = help: inputs must contain at least one valid workflow, action, or Dependabot config

    Caused by:
        no inputs collected
    "#
    );

    Ok(())
}

#[test]
fn invalid_input_not_strict() -> Result<()> {
    for tc in ["invalid-workflow", "invalid-action-1/action"] {
        insta::assert_snapshot!(
            zizmor()
                .expects_failure(true)
                .input(input_under_test(&format!("invalid/{tc}.yml")))
                .run()?
        );
    }

    Ok(())
}

#[test]
fn pr_960_backstop() -> Result<()> {
    // Backstop test for PR #960.
    // See: https://github.com/zizmorcore/zizmor/pull/960

    insta::assert_snapshot!(
        zizmor()
            .output(OutputMode::Both)
            .input(input_under_test("pr-960-backstop"))
            .run()?
    );

    Ok(())
}

/// Regression test for #1116.
/// Ensures that `--strict-collection` is respected for remote inputs.
#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn issue_1116_strict_collection_remote_input() -> Result<()> {
    // Fails with `--strict-collection`.
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .expects_failure(true)
            .output(OutputMode::Stderr)
            .args(["--strict-collection"])
            .input("woodruffw-experiments/zizmor-issue-1116@f41c414")
            .run()?
    );

    // Works without `--strict-collection`.
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .output(OutputMode::Stderr)
            .input("woodruffw-experiments/zizmor-issue-1116@f41c414")
            .run()?
    );

    Ok(())
}

/// Regression test for #1065.
///
/// This was actually a bug in `annotate-snippets` that was fixed
/// with their 0.12 series, but this ensures that we don't regress.
#[test]
fn issue_1065() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .output(OutputMode::Both)
            .input(input_under_test("issue-1065.yml"))
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
     INFO audit: zizmor: 🌈 completed @@INPUT@@
    warning[excessive-permissions]: overly broad permissions
      --> @@INPUT@@:12:3
       |
    12 | /   issue-1065:
    13 | |     runs-on: ubuntu-latest
    14 | |     steps:
    15 | |       - name: Comment PR
    ...  |
    24 | |             Please review the changes and provide any feedback. Thanks! 🚀
       | |                                                                          ^
       | |                                                                          |
       | |__________________________________________________________________________this job
       |                                                                            default permissions used due to no permissions: block
       |
       = note: audit confidence → Medium

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:16:15
       |
    16 |         uses: thollander/actions-comment-pull-request@v3
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    5 findings (3 suppressed): 0 informational, 0 low, 1 medium, 1 high
    "
    );

    Ok(())
}

/// Ensures that we emit an appropriate warning when the user
/// passes `--min-severity=unknown`.
#[test]
fn warn_on_min_severity_unknown() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(false)
            .output(OutputMode::Stderr)
            .setenv("RUST_LOG", "warn")
            .args(["--min-severity=unknown"])
            .input(input_under_test("e2e-menagerie"))
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
     WARN zizmor: `unknown` is a deprecated minimum severity that has no effect
     WARN zizmor: future versions of zizmor will reject this value
    "
    );

    Ok(())
}

/// Ensures that we emit an appropriate warning when the user
/// passes `--min-confidence=unknown`.
#[test]
fn warn_on_min_confidence_unknown() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(false)
            .output(OutputMode::Stderr)
            .setenv("RUST_LOG", "warn")
            .args(["--min-confidence=unknown"])
            .input(input_under_test("e2e-menagerie"))
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
     WARN zizmor: `unknown` is a deprecated minimum confidence that has no effect
     WARN zizmor: future versions of zizmor will reject this value
    "
    );
    Ok(())
}

/// Regression test for #1207.
///
/// Ensures that we correctly handle single-inputs that aren't given
/// with an explicit parent path, e.g. `action.yml` instead of
/// `./action.yml`.
#[test]
fn issue_1207() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(false)
            .output(OutputMode::Both)
            .working_dir(input_under_test("e2e-menagerie/dummy-action-1"))
            // Input doesn't matter, as long as it's relative without a leading
            // `./` or other path component.
            .input("action.yaml")
            .run()?
    );

    Ok(())
}

/// Regression test for #1286.
///
/// Ensures that we produce a useful error when a user's input references
/// a private (or missing) repository.
#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn issue_1286() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .output(OutputMode::Both)
            .offline(false)
            .input(input_under_test("issue-1286.yml"))
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    'ref-confusion' audit failed on file://@@INPUT@@

    Caused by:
        0: error in 'ref-confusion' audit
        1: couldn't list branches for woodruffw-experiments/this-does-not-exist
        2: can't access woodruffw-experiments/this-does-not-exist: missing or you have no access
    ",
    );

    Ok(())
}

/// Regression test for #1300.
///
/// Ensures that we produce a useful error when a user specifies
/// `--collect=workflows` on a remote input that doesn't have a
/// `.github/workflows/` directory.
#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn issue_1300() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .output(OutputMode::Both)
            .offline(false)
            .args(["--collect=workflows"])
            .input("woodruffw-experiments/empty")
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: input @@INPUT@@ doesn't contain any workflows
      |
      = help: ensure that @@INPUT@@ contains one or more workflows under `.github/workflows/`
      = help: ensure that @@INPUT@@ exists and you have access to it

    Caused by:
        0: input @@INPUT@@ doesn't contain any workflows
        1: request error while accessing GitHub API
        2: HTTP status client error (404 Not Found) for url (https://api.github.com/repos/@@INPUT@@/contents/.github/workflows)
    "
    );

    Ok(())
}

/// Regression test for #1341.
///
/// Ensures that we successfully collect a *workflow* named `dependabot.yml`, rather
/// than failing to parse it as a Dependabot config.
#[test]
fn issue_1341() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(true)
            .input(input_under_test(
                "issue-1341-repro/.github/workflows/dependabot.yml"
            ))
            .run()?,
    );

    Ok(())
}

/// Regression test for #1356.
///
/// Ensures that zizmor's LSP mode (`--lsp`) starts up correctly, i.e.
/// doesn't crash on launch.
#[test]
fn issue_1356_lsp_mode_starts() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(false)
            .output(OutputMode::Stdout)
            .stdin("{}") // Not a valid LSP message, but all we're testing is startup.
            .args(["--lsp"])
            .run()?,
        @r#"
    Content-Length: 75

    {"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null}
    "#
    );

    Ok(())
}

#[test]
fn test_cant_retrieve_offline() -> Result<()> {
    // Fails because --offline prevents network access.
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .offline(true)
            .args(["pypa/sampleproject"])
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: can't fetch remote repository: pypa/sampleproject
      |
      = help: remove --offline to audit remote repositories

    Caused by:
        can't fetch remote repository: pypa/sampleproject
    "
    );

    Ok(())
}

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_cant_retrieve_no_gh_token() -> Result<()> {
    // Fails because GH_TOKEN is not set.
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .offline(false)
            .gh_token(false)
            .args(["pypa/sampleproject"])
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    error: can't fetch remote repository: pypa/sampleproject
      |
      = help: set a GitHub token with --gh-token or GH_TOKEN

    Caused by:
        can't fetch remote repository: pypa/sampleproject
    "
    );

    Ok(())
}

#[test]
fn test_github_output() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(true)
            .input(input_under_test("several-vulnerabilities.yml"))
            .args(["--persona=auditor", "--format=github"])
            .run()?,
        @r"
    ::error file=@@INPUT@@,line=5,title=excessive-permissions::several-vulnerabilities.yml:5: overly broad permissions: uses write-all permissions
    ::error file=@@INPUT@@,line=11,title=excessive-permissions::several-vulnerabilities.yml:11: overly broad permissions: uses write-all permissions
    ::error file=@@INPUT@@,line=2,title=dangerous-triggers::several-vulnerabilities.yml:2: use of fundamentally insecure workflow trigger: pull_request_target is almost always used insecurely
    ::warning file=@@INPUT@@,line=16,title=template-injection::several-vulnerabilities.yml:16: code injection via template expansion: may expand into attacker-controllable code
    ::error file=@@INPUT@@,line=16,title=template-injection::several-vulnerabilities.yml:16: code injection via template expansion: may expand into attacker-controllable code
    ::warning file=@@INPUT@@,line=1,title=concurrency-limits::several-vulnerabilities.yml:1: insufficient job-level concurrency limits: missing concurrency setting
    "
    );

    Ok(())
}

/// Ensures that the `--show-audit-urls` flag works as expected.
#[test]
fn test_show_urls() -> Result<()> {
    let with_urls = zizmor()
        .offline(true)
        .show_audit_urls(true)
        .input(input_under_test("several-vulnerabilities.yml"))
        .run()?;

    assert!(with_urls.contains("audit documentation → "));

    let without_urls = zizmor()
        .offline(true)
        .show_audit_urls(false)
        .input(input_under_test("several-vulnerabilities.yml"))
        .run()?;

    assert!(!without_urls.contains("audit documentation → "));

    Ok(())
}
