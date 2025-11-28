//! Snapshot integration tests.
//!
//! TODO: This file is too big; break it into multiple
//! modules, one per audit/conceptual group.

use crate::common::{OutputMode, input_under_test, zizmor};
use anyhow::Result;

#[test]
fn test_cant_retrieve_offline() -> Result<()> {
    // Fails because --offline prevents network access.
    insta::assert_snapshot!(
        zizmor()
            .expects_failure(true)
            .offline(true)
            .unsetenv("GH_TOKEN")
            .args(["pypa/sampleproject"])
            .run()?
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
            .unsetenv("GH_TOKEN")
            .args(["pypa/sampleproject"])
            .run()?
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
            .run()?
    );

    Ok(())
}

#[test]
fn self_hosted() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("self-hosted.yml"))
            .args(["--persona=auditor"])
            .run()?
    );

    insta::assert_snapshot!(zizmor().input(input_under_test("self-hosted.yml")).run()?);

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("self-hosted/self-hosted-runner-label.yml"))
            .args(["--persona=auditor"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("self-hosted/self-hosted-runner-group.yml"))
            .args(["--persona=auditor"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "self-hosted/self-hosted-matrix-dimension.yml"
            ))
            .args(["--persona=auditor"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "self-hosted/self-hosted-matrix-inclusion.yml"
            ))
            .args(["--persona=auditor"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "self-hosted/self-hosted-matrix-exclusion.yml"
            ))
            .args(["--persona=auditor"])
            .run()?
    );

    // Fixed regressions
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("self-hosted/issue-283-repro.yml"))
            .args(["--persona=auditor"])
            .run()?
    );

    Ok(())
}

#[test]
fn unpinned_uses() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses.yml"))
            .args(["--pedantic"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses/action.yml"))
            .args(["--pedantic"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses/issue-433-repro.yml"))
            .args(["--pedantic"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-uses/issue-659-repro.yml"))
            .args(["--pedantic"])
            .run()?
    );

    // Config tests for `unpinned-uses`.

    // Default policies (no explicit config).
    insta::assert_snapshot!(
        "unpinned-uses-default-config",
        zizmor()
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?
    );

    // Require all uses to be hash-pinned.
    insta::assert_snapshot!(
        "unpinned-uses-hash-pin-everything-config",
        zizmor()
            .config(input_under_test(
                "unpinned-uses/configs/hash-pin-everything.yml"
            ))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?
    );

    // Require all uses to be ref-pinned.
    insta::assert_snapshot!(
        "unpinned-uses-ref-pin-everything-config",
        zizmor()
            .config(input_under_test(
                "unpinned-uses/configs/ref-pin-everything.yml"
            ))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?
    );

    // Composite config cases.
    insta::assert_snapshot!(
        "unpinned-uses-composite-config",
        zizmor()
            .config(input_under_test("unpinned-uses/configs/composite.yml"))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        "unpinned-uses-composite-config-2",
        zizmor()
            .config(input_under_test("unpinned-uses/configs/composite-2.yml"))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?
    );

    // Empty config.
    insta::assert_snapshot!(
        "unpinned-uses-empty-config",
        zizmor()
            .config(input_under_test("unpinned-uses/configs/empty.yml"))
            .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
            .run()?
    );

    // Invalid config: invalid policy syntax cases.
    for tc in [
        "invalid-wrong-policy-object",
        "invalid-policy-syntax-1",
        "invalid-policy-syntax-2",
        "invalid-policy-syntax-3",
        "invalid-policy-syntax-4",
        "invalid-policy-syntax-5",
        "invalid-policy-syntax-6",
    ] {
        insta::assert_snapshot!(
            zizmor()
                .expects_failure(true)
                .config(input_under_test(
                    &format!("unpinned-uses/configs/{tc}.yml",)
                ))
                .input(input_under_test("unpinned-uses/menagerie-of-uses.yml"))
                .run()?
        );
    }

    Ok(())
}

#[test]
fn use_trusted_publishing() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("use-trusted-publishing.yml"))
            .run()?,
        @r"
    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:18:9
       |
    18 |         uses: pypa/gh-action-pypi-publish@release/v1 # zizmor: ignore[unpinned-uses]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
    19 |         with:
    20 |           password: ${{ secrets.PYPI_TOKEN }}
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ uses a manually-configured credential instead of Trusted Publishing
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:25:9
       |
    25 |         uses: pypa/gh-action-pypi-publish@release/v1 # zizmor: ignore[unpinned-uses]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
    26 |         with:
    27 |           password: ${{ secrets.PYPI_TOKEN }}
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ uses a manually-configured credential instead of Trusted Publishing
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:33:9
       |
    33 |         uses: pypa/gh-action-pypi-publish@release/v1 # zizmor: ignore[unpinned-uses]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
    34 |         with:
    35 |           password: ${{ secrets.PYPI_TOKEN }}
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ uses a manually-configured credential instead of Trusted Publishing
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:51:9
       |
    51 |         uses: pypa/gh-action-pypi-publish@release/v1 # zizmor: ignore[unpinned-uses]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
    52 |         with:
    53 |           password: ${{ secrets.TEST_PYPI_TOKEN }}
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ uses a manually-configured credential instead of Trusted Publishing
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:58:9
       |
    58 |         uses: pypa/gh-action-pypi-publish@release/v1 # zizmor: ignore[unpinned-uses]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
    59 |         with:
    60 |           password: ${{ secrets.TEST_PYPI_TOKEN }}
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ uses a manually-configured credential instead of Trusted Publishing
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:65:9
       |
    65 |         uses: rubygems/release-gem@v1 # zizmor: ignore[unpinned-uses]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
    66 |         with:
    67 |           setup-trusted-publisher: false
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ uses a manually-configured credential instead of Trusted Publishing
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:82:9
       |
    82 |         uses: rubygems/configure-rubygems-credentials@v1 # zizmor: ignore[unpinned-uses]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
    83 |         with:
    84 |           api-token: ${{ secrets.RUBYGEMS_API_TOKEN }}
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ uses a manually-configured credential instead of Trusted Publishing
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:95:9
       |
    95 |         uses: rubygems/configure-rubygems-credentials@v1 # zizmor: ignore[unpinned-uses]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
    96 |         with:
    97 |           api-token: ${{ secrets.RUBYGEMS_API_TOKEN }}
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ uses a manually-configured credential instead of Trusted Publishing
       |
       = note: audit confidence → High

    27 findings (16 ignored, 3 suppressed): 8 informational, 0 low, 0 medium, 0 high
    "
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "use-trusted-publishing/demo-action/action.yml"
            ))
            .run()?,
        @r"
    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:9:7
       |
     9 |     - uses: pypa/gh-action-pypi-publish@release/v1 # zizmor: ignore[unpinned-uses]
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
    10 |       with:
    11 |         password: ${{ secrets.PYPI_TOKEN }}
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ uses a manually-configured credential instead of Trusted Publishing
       |
       = note: audit confidence → High

    2 findings (1 ignored): 1 informational, 0 low, 0 medium, 0 high
    "
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("use-trusted-publishing/cargo-publish.yml"))
            .run()?,
        @r"
    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:12:14
       |
    12 |         run: cargo publish
       |         ---  ^^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:17:14
       |
    17 |         run: cargo +nightly publish
       |         ---  ^^^^^^^^^^^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:24:11
       |
    23 |           run: |
       |           --- this step
    24 | /           cargo \
    25 | |             publish \
    26 | |             --allow-dirty \
    27 | |             --no-verify
       | |_______________________^ this command
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:49:14
       |
    49 |         run: cargo publish
       |         ---  ^^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:54:14
       |
    54 |         run: cargo +nightly publish
       |         ---  ^^^^^^^^^^^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:61:11
       |
    60 |           run: |
       |           --- this step
    61 | /           cargo `
    62 | |             publish `
    63 | |             --allow-dirty `
    64 | |             --no-verify
       | |_______________________^ this command
       |
       = note: audit confidence → High

    9 findings (3 suppressed): 6 informational, 0 low, 0 medium, 0 high
    "
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("use-trusted-publishing/npm-publish.yml"))
            .run()?,
        @r"
    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:14:9
       |
    14 |         uses: actions/setup-node@v4 # zizmor: ignore[unpinned-uses]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
    ...
    18 |           always-auth: true
       |           ^^^^^^^^^^^^^^^^^ uses a manually-configured credential instead of Trusted Publishing
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:20:14
       |
    20 |         run: npm publish
       |         ---  ^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:26:9
       |
    26 |         uses: actions/setup-node@v4 # zizmor: ignore[unpinned-uses]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
    ...
    30 |           always-auth: true
       |           ^^^^^^^^^^^^^^^^^ uses a manually-configured credential instead of Trusted Publishing
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:32:14
       |
    32 |         run: npm publish
       |         ---  ^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:43:14
       |
    43 |         run: npm publish
       |         ---  ^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:49:14
       |
    49 |         run: npm publish --access public
       |         ---  ^^^^^^^^^^^^^^^^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:57:11
       |
    55 |         run: |
       |         --- this step
    56 |           npm config set registry https://registry.npmjs.org
    57 |           npm publish --access public
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^ this command
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:63:14
       |
    63 |         run: yarn npm publish
       |         ---  ^^^^^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:69:14
       |
    69 |         run: yarn npm publish --access public
       |         ---  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:75:14
       |
    75 |         run: pnpm publish
       |         ---  ^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:81:14
       |
    81 |         run: pnpm publish --access public
       |         ---  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
       --> @@INPUT@@:129:9
        |
    129 |         uses: actions/setup-node@v4 # zizmor: ignore[unpinned-uses]
        |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
    ...
    132 |           always-auth: true
        |           ^^^^^^^^^^^^^^^^^ uses a manually-configured credential instead of Trusted Publishing
        |
        = note: audit confidence → High

    16 findings (4 suppressed): 12 informational, 0 low, 0 medium, 0 high
    "
    );

    // No use-trusted-publishing findings expected here.
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "use-trusted-publishing/issue-1191-repro.yml"
            ))
            .run()?,
        @"No findings to report. Good job! (3 suppressed)"
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("use-trusted-publishing/nuget-push.yml"))
            .run()?,
        @r"
    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:12:14
       |
    12 |         run: nuget push foo.nupkg
       |         ---  ^^^^^^^^^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:15:14
       |
    15 |         run: nuget.exe push foo.nupkg
       |         ---  ^^^^^^^^^^^^^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:18:14
       |
    18 |         run: dotnet nuget push foo.nupkg
       |         ---  ^^^^^^^^^^^^^^^^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    7 findings (4 suppressed): 3 informational, 0 low, 0 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn insecure_commands() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("insecure-commands.yml"))
            .args(["--persona=auditor"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("insecure-commands.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("insecure-commands/action.yml"))
            .args(["--persona=auditor"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("insecure-commands/issue-839-repro.yml"))
            .args(["--persona=auditor"])
            .run()?
    );

    Ok(())
}

#[test]
fn template_injection() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "template-injection/template-injection-static-matrix.yml"
            ))
            .args(["--persona=auditor"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "template-injection/template-injection-dynamic-matrix.yml"
            ))
            .args(["--persona=auditor"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection/issue-22-repro.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection/pr-317-repro.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection/static-env.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection/issue-339-repro.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection/issue-418-repro.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "template-injection/pr-425-backstop/action.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "template-injection/false-positive-menagerie.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection/issue-749-repro.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection/codeql-sinks.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection/pwsh-script.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "template-injection/issue-883-repro/action.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "template-injection/multiline-expression.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("template-injection/issue-988-repro.yml"))
            .args(["--persona=pedantic"])
            .run()?
    );

    Ok(())
}

#[test]
fn excessive_permissions() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/issue-336-repro.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/issue-336-repro.yml"
            ))
            .args(["--pedantic"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/workflow-default-perms.yml"
            ))
            .args(["--pedantic"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/workflow-read-all.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/workflow-write-all.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/workflow-empty-perms.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/jobs-broaden-permissions.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/workflow-write-explicit.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/workflow-default-perms-all-jobs-explicit.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/issue-472-repro.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/reusable-workflow-call.yml"
            ))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "excessive-permissions/reusable-workflow-other-triggers.yml"
            ))
            .run()?
    );

    Ok(())
}

#[test]
fn github_env() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("github-env/action.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("github-env/github-path.yml"))
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("github-env/issue-397-repro.yml"))
            .run()?
    );

    // Ensures that we produce a reasonable warning if the user gives us a
    // `shell:` clause containing an expression.
    insta::assert_snapshot!(
        zizmor()
            .output(OutputMode::Both)
            .setenv("RUST_LOG", "warn")
            .input(input_under_test("github-env/issue-1333/action.yml"))
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
     WARN zizmor::audit::github_env: github-env: couldn't determine shell type for @@INPUT@@ step 0; assuming bash
    No findings to report. Good job!
    "
    );

    Ok(())
}

#[test]
fn secrets_inherit() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("secrets-inherit.yml"))
            .run()?
    );

    Ok(())
}

#[test]
fn unsound_contains() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unsound-contains.yml"))
            .run()?
    );

    Ok(())
}

#[test]
fn overprovisioned_secrets() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("overprovisioned-secrets.yml"))
            .run()?
    );

    Ok(())
}

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn ref_confusion() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("ref-confusion.yml"))
            .offline(false)
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("ref-confusion/issue-518-repro.yml"))
            .offline(false)
            .run()?
    );

    Ok(())
}

#[test]
fn unredacted_secrets() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unredacted-secrets.yml"))
            .run()?
    );

    Ok(())
}

#[test]
fn forbidden_uses() -> Result<()> {
    for config in [
        "allow-all",
        "deny-all",
        "allow-some",
        "deny-some",
        "deny-some-refs",
        "allow-some-refs",
    ] {
        insta::assert_snapshot!(
            zizmor()
                .config(input_under_test(&format!(
                    "forbidden-uses/configs/{config}.yml"
                )))
                .input(input_under_test(
                    "forbidden-uses/forbidden-uses-menagerie.yml"
                ))
                .run()?
        );
    }

    Ok(())
}

#[test]
fn obfuscation() -> Result<()> {
    insta::assert_snapshot!(zizmor().input(input_under_test("obfuscation.yml")).run()?);

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("obfuscation/computed-indices.yml"))
            .args(["--persona=pedantic"])
            .run()?
    );

    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("obfuscation/issue-1177-repro.yml"))
            .args(["--persona=pedantic"])
            .run()?
    );

    Ok(())
}

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn stale_action_refs() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("stale-action-refs.yml"))
            .offline(false)
            .args(["--persona=pedantic"])
            .run()?
    );

    Ok(())
}

#[test]
fn unpinned_images() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-images.yml"))
            .args(["--persona=pedantic"])
            .run()?
    );

    Ok(())
}

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn ref_version_mismatch() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .output(crate::common::OutputMode::Both)
            .input(input_under_test("ref-version-mismatch.yml"))
            .run()?,
        @r"
    🌈 zizmor v@@VERSION@@
     INFO audit: zizmor: 🌈 completed @@INPUT@@
    warning[ref-version-mismatch]: detects commit SHAs that don't match their version comment tags
      --> @@INPUT@@:22:77
       |
    22 |       - uses: actions/setup-node@1a4442cacd436585916779262731d5b162bc6ec7 # v3.8.1
       |         -----------------------------------------------------------------   ^^^^^^ points to commit 5e21ff4d9bc1
       |         |
       |         is pointed to by tag v3.8.2
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    2 findings (1 suppressed, 1 fixable): 0 informational, 0 low, 1 medium, 0 high
    "
    );

    // Tags that point to other tags are handled correctly.
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .input(input_under_test(
                "ref-version-mismatch/nested-annotated-tags.yml"
            ))
            .run()?,
        @"No findings to report. Good job! (1 suppressed)"
    );

    Ok(())
}

#[test]
fn undocumented_permissions() -> Result<()> {
    // Test with pedantic persona (should find issues)
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("undocumented-permissions.yml"))
            .args(["--persona=pedantic"])
            .run()?
    );

    // Test with regular persona (should not find issues)
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("undocumented-permissions.yml"))
            .run()?
    );

    // Test with properly documented permissions (should not find issues even with pedantic)
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("undocumented-permissions/documented.yml"))
            .args(["--persona=pedantic"])
            .run()?
    );

    // Test with only "contents: read" (should not trigger rule)
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "undocumented-permissions/contents-read-only.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?
    );

    // Test with empty permissions (should not trigger rule)
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "undocumented-permissions/empty-permissions.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?
    );

    // Test with contents: read plus other permissions (should trigger rule)
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "undocumented-permissions/contents-read-with-other.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?
    );

    // Test with partially documented permissions (should ideally only flag undocumented ones)
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "undocumented-permissions/partially-documented.yml"
            ))
            .args(["--persona=pedantic"])
            .run()?
    );

    Ok(())
}

#[test]
fn unsound_condition() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unsound-condition.yml"))
            .run()?
    );

    Ok(())
}
