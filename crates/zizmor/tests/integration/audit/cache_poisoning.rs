use crate::common::{input_under_test, zizmor};

#[test]
fn test_caching_disabled_by_default() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "cache-poisoning/caching-disabled-by-default.yml"
            ))
            .run()?,
        @"No findings to report. Good job! (1 suppressed)"
    );

    Ok(())
}

#[test]
fn test_caching_enabled_by_default() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "cache-poisoning/caching-enabled-by-default.yml"
            ))
            .run()?,
        @r"
    error[cache-poisoning]: runtime artifacts potentially vulnerable to a cache poisoning attack
      --> @@INPUT@@:19:9
       |
     1 | on: release
       | ----------- generally used when publishing artifacts generated at runtime
    ...
    19 |         uses: Swatinem/rust-cache@82a92a6e8fbeee089604da2575dc567ae9ddeaab
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ cache enabled by default here
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    4 findings (1 ignored, 2 suppressed, 1 fixable): 0 informational, 0 low, 0 medium, 1 high
    ",
    );

    Ok(())
}

#[test]
fn test_caching_opt_in_boolean_toggle() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "cache-poisoning/caching-opt-in-boolean-toggle.yml"
            ))
            .run()?,
        @r#"
    error[cache-poisoning]: runtime artifacts potentially vulnerable to a cache poisoning attack
      --> @@INPUT@@:19:9
       |
     1 |   on: release
       |   ----------- generally used when publishing artifacts generated at runtime
    ...
    19 | /         with:
    20 | |           dotnet-version: "5.0.x"
    21 | |           cache: true
       | |_____________________^ opt-in for caching here
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    4 findings (1 ignored, 2 suppressed, 1 fixable): 0 informational, 0 low, 0 medium, 1 high
    "#,
    );

    Ok(())
}

#[test]
fn test_caching_opt_in_expression() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "cache-poisoning/caching-opt-in-expression.yml"
            ))
            .run()?,
        @r#"
    error[cache-poisoning]: runtime artifacts potentially vulnerable to a cache poisoning attack
      --> @@INPUT@@:19:9
       |
     1 |   on: release
       |   ----------- generally used when publishing artifacts generated at runtime
    ...
    19 | /         with:
    20 | |           python-version: "3.12"
    21 | |           enable-cache: ${{ github.ref == 'refs/heads/main' }}
       | |______________________________________________________________^ opt-in for caching might happen here
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    3 findings (1 ignored, 1 suppressed, 1 fixable): 0 informational, 0 low, 0 medium, 1 high
    "#,
    );

    Ok(())
}

#[test]
fn test_caching_opt_in_multi_value_toggle() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "cache-poisoning/caching-opt-in-multi-value-toggle.yml"
            ))
            .run()?,
        @r#"
    error[cache-poisoning]: runtime artifacts potentially vulnerable to a cache poisoning attack
      --> @@INPUT@@:19:9
       |
     1 |   on: release
       |   ----------- generally used when publishing artifacts generated at runtime
    ...
    19 | /         with:
    20 | |           distribution: "zulu"
    21 | |           cache: "gradle"
    22 | |           java-version: "17"
       | |____________________________^ opt-in for caching here
       |
       = note: audit confidence → Low

    2 findings (1 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#,
    );

    Ok(())
}

#[test]
fn test_caching_opt_out() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("cache-poisoning/caching-opt-out.yml"))
            .run()?,
        @"No findings to report. Good job! (1 ignored, 2 suppressed)"
    );

    Ok(())
}

#[test]
fn test_no_cache_aware_steps() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("cache-poisoning/no-cache-aware-steps.yml"))
            .run()?,
        @"No findings to report. Good job! (1 ignored, 2 suppressed)"
    );

    Ok(())
}

#[test]
fn test_workflow_tag_trigger() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("cache-poisoning/workflow-tag-trigger.yml"))
            .run()?,
        @r#"
    error[cache-poisoning]: runtime artifacts potentially vulnerable to a cache poisoning attack
      --> @@INPUT@@:21:9
       |
     1 | / on:
     2 | |   push:
     3 | |     tags:
     4 | |       - "**"
       | |____________- generally used when publishing artifacts generated at runtime
    ...
    21 |           uses: Swatinem/rust-cache@82a92a6e8fbeee089604da2575dc567ae9ddeaab
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ cache enabled by default here
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    4 findings (1 ignored, 2 suppressed, 1 fixable): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_caching_opt_in_boolish_toggle() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "cache-poisoning/caching-opt-in-boolish-toggle.yml"
            ))
            .run()?,
        @r#"
    error[cache-poisoning]: runtime artifacts potentially vulnerable to a cache poisoning attack
      --> @@INPUT@@:18:9
       |
     4 |   on: release
       |   ----------- generally used when publishing artifacts generated at runtime
    ...
    18 | /         with:
    19 | |           target: ${{ matrix.platform.target }}
    20 | |           args: --release --out dist
    21 | |           sccache: "true"
       | |__________________________^ opt-in for caching here
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    2 findings (1 suppressed, 1 fixable): 0 informational, 0 low, 0 medium, 1 high
    "#,
    );

    Ok(())
}

#[test]
fn test_publisher_step() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("cache-poisoning/publisher-step.yml"))
            .run()?,
        @r"
    error[cache-poisoning]: runtime artifacts potentially vulnerable to a cache poisoning attack
      --> @@INPUT@@:21:9
       |
    21 |         uses: Swatinem/rust-cache@82a92a6e8fbeee089604da2575dc567ae9ddeaab
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ cache enabled by default here
    ...
    28 |         uses: softprops/action-gh-release@01570a1f39cb168c169c802c3bceb9e93fb10974
       |         -------------------------------------------------------------------------- runtime artifacts usually published here
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    2 findings (1 suppressed, 1 fixable): 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

/// Bug #343: setup-go's caching behavior was not modeled as opt-out.
///
/// See: <https://github.com/zizmorcore/zizmor/pull/343>
#[test]
fn test_issue_343() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("cache-poisoning/issue-343-repro.yml"))
            .run()?,
        @r#"
    error[cache-poisoning]: runtime artifacts potentially vulnerable to a cache poisoning attack
      --> @@INPUT@@:28:9
       |
     5 | / on:
     6 | |   push:
     7 | |     tags:
     8 | |       - "v*.*.*"
       | |________________- generally used when publishing artifacts generated at runtime
    ...
    28 |           uses: actions/setup-go@v5
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^ cache enabled by default here
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    error[cache-poisoning]: runtime artifacts potentially vulnerable to a cache poisoning attack
      --> @@INPUT@@:35:9
       |
     5 | / on:
     6 | |   push:
     7 | |     tags:
     8 | |       - "v*.*.*"
       | |________________- generally used when publishing artifacts generated at runtime
    ...
    35 | /         with:
    36 | |           go-version: stable
    37 | |           cache: true
    38 | |
    39 | |       # Finding because setup enables cache explicitly
       | |______________________________________________________^ opt-in for caching here
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    error[cache-poisoning]: runtime artifacts potentially vulnerable to a cache poisoning attack
      --> @@INPUT@@:42:9
       |
     5 | / on:
     6 | |   push:
     7 | |     tags:
     8 | |       - "v*.*.*"
       | |________________- generally used when publishing artifacts generated at runtime
    ...
    42 | /         with:
    43 | |           go-version: stable
    44 | |           cache: "true"
       | |________________________^ opt-in for caching here
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    5 findings (2 suppressed, 3 fixable): 0 informational, 0 low, 0 medium, 3 high
    "#
    );

    Ok(())
}

#[test]
fn test_caching_not_configurable() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "cache-poisoning/caching-not-configurable.yml"
            ))
            .run()?,
        @r#"
    error[cache-poisoning]: runtime artifacts potentially vulnerable to a cache poisoning attack
      --> @@INPUT@@:21:9
       |
     1 | / on:
     2 | |   push:
     3 | |     tags:
     4 | |       - "**"
       | |____________- generally used when publishing artifacts generated at runtime
    ...
    21 |           uses: Mozilla-Actions/sccache-action@054db53350805f83040bf3e6e9b8cf5a139aa7c9
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ cache always restored here
       |
       = note: audit confidence → Low

    4 findings (1 ignored, 2 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_workflow_release_branch_trigger() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "cache-poisoning/workflow-release-branch-trigger.yml"
            ))
            .run()?,
        @r#"
    error[cache-poisoning]: runtime artifacts potentially vulnerable to a cache poisoning attack
      --> @@INPUT@@:21:9
       |
     1 | / on:
     2 | |   push:
     3 | |     branches:
     4 | |       - "release-v2.0.0"
       | |________________________- generally used when publishing artifacts generated at runtime
    ...
    21 |           uses: Swatinem/rust-cache@82a92a6e8fbeee089604da2575dc567ae9ddeaab
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ cache enabled by default here
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    4 findings (1 ignored, 2 suppressed, 1 fixable): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

/// Bug #378: docker/build-push-action should not be considered a publishing
/// sink when `push: false`.
///
/// See: <https://github.com/zizmorcore/zizmor/issues/378>
#[test]
fn test_issue_378() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("cache-poisoning/issue-378-repro.yml"))
            .run()?,
        @"No findings to report. Good job! (1 suppressed)"
    );

    Ok(())
}

/// See: <https://github.com/zizmorcore/zizmor/issues/642>
#[test]
fn test_issue_642() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("cache-poisoning/issue-642-repro.yml"))
            .run()?,
        @r"
    error[cache-poisoning]: runtime artifacts potentially vulnerable to a cache poisoning attack
      --> @@INPUT@@:16:9
       |
    16 | /         with:
    17 | |           cache-binary: true
    18 | |           version: latest
       | |_________________________^ opt-in for caching here
    ...
    21 |           uses: docker/build-push-action@48aba3b46d1b1fec4febb7c5d0c644b249a11355
       |           ----------------------------------------------------------------------- runtime artifacts usually published here
       |
       = note: audit confidence → Low

    3 findings (2 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

// Bug #1081: setup-uv's caching analysis was inverted.
//
// See: <https://github.com/zizmorcore/zizmor/issues/1081>
#[test]
fn test_issue_1081() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("cache-poisoning/issue-1081-repro.yml"))
            .run()?,
        @r"
    error[cache-poisoning]: runtime artifacts potentially vulnerable to a cache poisoning attack
      --> @@INPUT@@:15:9
       |
     5 | on: release
       | ----------- generally used when publishing artifacts generated at runtime
    ...
    15 |       - uses: astral-sh/setup-uv@d9e0f98d3fc6adb07d1e3d37f3043649ddad06a1 # v6.5.0
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ cache enabled by default here
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    error[cache-poisoning]: runtime artifacts potentially vulnerable to a cache poisoning attack
      --> @@INPUT@@:19:9
       |
     5 |   on: release
       |   ----------- generally used when publishing artifacts generated at runtime
    ...
    19 | /         with:
    20 | |           enable-cache: true
       | |____________________________^ opt-in for caching here
       |
       = note: audit confidence → Low
       = note: this finding has an auto-fix

    4 findings (2 suppressed, 2 fixable): 0 informational, 0 low, 0 medium, 2 high
    "
    );

    Ok(())
}

/// Bug #1152: Changes to setup-node v5's caching behavior.
///
/// See: <https://github.com/zizmorcore/zizmor/issues/1152>
#[test]
fn test_issue_1152() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("cache-poisoning/issue-1152-repro.yml"))
            .run()?,
        @r"
    error[cache-poisoning]: runtime artifacts potentially vulnerable to a cache poisoning attack
      --> @@INPUT@@:16:9
       |
     5 | on: release
       | ----------- generally used when publishing artifacts generated at runtime
    ...
    16 |         uses: actions/setup-node@v5
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^ cache enabled by default here
       |
       = note: audit confidence → Low

    error[cache-poisoning]: runtime artifacts potentially vulnerable to a cache poisoning attack
      --> @@INPUT@@:21:9
       |
     5 |   on: release
       |   ----------- generally used when publishing artifacts generated at runtime
    ...
    21 | /         with:
    22 | |           package-manager-cache: true
       | |_____________________________________^ opt-in for caching here
       |
       = note: audit confidence → Low

    error[cache-poisoning]: runtime artifacts potentially vulnerable to a cache poisoning attack
      --> @@INPUT@@:42:9
       |
     5 | on: release
       | ----------- generally used when publishing artifacts generated at runtime
    ...
    42 |       - uses: actions/setup-node@a0853c24544627f65ddf259abe73b1d18a591444 # v5.0.0
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ cache enabled by default here
       |
       = note: audit confidence → Low

    6 findings (3 suppressed): 0 informational, 0 low, 0 medium, 3 high
    "
    );

    Ok(())
}
