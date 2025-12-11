use crate::common::{input_under_test, zizmor};
use anyhow::Result;

#[test]
fn test_use_trusted_publishing() -> Result<()> {
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

    Ok(())
}

#[test]
fn test_demo_action() -> Result<()> {
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

    Ok(())
}

#[test]
fn test_cargo_publish() -> Result<()> {
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

    Ok(())
}

#[test]
fn test_npm_publish() -> Result<()> {
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

    Ok(())
}

/// No use-trusted-publishing findings expected here.
#[test]
fn test_issue_1191_repro() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "use-trusted-publishing/issue-1191-repro.yml"
            ))
            .run()?,
        @"No findings to report. Good job! (3 suppressed)"
    );

    Ok(())
}

#[test]
fn test_nuget_push() -> Result<()> {
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
fn test_gem_push() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("use-trusted-publishing/gem-push.yml"))
            .run()?,
        @r"
    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:12:14
       |
    12 |         run: gem push foo-0.1.0.gem
       |         ---  ^^^^^^^^^^^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:15:14
       |
    15 |         run: bundle exec gem push foo-0.1.0.gem
       |         ---  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:20:11
       |
    19 |           run: |
       |           --- this step
    20 | /           gem \
    21 | |             push \
    22 | |             foo-0.1.0.gem
       | |_________________________^ this command
       |
       = note: audit confidence → High

    5 findings (2 suppressed): 3 informational, 0 low, 0 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_twine_upload() -> Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("use-trusted-publishing/twine-upload.yml"))
            .run()?,
        @r"
    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:12:14
       |
    12 |         run: twine upload dist/*
       |         ---  ^^^^^^^^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:15:14
       |
    15 |         run: python -m twine upload dist/*
       |         ---  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:19:11
       |
    18 |           run: |
       |           --- this step
    19 | /           python3.10 -m \
    20 | |             twine \
    21 | |             upload \
    22 | |             dist/*
       | |__________________^ this command
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:26:11
       |
    25 |         run: |
       |         --- this step
    26 |           pipx run twine==6.1.0 upload dist/*
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this command
       |
       = note: audit confidence → High

    6 findings (2 suppressed): 4 informational, 0 low, 0 medium, 0 high
    "
    );

    Ok(())
}
