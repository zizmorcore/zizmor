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
      --> @@INPUT@@:19:9
       |
    19 |         uses: pypa/gh-action-pypi-publish@release/v1 # zizmor: ignore[unpinned-uses]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
    20 |         with:
    21 |           password: ${{ secrets.PYPI_TOKEN }}
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ uses a manually-configured credential instead of Trusted Publishing
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:26:9
       |
    26 |         uses: pypa/gh-action-pypi-publish@release/v1 # zizmor: ignore[unpinned-uses]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
    27 |         with:
    28 |           password: ${{ secrets.PYPI_TOKEN }}
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ uses a manually-configured credential instead of Trusted Publishing
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:34:9
       |
    34 |         uses: pypa/gh-action-pypi-publish@release/v1 # zizmor: ignore[unpinned-uses]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
    35 |         with:
    36 |           password: ${{ secrets.PYPI_TOKEN }}
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ uses a manually-configured credential instead of Trusted Publishing
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:52:9
       |
    52 |         uses: pypa/gh-action-pypi-publish@release/v1 # zizmor: ignore[unpinned-uses]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
    53 |         with:
    54 |           password: ${{ secrets.TEST_PYPI_TOKEN }}
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ uses a manually-configured credential instead of Trusted Publishing
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:59:9
       |
    59 |         uses: pypa/gh-action-pypi-publish@release/v1 # zizmor: ignore[unpinned-uses]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
    60 |         with:
    61 |           password: ${{ secrets.TEST_PYPI_TOKEN }}
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ uses a manually-configured credential instead of Trusted Publishing
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:66:9
       |
    66 |         uses: rubygems/release-gem@v1 # zizmor: ignore[unpinned-uses]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
    67 |         with:
    68 |           setup-trusted-publisher: false
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ uses a manually-configured credential instead of Trusted Publishing
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:83:9
       |
    83 |         uses: rubygems/configure-rubygems-credentials@v1 # zizmor: ignore[unpinned-uses]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
    84 |         with:
    85 |           api-token: ${{ secrets.RUBYGEMS_API_TOKEN }}
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ uses a manually-configured credential instead of Trusted Publishing
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:96:9
       |
    96 |         uses: rubygems/configure-rubygems-credentials@v1 # zizmor: ignore[unpinned-uses]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
    97 |         with:
    98 |           api-token: ${{ secrets.RUBYGEMS_API_TOKEN }}
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
      --> @@INPUT@@:13:14
       |
    13 |         run: cargo publish
       |         ---  ^^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:18:14
       |
    18 |         run: cargo +nightly publish
       |         ---  ^^^^^^^^^^^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:25:11
       |
    24 |           run: |
       |           --- this step
    25 | /           cargo \
    26 | |             publish \
    27 | |             --allow-dirty \
    28 | |             --no-verify
       | |_______________________^ this command
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:50:14
       |
    50 |         run: cargo publish
       |         ---  ^^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:55:14
       |
    55 |         run: cargo +nightly publish
       |         ---  ^^^^^^^^^^^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:62:11
       |
    61 |           run: |
       |           --- this step
    62 | /           cargo `
    63 | |             publish `
    64 | |             --allow-dirty `
    65 | |             --no-verify
       | |_______________________^ this command
       |
       = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:52:37
       |
    44 |   publish-2:
       |   --------- this job
    ...
    52 |           CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}
       |                                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:57:37
       |
    44 |   publish-2:
       |   --------- this job
    ...
    57 |           CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}
       |                                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    11 findings (3 suppressed): 6 informational, 0 low, 2 medium, 0 high
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
      --> @@INPUT@@:15:9
       |
    15 |         uses: actions/setup-node@v4 # zizmor: ignore[unpinned-uses]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
    ...
    19 |           always-auth: true
       |           ^^^^^^^^^^^^^^^^^ uses a manually-configured credential instead of Trusted Publishing
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:21:14
       |
    21 |         run: npm publish
       |         ---  ^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:27:9
       |
    27 |         uses: actions/setup-node@v4 # zizmor: ignore[unpinned-uses]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
    ...
    31 |           always-auth: true
       |           ^^^^^^^^^^^^^^^^^ uses a manually-configured credential instead of Trusted Publishing
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:33:14
       |
    33 |         run: npm publish
       |         ---  ^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:44:14
       |
    44 |         run: npm publish
       |         ---  ^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:50:14
       |
    50 |         run: npm publish --access public
       |         ---  ^^^^^^^^^^^^^^^^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:58:11
       |
    56 |         run: |
       |         --- this step
    57 |           npm config set registry https://registry.npmjs.org
    58 |           npm publish --access public
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^ this command
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:64:14
       |
    64 |         run: yarn npm publish
       |         ---  ^^^^^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:70:14
       |
    70 |         run: yarn npm publish --access public
       |         ---  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:76:14
       |
    76 |         run: pnpm publish
       |         ---  ^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
      --> @@INPUT@@:82:14
       |
    82 |         run: pnpm publish --access public
       |         ---  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this command
       |         |
       |         this step
       |
       = note: audit confidence → High

    info[use-trusted-publishing]: prefer trusted publishing for authentication
       --> @@INPUT@@:130:9
        |
    130 |         uses: actions/setup-node@v4 # zizmor: ignore[unpinned-uses]
        |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^ this step
    ...
    133 |           always-auth: true
        |           ^^^^^^^^^^^^^^^^^ uses a manually-configured credential instead of Trusted Publishing
        |
        = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:46:26
       |
    37 |   npm-direct-commands:
       |   ------------------- this job
    ...
    46 |           NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
       |                          ^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:52:26
       |
    37 |   npm-direct-commands:
       |   ------------------- this job
    ...
    52 |           NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
       |                          ^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:60:26
       |
    37 |   npm-direct-commands:
       |   ------------------- this job
    ...
    60 |           NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
       |                          ^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:66:36
       |
    37 |   npm-direct-commands:
       |   ------------------- this job
    ...
    66 |           YARN_NPM_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
       |                                    ^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:72:36
       |
    37 |   npm-direct-commands:
       |   ------------------- this job
    ...
    72 |           YARN_NPM_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
       |                                    ^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:78:26
       |
    37 |   npm-direct-commands:
       |   ------------------- this job
    ...
    78 |           NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
       |                          ^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:84:26
       |
    37 |   npm-direct-commands:
       |   ------------------- this job
    ...
    84 |           NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
       |                          ^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
       --> @@INPUT@@:126:32
        |
     87 |   npm-trusted-publishing:
        |   ---------------------- this job
    ...
    126 |           NODE_AUTH_TOKEN: ${{ secrets.CUSTOM_NPM_TOKEN }}
        |                                ^^^^^^^^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
        |
        = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
       --> @@INPUT@@:137:32
        |
     87 |   npm-trusted-publishing:
        |   ---------------------- this job
    ...
    137 |           NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
        |                                ^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
        |
        = note: audit confidence → High

    31 findings (6 ignored, 4 suppressed): 12 informational, 0 low, 9 medium, 0 high
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
