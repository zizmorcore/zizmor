use crate::common::{input_under_test, zizmor};

#[test]
fn test_regular_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("github-app.yml"))
            .run()?,
        @"
    error[github-app]: dangerous use of GitHub App tokens
      --> @@INPUT@@:21:11
       |
    19 |         uses: actions/create-github-app-token@1b10c78c7865c340bc4f6099eb2f838309f1e8c3 # v3.1.1
       |               ------------------------------------------------------------------------ app token requested here
    20 |         with:
    21 |           skip-token-revoke: true
       |           ^^^^^^^^^^^^^^^^^^^^^^^ token revocation disabled here
       |
       = note: audit confidence → High

    error[github-app]: dangerous use of GitHub App tokens
      --> @@INPUT@@:29:11
       |
    27 |         uses: actions/create-github-app-token@1b10c78c7865c340bc4f6099eb2f838309f1e8c3 # v3.1.1
       |               ------------------------------------------------------------------------ app token requested here
    28 |         with:
    29 |           skip-token-revoke: ${{ github.ref_name == 'main' }}
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ token revocation conditionally disabled here
       |
       = note: audit confidence → Low

    error[github-app]: dangerous use of GitHub App tokens
      --> @@INPUT@@:37:11
       |
    35 |         uses: actions/create-github-app-token@1b10c78c7865c340bc4f6099eb2f838309f1e8c3 # v3.1.1
       |               ------------------------------------------------------------------------ app token requested here
    36 |         with:
    37 |           owner: github
       |           ^^^^^^^^^^^^^ token granted access to all repositories for this owner's app installation
       |
       = note: audit confidence → High
       = tip: use `repositories: 'repo1,repo2'` to scope the token to specific repositories

    error[github-app]: dangerous use of GitHub App tokens
      --> @@INPUT@@:45:11
       |
    43 |         uses: actions/create-github-app-token@1b10c78c7865c340bc4f6099eb2f838309f1e8c3 # v3.1.1
       |               ------------------------------------------------------------------------ app token requested here
    44 |         with:
    45 |           owner: github
       |           ^^^^^^^^^^^^^ token granted access to all repositories for this owner's app installation
       |
       = note: audit confidence → High
       = tip: use `repositories: 'repo1,repo2'` to scope the token to specific repositories

    error[github-app]: dangerous use of GitHub App tokens
      --> @@INPUT@@:43:15
       |
    43 |         uses: actions/create-github-app-token@1b10c78c7865c340bc4f6099eb2f838309f1e8c3 # v3.1.1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ app token inherits blanket installation permissions
       |
       = note: audit confidence → High
       = tip: specify at least one `permission-<name>` input to limit the token's permissions

    5 findings: 0 informational, 0 low, 0 medium, 5 high
    ");
    Ok(())
}
