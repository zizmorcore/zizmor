use crate::common::{input_under_test, zizmor};

#[test]
fn test_regular_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("github-app.yml"))
            .run()?,
        @"
    error[github-app]: dangerous use of GitHub App tokens
      --> @@INPUT@@:19:11
       |
    17 |         uses: actions/create-github-app-token@1b10c78c7865c340bc4f6099eb2f838309f1e8c3 # v3.1.1
       |               ------------------------------------------------------------------------ app token requested here
    18 |         with:
    19 |           skip-token-revoke: true
       |           ^^^^^^^^^^^^^^^^^^^^^^^ token revocation disabled here
       |
       = note: audit confidence → High

    error[github-app]: dangerous use of GitHub App tokens
      --> @@INPUT@@:27:11
       |
    25 |         uses: actions/create-github-app-token@1b10c78c7865c340bc4f6099eb2f838309f1e8c3 # v3.1.1
       |               ------------------------------------------------------------------------ app token requested here
    26 |         with:
    27 |           skip-token-revoke: ${{ github.ref_name == 'main' }}
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ token revocation conditionally disabled here
       |
       = note: audit confidence → Low

    error[github-app]: dangerous use of GitHub App tokens
      --> @@INPUT@@:35:11
       |
    33 |         uses: actions/create-github-app-token@1b10c78c7865c340bc4f6099eb2f838309f1e8c3 # v3.1.1
       |               ------------------------------------------------------------------------ app token requested here
    34 |         with:
    35 |           owner: github
       |           ^^^^^^^^^^^^^ token granted access to all repositories for this owner's app installation
       |
       = note: audit confidence → High
       = tip: use `repositories: 'repo1,repo2'` to scope the token to specific repositories

    error[github-app]: dangerous use of GitHub App tokens
      --> @@INPUT@@:43:11
       |
    41 |         uses: actions/create-github-app-token@1b10c78c7865c340bc4f6099eb2f838309f1e8c3 # v3.1.1
       |               ------------------------------------------------------------------------ app token requested here
    42 |         with:
    43 |           owner: github
       |           ^^^^^^^^^^^^^ token granted access to all repositories for this owner's app installation
       |
       = note: audit confidence → High
       = tip: use `repositories: 'repo1,repo2'` to scope the token to specific repositories

    error[github-app]: dangerous use of GitHub App tokens
      --> @@INPUT@@:41:15
       |
    41 |         uses: actions/create-github-app-token@1b10c78c7865c340bc4f6099eb2f838309f1e8c3 # v3.1.1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ app token inherits blanket installation permissions
       |
       = note: audit confidence → High
       = tip: specify at least one `permission-<name>` input to limit the token's permissions

    9 findings (4 suppressed): 0 informational, 0 low, 0 medium, 5 high
    ");
    Ok(())
}
