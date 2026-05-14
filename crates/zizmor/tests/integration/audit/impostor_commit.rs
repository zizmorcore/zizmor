use crate::common::{input_under_test, zizmor};

#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_regular_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("impostor-commit.yml"))
            .offline(false)
            .run()?,
        @"
    error[impostor-commit]: commit with no history in referenced repository
      --> @@INPUT@@:29:15
       |
    29 |         - uses: actions/checkout@c7d749a2d57b4b375d1ebcd17cfbfb60c676f18e
       |           -     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ uses a commit that doesn't belong to the specified org/repo
       |  _________|
       | |
    30 | |         with:
    31 | |           persist-credentials: false
       | |____________________________________- this step
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    4 findings (3 suppressed, 1 unsafe fixes): 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

/// Test for #1997: if a user does something like `uses: foo/bar@sha`
/// where `sha` is a tag SHA, then we should correctly "peel" that tag
/// back to its original commit SHA rather than emitting a false positive.
#[cfg_attr(not(feature = "gh-token-tests"), ignore)]
#[test]
fn test_peels_tag_sha_to_commit_sha() -> anyhow::Result<()> {
    insta::assert_snapshot!(
    zizmor()
        .input(input_under_test("impostor-commit/sha-is-tag.yml"))
        .offline(false)
        .run()?,
    @"No findings to report. Good job! (3 suppressed)"
    );

    Ok(())
}
