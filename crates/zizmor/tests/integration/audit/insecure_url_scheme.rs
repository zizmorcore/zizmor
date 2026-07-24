use crate::common::{input_under_test, zizmor};

#[test]
fn test_insecure_origin_pre_commit_config() -> anyhow::Result<()> {
    insta::assert_snapshot!(
    zizmor()
        .input(input_under_test("insecure-url-scheme/"))
        .run()?,
    @r#"
    error[insecure-url-scheme]: use of an insecure scheme within a URL
     --> @@INPUT@@.pre-commit-config.yml:2:11
      |
    2 | -   repo: http://github.com/pre-commit/pre-commit-hooks
      |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ repository URL uses an insecure scheme: "http"
      |
      = note: audit confidence → High

    error[insecure-url-scheme]: use of an insecure scheme within a URL
     --> @@INPUT@@.pre-commit-config.yml:6:11
      |
    6 | -   repo: git://github.com/pre-commit/pre-commit-hooks
      |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ repository URL uses an insecure scheme: "git"
      |
      = note: audit confidence → High

    2 findings: 0 informational, 0 low, 0 medium, 2 high
    "#
    );

    Ok(())
}
