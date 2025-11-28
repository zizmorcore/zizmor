use crate::common::{input_under_test, zizmor};

#[test]
fn test_regular_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "dependabot-execution/basic/dependabot.yml"
            ))
            .run()?,
        @r"
    error[dependabot-execution]: external code execution in Dependabot updates
      --> @@INPUT@@:10:5
       |
     4 |   - package-ecosystem: pip
       |     ---------------------- this ecosystem
    ...
    10 |     insecure-external-code-execution: allow
       |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ enabled here
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    1 findings (1 fixable): 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}
