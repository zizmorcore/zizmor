use zizmor_dev::{WorkspaceBuilder, Zizmor, input_under_test};

#[test]
fn test_regular_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test(
                "dependabot-execution/basic/dependabot.yml"
            ))
            .run()?,
        @"
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

    1 findings (1 unsafe fixes): 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

#[test]
fn test_fix_allow_to_deny() -> anyhow::Result<()> {
    let dependabot_content = r#"
version: 2

updates:
  - package-ecosystem: pip
    directory: /
    schedule:
      interval: daily
    cooldown:
      default-days: 7
    insecure-external-code-execution: allow
"#;

    let workspace = WorkspaceBuilder::default().is_git_repo(true).build()?;
    workspace.add_file(".github/dependabot.yml", dependabot_content);

    insta::assert_snapshot!(
        &workspace.diff(".github/dependabot.yml", |workspace| {
            Zizmor::cargo_bin()
                .args(["--fix=all"])
                .input(workspace.path())
                .run()
        })?,
        @"
    @@ -8,4 +8,4 @@
           interval: daily
         cooldown:
           default-days: 7
    -    insecure-external-code-execution: allow
    +    insecure-external-code-execution: deny
    "
    );
    Ok(())
}
