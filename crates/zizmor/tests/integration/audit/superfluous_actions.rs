use crate::common::{input_under_test, zizmor};

#[test]
fn test_superfluous_actions() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("superfluous-actions.yml"))
            .run()?,
        @r"
    help[superfluous-actions]: action functionality is already included by the runner
      --> @@INPUT@@:16:15
       |
    15 |       - name: setup rust
       |         ---------------- this step
    16 |         uses: dtolnay/rust-toolchain@086dfa4efe372cfb6b375460a56e26a62a873d2e # 1.93.1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ use `rustup` and/or `cargo` in a script step
       |
       = note: audit confidence → High

    help[superfluous-actions]: action functionality is already included by the runner
      --> @@INPUT@@:19:15
       |
    18 |       - name: update comment
       |         -------------------- this step
    19 |         uses: peter-evans/create-or-update-comment@e8674b075228eee787fea43ef493e45ece1004c9 # v5.0.0
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ use `gh pr comment` or `gh issue comment` in a script step
       |
       = note: audit confidence → High

    2 findings: 0 informational, 2 low, 0 medium, 0 high
    ");

    Ok(())
}
