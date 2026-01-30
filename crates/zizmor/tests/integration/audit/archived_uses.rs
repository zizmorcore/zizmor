use crate::common::{input_under_test, zizmor};

#[test]
fn test_regular_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor().input(input_under_test("archived-uses.yml")).run()?,
        @r"
    warning[archived-uses]: action or reusable workflow from archived repository
      --> @@INPUT@@:17:15
       |
    16 |       - name: setup ruby
       |         ---------------- this step
    17 |         uses: actions/setup-ruby@e932e7af67fc4a8fc77bd86b744acd4e42fe3543 # v1.1.3
       |               ^^^^^^^^^^^^^^^^^^ repository is archived
       |
       = note: audit confidence → High

    warning[archived-uses]: action or reusable workflow from archived repository
      --> @@INPUT@@:20:15
       |
    19 |       - name: SETUP RUBY BUT LOUDLY
       |         --------------------------- this step
    20 |         uses: ACTIONS/SETUP-RUBY@e932e7af67fc4a8fc77bd86b744acd4e42fe3543 # v1.1.3
       |               ^^^^^^^^^^^^^^^^^^ repository is archived
       |
       = note: audit confidence → High

    warning[archived-uses]: action or reusable workflow from archived repository
      --> @@INPUT@@:24:11
       |
    23 |     name: archived-uses-reusable
       |     ---------------------------- this job
    24 |     uses: actions/setup-ruby/.github/workflows/notreal.yml@e932e7af67fc4a8fc77bd86b744acd4e42fe3543 # v1.1.3
       |           ^^^^^^^^^^^^^^^^^^ repository is archived
       |
       = note: audit confidence → High

    3 findings: 0 informational, 0 low, 3 medium, 0 high
    "
    );

    Ok(())
}

#[test]
fn test_composite_action() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("archived-uses/action/"))
            .run()?,
        @r"
    warning[archived-uses]: action or reusable workflow from archived repository
     --> @@INPUT@@action.yml:9:13
      |
    8 |     - name: setup ruby
      |       ---------------- this step
    9 |       uses: actions/setup-ruby@e932e7af67fc4a8fc77bd86b744acd4e42fe3543 # v1.1.3
      |             ^^^^^^^^^^^^^^^^^^ repository is archived
      |
      = note: audit confidence → High

    1 finding: 0 informational, 0 low, 1 medium, 0 high
    "
    );

    Ok(())
}
