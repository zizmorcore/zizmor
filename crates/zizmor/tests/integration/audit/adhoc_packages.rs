use crate::common::{input_under_test, zizmor};

#[test]
fn test_adhoc_packages() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("adhoc-packages.yml"))
            .run()?,
        @r"
    help[adhoc-packages]: ad-hoc package installation outside of a lockfile
      --> @@INPUT@@:18:14
       |
    18 |         run: gem install rake
       |         ---  ^^^^^^^^^^^^^^^^ installs a package outside of a lockfile
       |         |
       |         this step
       |
       = note: audit confidence → High

    help[adhoc-packages]: ad-hoc package installation outside of a lockfile
      --> @@INPUT@@:22:14
       |
    22 |         run: gem install rake rspec
       |         ---  ^^^^^^^^^^^^^^^^^^^^^^ installs a package outside of a lockfile
       |         |
       |         this step
       |
       = note: audit confidence → High

    help[adhoc-packages]: ad-hoc package installation outside of a lockfile
      --> @@INPUT@@:26:14
       |
    26 |         run: gem install rake -v 13.0.6
       |         ---  ^^^^^^^^^^^^^^^^^^^^^^^^^^ installs a package outside of a lockfile
       |         |
       |         this step
       |
       = note: audit confidence → High

    help[adhoc-packages]: ad-hoc package installation outside of a lockfile
      --> @@INPUT@@:30:14
       |
    30 |         run: gem install --no-document rake
       |         ---  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ installs a package outside of a lockfile
       |         |
       |         this step
       |
       = note: audit confidence → High

    4 findings: 0 informational, 4 low, 0 medium, 0 high
    "
    );

    Ok(())
}
