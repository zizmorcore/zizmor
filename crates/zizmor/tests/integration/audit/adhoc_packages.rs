use crate::common::{input_under_test, zizmor};

#[test]
fn test_adhoc_packages() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("adhoc-packages.yml"))
            .run()?,
        @r#"
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
    26 |         run: gem install rake:13.0.6
       |         ---  ^^^^^^^^^^^^^^^^^^^^^^^ installs a package outside of a lockfile
       |         |
       |         this step
       |
       = note: audit confidence → High

    help[adhoc-packages]: ad-hoc package installation outside of a lockfile
      --> @@INPUT@@:30:14
       |
    30 |         run: gem install rake -v 13.0.6
       |         ---  ^^^^^^^^^^^^^^^^^^^^^^^^^^ installs a package outside of a lockfile
       |         |
       |         this step
       |
       = note: audit confidence → High

    help[adhoc-packages]: ad-hoc package installation outside of a lockfile
      --> @@INPUT@@:34:14
       |
    34 |         run: gem install --no-document rake
       |         ---  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ installs a package outside of a lockfile
       |         |
       |         this step
       |
       = note: audit confidence → High

    help[adhoc-packages]: ad-hoc package installation outside of a lockfile
      --> @@INPUT@@:38:14
       |
    38 |         run: gem i rake
       |         ---  ^^^^^^^^^^ installs a package outside of a lockfile
       |         |
       |         this step
       |
       = note: audit confidence → High

    help[adhoc-packages]: ad-hoc package installation outside of a lockfile
      --> @@INPUT@@:44:11
       |
    42 |         run: |
       |         --- this step
    43 |           echo "Hello"
    44 |           gem install foo
       |           ^^^^^^^^^^^^^^^ installs a package outside of a lockfile
       |
       = note: audit confidence → High

    help[adhoc-packages]: ad-hoc package installation outside of a lockfile
      --> @@INPUT@@:45:11
       |
    42 |         run: |
       |         --- this step
    ...
    45 |           gem install bar
       |           ^^^^^^^^^^^^^^^ installs a package outside of a lockfile
       |
       = note: audit confidence → High

    help[adhoc-packages]: ad-hoc package installation outside of a lockfile
      --> @@INPUT@@:50:14
       |
    50 |         run: npm install lodash
       |         ---  ^^^^^^^^^^^^^^^^^^ installs a package outside of a lockfile
       |         |
       |         this step
       |
       = note: audit confidence → High

    help[adhoc-packages]: ad-hoc package installation outside of a lockfile
      --> @@INPUT@@:54:14
       |
    54 |         run: npm install oxlint@1.55.0
       |         ---  ^^^^^^^^^^^^^^^^^^^^^^^^^ installs a package outside of a lockfile
       |         |
       |         this step
       |
       = note: audit confidence → High

    help[adhoc-packages]: ad-hoc package installation outside of a lockfile
      --> @@INPUT@@:58:14
       |
    58 |         run: npm install --no-fund oxlint@1.55.0
       |         ---  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ installs a package outside of a lockfile
       |         |
       |         this step
       |
       = note: audit confidence → High

    help[adhoc-packages]: ad-hoc package installation outside of a lockfile
      --> @@INPUT@@:62:14
       |
    62 |         run: npm i lodash
       |         ---  ^^^^^^^^^^^^ installs a package outside of a lockfile
       |         |
       |         this step
       |
       = note: audit confidence → High

    help[adhoc-packages]: ad-hoc package installation outside of a lockfile
      --> @@INPUT@@:66:14
       |
    66 |         run: npm add lodash
       |         ---  ^^^^^^^^^^^^^^ installs a package outside of a lockfile
       |         |
       |         this step
       |
       = note: audit confidence → High

    help[adhoc-packages]: ad-hoc package installation outside of a lockfile
       --> @@INPUT@@:123:14
        |
    123 |         run: gem install rake
        |         ---  ^^^^^^^^^^^^^^^^ installs a package outside of a lockfile
        |         |
        |         this step
        |
        = note: audit confidence → High

    help[adhoc-packages]: ad-hoc package installation outside of a lockfile
       --> @@INPUT@@:127:14
        |
    127 |         run: npm install lodash
        |         ---  ^^^^^^^^^^^^^^^^^^ installs a package outside of a lockfile
        |         |
        |         this step
        |
        = note: audit confidence → High

    help[adhoc-packages]: ad-hoc package installation outside of a lockfile
       --> @@INPUT@@:137:11
        |
    135 |         run: |
        |         --- this step
    136 |           Write-Host "Hello"
    137 |           gem install foo
        |           ^^^^^^^^^^^^^^^ installs a package outside of a lockfile
        |
        = note: audit confidence → High

    16 findings: 0 informational, 16 low, 0 medium, 0 high
    "#
    );

    Ok(())
}
