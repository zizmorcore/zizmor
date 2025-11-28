use crate::common::{input_under_test, zizmor};

#[test]
fn test_normal_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unsound-condition.yml"))
            .run()?,
        @r#"
    error[unsound-condition]: unsound conditional expression
      --> @@INPUT@@:27:9
       |
    27 | /         if: |
    28 | |           ${{ some.context }}
       | |_____________________________^ condition always evaluates to true
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[unsound-condition]: unsound conditional expression
      --> @@INPUT@@:33:9
       |
    33 | /         if: >
    34 | |           ${{ some.context }}
       | |_____________________________^ condition always evaluates to true
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[unsound-condition]: unsound conditional expression
      --> @@INPUT@@:60:9
       |
    60 | /         if: |
    61 | |           ${{ some.context
    62 | |             && other.context
    63 | |           }}
       | |____________^ condition always evaluates to true
       |
       = note: audit confidence → High
       = note: this finding has an auto-fix

    error[unsound-condition]: unsound conditional expression
      --> @@INPUT@@:68:9
       |
    68 |         if: true && ${{ false }} # zizmor: ignore[obfuscation]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^ condition always evaluates to true
       |
       = note: audit confidence → High

    error[unsound-condition]: unsound conditional expression
      --> @@INPUT@@:73:9
       |
    73 |         if: ${{ false }} && true # zizmor: ignore[obfuscation]
       |         ^^^^^^^^^^^^^^^^^^^^^^^^ condition always evaluates to true
       |
       = note: audit confidence → High

    error[unsound-condition]: unsound conditional expression
      --> @@INPUT@@:78:9
       |
    78 |         if: ${{ false }} lol # zizmor: ignore[obfuscation]
       |         ^^^^^^^^^^^^^^^^^^^^ condition always evaluates to true
       |
       = note: audit confidence → High

    error[unsound-condition]: unsound conditional expression
      --> @@INPUT@@:83:9
       |
    83 |         if: lol ${{ false }} # zizmor: ignore[obfuscation]
       |         ^^^^^^^^^^^^^^^^^^^^ condition always evaluates to true
       |
       = note: audit confidence → High

    error[unsound-condition]: unsound conditional expression
      --> @@INPUT@@:88:9
       |
    88 |         if: "${{ false }} " # zizmor: ignore[obfuscation]
       |         ^^^^^^^^^^^^^^^^^^^ condition always evaluates to true
       |
       = note: audit confidence → High

    error[unsound-condition]: unsound conditional expression
      --> @@INPUT@@:93:9
       |
    93 |         if: " ${{ false }}" # zizmor: ignore[obfuscation]
       |         ^^^^^^^^^^^^^^^^^^^ condition always evaluates to true
       |
       = note: audit confidence → High

    16 findings (6 ignored, 1 suppressed, 3 fixable): 0 informational, 0 low, 0 medium, 9 high
    "#
    );

    Ok(())
}
