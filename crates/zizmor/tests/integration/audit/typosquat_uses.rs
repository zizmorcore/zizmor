use crate::common::{input_under_test, zizmor};

#[test]
fn test_regular_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("typosquat-uses.yml"))
            .run()?,
        @"
    error[typosquat-uses]: action reference resembles a popular action
      --> @@INPUT@@:17:15
       |
    16 |       - name: omission
       |         -------------- this step
    17 |         uses: action/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
       |               ^^^^^^^^^^^^^^^ action/checkout omits characters in actions/checkout
       |
       = note: audit confidence → Low

    error[typosquat-uses]: action reference resembles a popular action
      --> @@INPUT@@:20:15
       |
    19 |       - name: transposition
       |         ------------------- this step
    20 |         uses: cations/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
       |               ^^^^^^^^^^^^^^^^ cations/checkout swaps characters in actions/checkout
       |
       = note: audit confidence → Low

    error[typosquat-uses]: action reference resembles a popular action
      --> @@INPUT@@:23:15
       |
    22 |       - name: homoglyph
       |         --------------- this step
    23 |         uses: acti0ns/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
       |               ^^^^^^^^^^^^^^^^ acti0ns/checkout uses a common typo for actions/checkout
       |
       = note: audit confidence → Low

    error[typosquat-uses]: action reference resembles a popular action
      --> @@INPUT@@:26:15
       |
    25 |       - name: repetition
       |         ---------------- this step
    26 |         uses: actiions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
       |               ^^^^^^^^^^^^^^^^^ actiions/checkout repeats characters in actions/checkout
       |
       = note: audit confidence → Low

    error[typosquat-uses]: action reference resembles a popular action
      --> @@INPUT@@:29:15
       |
    28 |       - name: owner transposition
       |         ------------------------- this step
    29 |         uses: dokcer/login-action@9780b0c442fbb1117ed29e0efdff1e18412f7567 # v3.3.0
       |               ^^^^^^^^^^^^^^^^^^^ dokcer/login-action swaps characters in docker/login-action
       |
       = note: audit confidence → Low

    5 findings: 0 informational, 0 low, 0 medium, 5 high
    "
    );

    Ok(())
}
