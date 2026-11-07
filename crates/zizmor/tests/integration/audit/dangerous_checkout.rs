use zizmor_dev::{Zizmor, input_under_test};

#[test]
fn test_normal_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("dangerous-checkout.yml"))
            .run()?,
        @"
    error[unsafe-checkout]: unsafe Git checkout
      --> @@INPUT@@:20:11
       |
    17 |         uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
       |               --------------------------------------------------------- this checkout
    ...
    20 |           allow-unsafe-pr-checkout: true
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ enables unsafe checkouts here
       |
       = note: audit confidence → High

    error[unsafe-checkout]: unsafe Git checkout
      --> @@INPUT@@:26:11
       |
    23 |         uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
       |               --------------------------------------------------------- this checkout
    ...
    26 |           allow-unsafe-pr-checkout: ${{ github.event_name == 'push' }}
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ conditionally enables unsafe checkouts here
       |
       = note: audit confidence → Low

    2 findings: 0 informational, 0 low, 0 medium, 2 high
    "
    );

    Ok(())
}
