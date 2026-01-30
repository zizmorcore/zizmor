use crate::common::{input_under_test, zizmor};

#[test]
fn test_pedantic_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-images.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @r"
    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:23:7
       |
    23 |       image: fake.example.com/example
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ container image is unpinned
       |
       = note: audit confidence → High

    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:32:9
       |
    32 |         image: fake.example.com/redis
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ container image is unpinned
       |
       = note: audit confidence → High

    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:40:7
       |
    40 |       image: fake.example.com/example:latest
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ container image is pinned to latest
       |
       = note: audit confidence → High

    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:49:9
       |
    49 |         image: fake.example.com/redis:latest
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ container image is pinned to latest
       |
       = note: audit confidence → High

    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:57:7
       |
    57 |       image: fake.example.com/example:0.0.348
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ container image is not pinned to a SHA256 hash
       |
       = note: audit confidence → High

    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:66:9
       |
    66 |         image: fake.example.com/redis:7.4.3
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ container image is not pinned to a SHA256 hash
       |
       = note: audit confidence → High

    6 findings: 0 informational, 0 low, 0 medium, 6 high
    "
    );

    Ok(())
}

#[test]
fn test_matrix_in_image_pedantic() -> anyhow::Result<()> {
    // pedantic: shows unhashed findings
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-images/matrix-in-image.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @r"
    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:20:7
       |
    20 |       image: ${{ matrix.image }}
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^ container image is not pinned to a SHA256 hash
    ...
    23 |       matrix:
       |       ------ this matrix
    ...
    28 |             image: ubuntu:24.04
       |             ------------------- this expansion of matrix.image
       |
       = note: audit confidence → High

    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:20:7
       |
    20 |       image: ${{ matrix.image }}
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^ container image is not pinned to a SHA256 hash
    ...
    23 |       matrix:
       |       ------ this matrix
    ...
    32 |             image: ubuntu:22.04
       |             ------------------- this expansion of matrix.image
       |
       = note: audit confidence → High

    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:20:7
       |
    20 |       image: ${{ matrix.image }}
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^ container image is unpinned
    ...
    23 |       matrix:
       |       ------ this matrix
    ...
    37 |             image: ubuntu
       |             ------------- this expansion of matrix.image
       |
       = note: audit confidence → High

    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:20:7
       |
    20 |       image: ${{ matrix.image }}
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^ container image is pinned to latest
    ...
    23 |       matrix:
       |       ------ this matrix
    ...
    42 |             image: ubuntu:latest
       |             -------------------- this expansion of matrix.image
       |
       = note: audit confidence → High

    4 findings: 0 informational, 0 low, 0 medium, 4 high
    "
    );

    Ok(())
}

#[test]
fn test_matrix_in_image_regular() -> anyhow::Result<()> {
    // regular persona: suppresses unhashed findings
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-images/matrix-in-image.yml"))
            .run()?,
        @r"
    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:20:7
       |
    20 |       image: ${{ matrix.image }}
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^ container image is unpinned
    ...
    23 |       matrix:
       |       ------ this matrix
    ...
    37 |             image: ubuntu
       |             ------------- this expansion of matrix.image
       |
       = note: audit confidence → High

    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:20:7
       |
    20 |       image: ${{ matrix.image }}
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^ container image is pinned to latest
    ...
    23 |       matrix:
       |       ------ this matrix
    ...
    42 |             image: ubuntu:latest
       |             -------------------- this expansion of matrix.image
       |
       = note: audit confidence → High

    4 findings (2 suppressed): 0 informational, 0 low, 0 medium, 2 high
    "
    );

    Ok(())
}
