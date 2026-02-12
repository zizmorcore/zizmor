use crate::common::{input_under_test, zizmor};

#[test]
fn test_pedantic_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test("unpinned-images.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @"
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

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:19:3
       |
    19 | /   unpinned-container-image:
    20 | |     name: unpinned-container-image
    21 | |     runs-on: ubuntu-latest
    22 | |     container:
    23 | |       image: fake.example.com/example
    24 | |     steps:
    25 | |       - run: echo 'vulnerable!'
       | |_______________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:27:3
       |
    27 | /   unpinned-service-container-image:
    28 | |     name: unpinned-service-container-image
    29 | |     runs-on: ubuntu-latest
    30 | |     services:
    ...  |
    33 | |     steps:
    34 | |       - run: echo 'vulnerable!'
       | |_______________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:36:3
       |
    36 | /   unpinned-container-image-latest:
    37 | |     name: unpinned-container-image-latest
    38 | |     runs-on: ubuntu-latest
    39 | |     container:
    40 | |       image: fake.example.com/example:latest
    41 | |     steps:
    42 | |       - run: echo 'vulnerable!'
       | |_______________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:44:3
       |
    44 | /   unpinned-service-container-image-latest:
    45 | |     name: unpinned-service-container-image-latest
    46 | |     runs-on: ubuntu-latest
    47 | |     services:
    ...  |
    50 | |     steps:
    51 | |       - run: echo 'vulnerable!'
       | |_______________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:53:3
       |
    53 | /   tag-pinned-container-image:
    54 | |     name: tag-pinned-container-image
    55 | |     runs-on: ubuntu-latest
    56 | |     container:
    57 | |       image: fake.example.com/example:0.0.348
    58 | |     steps:
    59 | |       - run: echo 'not vulnerable!'
       | |___________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:61:3
       |
    61 | /   tag-pinned-service-container-image:
    62 | |     name: tag-pinned-service-container-image
    63 | |     runs-on: ubuntu-latest
    64 | |     services:
    ...  |
    67 | |     steps:
    68 | |       - run: echo 'not vulnerable!'
       | |___________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:70:3
       |
    70 | /   hash-pinned-container-image:
    71 | |     name: hash-pinned-container-image
    72 | |     runs-on: ubuntu-latest
    73 | |     container:
    74 | |       image: fake.example.com/example@sha256:bfadbbcb25fd75c30c295843f1a861414f46c080f0f1d0c5cd93843c88edabcf
    75 | |     steps:
    76 | |       - run: echo 'not vulnerable!'
       | |___________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    help[missing-timeout]: job does not set a timeout
      --> @@INPUT@@:78:3
       |
    78 | /   hash-pinned-service-container-image:
    79 | |     name: hash-pinned-service-container-image
    80 | |     runs-on: ubuntu-latest
    81 | |     services:
    ...  |
    84 | |     steps:
    85 | |       - run: echo 'not vulnerable!'
       | |____________________________________^ job is missing a timeout-minutes setting
       |
       = note: audit confidence → High
       = tip: set 'timeout-minutes: <N>' to prevent hung jobs from consuming runner minutes

    14 findings: 0 informational, 8 low, 0 medium, 6 high
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
