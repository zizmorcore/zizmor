use zizmor_dev::{Zizmor, input_under_test};

#[test]
fn test_pedantic_persona() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("unpinned-images.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @r#"
    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:30:7
       |
    30 |       image: fake.example.com/example
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ container image is unpinned
       |
       = note: audit confidence → High

    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:39:9
       |
    39 |         image: fake.example.com/redis
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ container image is unpinned
       |
       = note: audit confidence → High

    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:47:7
       |
    47 |       image: fake.example.com/example:latest
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ container image uses the floating 'latest' tag
       |
       = note: audit confidence → High

    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:56:9
       |
    56 |         image: fake.example.com/redis:latest
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ container image uses the floating 'latest' tag
       |
       = note: audit confidence → High

    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:64:7
       |
    64 |       image: fake.example.com/example:0.0.348
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ container image is not pinned to a SHA256 hash
       |
       = note: audit confidence → High

    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:73:9
       |
    73 |         image: fake.example.com/redis:7.4.3
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ container image is not pinned to a SHA256 hash
       |
       = note: audit confidence → High

    error[unpinned-images]: unpinned image references
       --> @@INPUT@@:108:9
        |
    108 |         image: ${{ inputs.use-redis && 'redis:7' || '' }}
        |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ container image "redis:7" is not pinned to a SHA256 hash
        |
        = note: audit confidence → High

    error[unpinned-images]: unpinned image references
       --> @@INPUT@@:125:7
        |
    125 |       image: ${{ inputs.image || vars.DEFAULT_IMAGE }}
        |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ container image may be unpinned
        |
        = note: audit confidence → Low

    error[unpinned-images]: unpinned image references
       --> @@INPUT@@:133:24
        |
    133 |       - uses: docker://ubuntu
        |                        ^^^^^^ container image is unpinned
        |
        = note: audit confidence → High

    error[unpinned-images]: unpinned image references
       --> @@INPUT@@:134:24
        |
    134 |       - uses: docker://ubuntu:latest
        |                        ^^^^^^^^^^^^^ container image uses the floating 'latest' tag
        |
        = note: audit confidence → High

    error[unpinned-images]: unpinned image references
       --> @@INPUT@@:135:24
        |
    135 |       - uses: docker://ghcr.io/pypa/gh-action-pypi-publish
        |                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ container image is unpinned
        |
        = note: audit confidence → High

    11 findings: 0 informational, 0 low, 0 medium, 11 high
    "#
    );

    Ok(())
}

#[test]
fn test_evaluated_images() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("unpinned-images/evaluated-images.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @r#"
    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:32:5
       |
    14 |       container: '{"image":"alpine:latest"}'
       |       -------------------------------------- this job declares output container
    ...
    32 |     container: ${{ fromJSON(needs.define.outputs.container) }}
       |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ container image "alpine:latest" uses the floating 'latest' tag
       |
       = note: audit confidence → High

    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:34:7
       |
    25 |           - name: redis
       |             ----------- matrix value defined here
    26 |             tag: '7'
       |             -------- matrix value defined here
    ...
    34 |       cache: registry.example/${{ matrix.name }}:${{ matrix.tag }}
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ container image "registry.example/redis:7" is not pinned to a SHA256 hash
       |
       = note: audit confidence → High

    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:34:7
       |
    27 |           - name: valkey
       |             ------------ matrix value defined here
    28 |             tag: latest
       |             ----------- matrix value defined here
    ...
    34 |       cache: registry.example/${{ matrix.name }}:${{ matrix.tag }}
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ container image "registry.example/valkey:latest" uses the floating 'latest' tag
       |
       = note: audit confidence → High

    4 findings (1 ignored): 0 informational, 0 low, 0 medium, 3 high
    "#
    );

    Ok(())
}

#[test]
fn test_matrix_in_image_pedantic() -> anyhow::Result<()> {
    // pedantic: shows unhashed findings
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("unpinned-images/matrix-in-image.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @r#"
    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:20:7
       |
    20 |       image: ${{ matrix.image }}
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^ container image "ubuntu:24.04" is not pinned to a SHA256 hash
    ...
    28 |             image: ubuntu:24.04
       |             ------------------- matrix value defined here
       |
       = note: audit confidence → High

    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:20:7
       |
    20 |       image: ${{ matrix.image }}
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^ container image "ubuntu:22.04" is not pinned to a SHA256 hash
    ...
    32 |             image: ubuntu:22.04
       |             ------------------- matrix value defined here
       |
       = note: audit confidence → High

    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:20:7
       |
    20 |       image: ${{ matrix.image }}
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^ container image "ubuntu" is unpinned
    ...
    37 |             image: ubuntu
       |             ------------- matrix value defined here
       |
       = note: audit confidence → High

    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:20:7
       |
    20 |       image: ${{ matrix.image }}
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^ container image "ubuntu:latest" uses the floating 'latest' tag
    ...
    42 |             image: ubuntu:latest
       |             -------------------- matrix value defined here
       |
       = note: audit confidence → High

    4 findings: 0 informational, 0 low, 0 medium, 4 high
    "#
    );

    Ok(())
}

#[test]
fn test_matrix_in_image_regular() -> anyhow::Result<()> {
    // regular persona: suppresses unhashed findings
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("unpinned-images/matrix-in-image.yml"))
            .run()?,
        @r#"
    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:20:7
       |
    20 |       image: ${{ matrix.image }}
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^ container image "ubuntu" is unpinned
    ...
    37 |             image: ubuntu
       |             ------------- matrix value defined here
       |
       = note: audit confidence → High

    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:20:7
       |
    20 |       image: ${{ matrix.image }}
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^ container image "ubuntu:latest" uses the floating 'latest' tag
    ...
    42 |             image: ubuntu:latest
       |             -------------------- matrix value defined here
       |
       = note: audit confidence → High

    4 findings (2 suppressed): 0 informational, 0 low, 0 medium, 2 high
    "#
    );

    Ok(())
}

#[test]
fn test_matrix_indirect_expansions() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("unpinned-images/indirect-matrices.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @r#"
    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:18:7
       |
    18 |       image: ${{ matrix.image }}
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^ container image may be unpinned
    19 |     strategy:
    20 |       matrix: ${{ fromJSON(vars.CUSTOM_TARGETS) }}
       |       -------------------------------------------- matrix value defined here
       |
       = note: audit confidence → Low

    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:29:7
       |
    29 |       image: ${{ matrix.image }}
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^ container image "ubuntu:latest" uses the floating 'latest' tag
    ...
    35 |           - ubuntu:latest
       |             ------------- matrix value defined here
       |
       = note: audit confidence → High

    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:29:7
       |
    29 |       image: ${{ matrix.image }}
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^ container image may be unpinned
    ...
    36 |         include: ${{ fromJSON(vars.EXTRA_TARGETS) }}
       |         -------------------------------------------- matrix value defined here
       |
       = note: audit confidence → Low

    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:45:7
       |
    45 |       image: ${{ matrix.image }}
       |       ^^^^^^^^^^^^^^^^^^^^^^^^^^ container image "ubuntu:latest" uses the floating 'latest' tag
    ...
    53 |           - ubuntu:latest
       |             ------------- matrix value defined here
       |
       = note: audit confidence → High

    4 findings: 0 informational, 0 low, 0 medium, 4 high
    "#
    );

    Ok(())
}

#[test]
fn test_urllib3_empty_matrix_container_regular() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test(
                "unpinned-images/urllib3-empty-matrix-container.yml"
            ))
            .run()?,
        @r#"
    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:51:5
       |
    41 |             container: python
       |             ----------------- matrix value defined here
    ...
    51 |     container: ${{ matrix.container }}
       |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ container image "python" is unpinned
       |
       = note: audit confidence → High

    2 findings (1 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_issue_1942_repro() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("unpinned-images/issue-1942-repro.yml"))
            .args(["--persona=pedantic"])
            .run()?,
        @"
    error[unpinned-images]: unpinned image references
      --> @@INPUT@@:13:5
       |
    13 |     container: node:18
       |     ^^^^^^^^^^^^^^^^^^ container image is not pinned to a SHA256 hash
       |
       = note: audit confidence → High

    1 finding: 0 informational, 0 low, 0 medium, 1 high
    "
    );

    Ok(())
}

/// Tests that `unpinned-images` handles Docker-style action definitions, not just images
/// in jobs/steps within workflows.
#[test]
fn test_docker_action() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("unpinned-images/docker-action/"))
            .args(["--persona=pedantic"])
            .run()?,
        @r#"
    error[unpinned-images]: unpinned image references
     --> @@INPUT@@/action.yml:7:3
      |
    7 |   image: "docker://ghcr.io/super-linter/super-linter:slim-v8.5.0" # x-release-please-version
      |   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ container image is not pinned to a SHA256 hash
      |
      = note: audit confidence → High

    1 finding: 0 informational, 0 low, 0 medium, 1 high
    "#
    );

    Ok(())
}

#[test]
fn test_issue_2097_repro() -> anyhow::Result<()> {
    // `${{ matrix.mysql || '' }}` expands to either a hash-pinned image or an
    // empty (absent) container, so there's nothing to report.
    insta::assert_snapshot!(
        Zizmor::cargo_bin()
            .input(input_under_test("unpinned-images/issue-2097-repro.yml"))
            .run()?,
        @"No findings to report. Good job!"
    );

    Ok(())
}
