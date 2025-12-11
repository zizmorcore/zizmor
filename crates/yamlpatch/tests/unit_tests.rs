use std::borrow::Cow;
use yamlpatch::*;
use yamlpath::route;

/// Format the patch with fencing to ensure that interior whitespace is preserved.
fn format_patch(patch: &str) -> String {
    format!("--- PATCH ---\n{patch}\n--- END PATCH ---")
}

#[test]
fn test_serialize_flow() {
    let doc = r#"
foo:
  bar:
  baz: qux
  abc:
    - def
    - ghi
    - null
    - ~
    - |
      abcd
      efgh

flow: [1, 2, 3, {more: 456, evenmore: "abc\ndef"}]
"#;

    let value: serde_yaml::Value = serde_yaml::from_str(doc).unwrap();
    let serialized = serialize_flow(&value).unwrap();

    // serialized is valid YAML
    assert!(serde_yaml::from_str::<serde_yaml::Value>(&serialized).is_ok());

    insta::assert_snapshot!(format_patch(&serialized), @r#"
    --- PATCH ---
    { foo: { bar: , baz: qux, abc: [def, ghi, null, null, "abcd\nefgh\n"] }, flow: [1, 2, 3, { more: 456, evenmore: "abc\ndef" }] }
    --- END PATCH ---
    "#);
}

#[test]
fn test_detect_style() {
    let doc = r#"
block-mapping-a:
  foo: bar
  baz: qux

"block-mapping-b":
  foo: bar

block-sequence-a:
  - item1
  - item2
  - item3

"block-sequence-b":
  - item1
  - item2
  - item3

flow-mapping-a: { a: b, c: d }
flow-mapping-b: { a: b, c: d, }
flow-mapping-c: {
  a: b,
  c: d
}
flow-mapping-d: {
  a: b,
  c: d,
}
flow-mapping-e: {
  a: b, c: d,
}
flow-mapping-f: { abc }
flow-mapping-g: { abc: }

flow-sequence-a: [item1, item2, item3]
flow-sequence-b: [ item1, item2, item3 ]
flow-sequence-c: [
  item1,
  item2,
  item3
]
flow-sequence-d: [
  item1,
  item2,
  item3,
]

scalars:
  - 123
  - abc
  - "abc"
  - 'abc'
  - -123
  - '{abc}'
  - '[abc]'
  - abc def

multiline-scalars:
  literal-a: |
    abcd
  literal-b: |-
    abcd
  literal-c: |+
    abcd
  literal-d: |2
    abcd
  literal-e: |-2
    abcd

  folded-a: >
    abcd
  folded-b: >-
    abcd
  folded-c: >+
    abcd
  folded-d: >2
    abcd
  folded-e: >-2
    abcd

empty:
  foo:

"#;

    let doc = yamlpath::Document::new(doc).unwrap();

    for (route, expected_style) in &[
        (route!("block-mapping-a"), Style::BlockMapping),
        (route!("block-mapping-b"), Style::BlockMapping),
        (route!("block-sequence-a"), Style::BlockSequence),
        (route!("block-sequence-b"), Style::BlockSequence),
        (route!("flow-mapping-a"), Style::FlowMapping),
        (route!("flow-mapping-b"), Style::FlowMapping),
        (route!("flow-mapping-c"), Style::MultilineFlowMapping),
        (route!("flow-mapping-d"), Style::MultilineFlowMapping),
        (route!("flow-mapping-e"), Style::MultilineFlowMapping),
        (route!("flow-mapping-f"), Style::FlowMapping),
        (route!("flow-mapping-g"), Style::FlowMapping),
        (route!("flow-sequence-a"), Style::FlowSequence),
        (route!("flow-sequence-b"), Style::FlowSequence),
        (route!("flow-sequence-c"), Style::MultilineFlowSequence),
        (route!("flow-sequence-d"), Style::MultilineFlowSequence),
        (route!("scalars", 0), Style::PlainScalar),
        (route!("scalars", 1), Style::PlainScalar),
        (route!("scalars", 2), Style::DoubleQuoted),
        (route!("scalars", 3), Style::SingleQuoted),
        (route!("scalars", 4), Style::PlainScalar),
        (route!("scalars", 5), Style::SingleQuoted),
        (route!("scalars", 6), Style::SingleQuoted),
        (route!("scalars", 7), Style::PlainScalar),
        (
            route!("multiline-scalars", "literal-a"),
            Style::MultilineLiteralScalar,
        ),
        (
            route!("multiline-scalars", "literal-b"),
            Style::MultilineLiteralScalar,
        ),
        (
            route!("multiline-scalars", "literal-c"),
            Style::MultilineLiteralScalar,
        ),
        (
            route!("multiline-scalars", "literal-d"),
            Style::MultilineLiteralScalar,
        ),
        (
            route!("multiline-scalars", "literal-e"),
            Style::MultilineLiteralScalar,
        ),
        (
            route!("multiline-scalars", "folded-a"),
            Style::MultilineFoldedScalar,
        ),
        (
            route!("multiline-scalars", "folded-b"),
            Style::MultilineFoldedScalar,
        ),
        (
            route!("multiline-scalars", "folded-c"),
            Style::MultilineFoldedScalar,
        ),
        (
            route!("multiline-scalars", "folded-d"),
            Style::MultilineFoldedScalar,
        ),
        (
            route!("multiline-scalars", "folded-e"),
            Style::MultilineFoldedScalar,
        ),
    ] {
        let feature = route_to_feature_exact(route, &doc).unwrap().unwrap();
        let style = Style::from_feature(&feature, &doc);
        assert_eq!(style, *expected_style, "for route: {route:?}");
    }
}

#[test]
fn test_reparse_exact_extracted() {
    let original = r#"
foo:
  bar:
    a: b
    c: d
    e: f
"#;

    let doc = yamlpath::Document::new(original).unwrap();
    let feature = route_to_feature_exact(&route!("foo", "bar"), &doc)
        .unwrap()
        .unwrap();

    let content = doc.extract_with_leading_whitespace(&feature);

    let reparsed = serde_yaml::from_str::<serde_yaml::Mapping>(content).unwrap();
    assert_eq!(
        reparsed.get(serde_yaml::Value::String("a".to_string())),
        Some(&serde_yaml::Value::String("b".to_string()))
    );
}

#[test]
fn test_rewrite_fragment_single_line() {
    let original = r#"
foo:
  bar: 'echo "foo: ${{ foo }}"'
"#;

    let document = yamlpath::Document::new(original).unwrap();

    let operations = vec![Patch {
        route: route!("foo", "bar"),
        operation: Op::RewriteFragment {
            from: subfeature::Subfeature::new(0, "${{ foo }}"),
            to: "${FOO}".into(),
        },
    }];

    let result = apply_yaml_patches(&document, &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r#"
    --- PATCH ---

    foo:
      bar: 'echo "foo: ${FOO}"'

    --- END PATCH ---
    "#);
}

#[test]
fn test_rewrite_fragment_multi_line() {
    let original = r#"
foo:
  bar: |
    echo "foo: ${{ foo }}"
    echo "bar: ${{ bar }}"
    echo "foo: ${{ foo }}"
"#;

    let document = yamlpath::Document::new(original).unwrap();

    // Only the first occurrence of `from` should be replaced
    let operations = vec![Patch {
        route: route!("foo", "bar"),
        operation: Op::RewriteFragment {
            from: subfeature::Subfeature::new(0, "${{ foo }}"),
            to: "${FOO}".into(),
        },
    }];

    let result = apply_yaml_patches(&document, &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r#"
    --- PATCH ---

    foo:
      bar: |
        echo "foo: ${FOO}"
        echo "bar: ${{ bar }}"
        echo "foo: ${{ foo }}"

    --- END PATCH ---
    "#);

    // Now test with after set to skip the first occurrence
    let operations = vec![Patch {
        route: route!("foo", "bar"),
        operation: Op::RewriteFragment {
            from: subfeature::Subfeature::new(
                original.find("${{ foo }}").unwrap() + 1,
                "${{ foo }}",
            ),
            to: "${FOO}".into(),
        },
    }];

    let result = apply_yaml_patches(&document, &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r#"
    --- PATCH ---

    foo:
      bar: |
        echo "foo: ${{ foo }}"
        echo "bar: ${{ bar }}"
        echo "foo: ${FOO}"

    --- END PATCH ---
    "#);
}

#[test]
fn test_rewrite_fragment_multi_line_in_list() {
    let original = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "foo: ${{ foo }}"
          echo "bar: ${{ bar }}"
        "#;

    let document = yamlpath::Document::new(original).unwrap();

    let operations = vec![
        Patch {
            route: route!("jobs", "test", "steps", 0, "run"),
            operation: Op::RewriteFragment {
                from: subfeature::Subfeature::new(0, "${{ foo }}"),
                to: "${FOO}".into(),
            },
        },
        Patch {
            route: route!("jobs", "test", "steps", 0, "run"),
            operation: Op::RewriteFragment {
                from: subfeature::Subfeature::new(0, "${{ bar }}"),
                to: "${BAR}".into(),
            },
        },
    ];

    let result = apply_yaml_patches(&document, &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r#"
    --- PATCH ---

    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - run: |
              echo "foo: ${FOO}"
              echo "bar: ${BAR}"
            

    --- END PATCH ---
    "#);
}

/// `Operation::ReplaceComment` should replace the comment
/// at the given route with the new comment, without affecting
/// any YAML values or any other comments.
#[test]
fn test_replace_comment() {
    let original = r#"
foo:
  bar: baz # This is a comment
  abc: def # Another comment
"#;

    let document = yamlpath::Document::new(original).unwrap();

    let operations = vec![Patch {
        route: route!("foo", "bar"),
        operation: Op::ReplaceComment {
            new: "# Updated comment".into(),
        },
    }];

    let result = apply_yaml_patches(&document, &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---

    foo:
      bar: baz # Updated comment
      abc: def # Another comment

    --- END PATCH ---
    ");
}

/// `Operation::ReplaceComment` should fdo nothing if there is no comment
/// at the given route, and should not affect the YAML value.
#[test]
fn test_replace_comment_noop() {
    let original = r#"
foo:
    bar: baz
    abc: def
"#;

    let document = yamlpath::Document::new(original).unwrap();

    let operations = vec![Patch {
        route: route!("foo", "bar"),
        operation: Op::ReplaceComment {
            new: "# This comment does not exist".into(),
        },
    }];

    let result = apply_yaml_patches(&document, &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---

    foo:
        bar: baz
        abc: def

    --- END PATCH ---
    ");
}

/// `Operation::ReplaceComment` should fail if there are multiple comments
/// at the given route, as it's unclear which one to replace.
#[test]
fn test_replace_comment_fails_on_too_many_comments() {
    let original = r#"
foo:
    bar: baz # First comment
    abc: def # Second comment
"#;

    let document = yamlpath::Document::new(original).unwrap();

    let operations = vec![Patch {
        route: route!("foo"),
        operation: Op::ReplaceComment {
            new: "# This won't work".into(),
        },
    }];

    let result = apply_yaml_patches(&document, &operations);

    assert!(result.is_err());
}

#[test]
fn test_replace_empty_block_value() {
    let original = r#"
foo:
  bar:
"#;

    let document = yamlpath::Document::new(original).unwrap();

    let operations = vec![Patch {
        route: route!("foo", "bar"),
        operation: Op::Replace(serde_yaml::Value::String("abc".to_string())),
    }];

    let result = apply_yaml_patches(&document, &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---

    foo:
      bar: abc

    --- END PATCH ---
    ");
}

#[test]
fn test_replace_empty_flow_value() {
    let original = r#"
    foo: { bar: }
    "#;

    let document = yamlpath::Document::new(original).unwrap();

    let patches = vec![Patch {
        route: route!("foo", "bar"),
        operation: Op::Replace(serde_yaml::Value::String("abc".to_string())),
    }];

    let result = apply_yaml_patches(&document, &patches).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---

        foo: { bar: abc }
        

    --- END PATCH ---
    ");
}

#[test]
fn test_replace_empty_flow_value_no_colon() {
    let original = r#"
        foo: { bar }
        "#;

    let document = yamlpath::Document::new(original).unwrap();

    let patches = vec![Patch {
        route: route!("foo", "bar"),
        operation: Op::Replace(serde_yaml::Value::String("abc".to_string())),
    }];

    let result = apply_yaml_patches(&document, &patches).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---

            foo: { bar: abc }
            

    --- END PATCH ---
    ");
}

#[test]
fn test_replace_multiline_string() {
    let original = r#"
foo:
  bar:
    baz: |
      Replace me.
      Replace me too.
"#;

    let document = yamlpath::Document::new(original).unwrap();

    let operations = vec![Patch {
        route: route!("foo", "bar", "baz"),
        operation: Op::Replace("New content.\nMore new content.\n".into()),
    }];

    let result = apply_yaml_patches(&document, &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---

    foo:
      bar:
        baz: |
          New content.
          More new content.

    --- END PATCH ---
    ");
}

#[test]
fn test_yaml_patch_replace_preserves_comments() {
    let original = r#"
# This is a workflow file
name: CI
on: push

permissions: # This configures permissions
  contents: read  # Only read access
  actions: write  # Write access for actions

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"#;

    let document = yamlpath::Document::new(original).unwrap();

    let operations = vec![Patch {
        route: route!("permissions", "contents"),
        operation: Op::Replace(serde_yaml::Value::String("write".to_string())),
    }];

    let result = apply_yaml_patches(&document, &operations).unwrap();

    // Preserves all comments, but changes the value of `contents`
    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---

    # This is a workflow file
    name: CI
    on: push

    permissions: # This configures permissions
      contents: write  # Only read access
      actions: write  # Write access for actions

    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4

    --- END PATCH ---
    ");
}

#[test]
fn test_add_rejects_duplicate_key() {
    let original = r#"
        foo:
            bar: abc
        "#;

    let document = yamlpath::Document::new(original).unwrap();

    let operations = vec![Patch {
        route: route!("foo"),
        operation: Op::Add {
            key: "bar".to_string(),
            value: serde_yaml::Value::String("def".to_string()),
        },
    }];

    let result = apply_yaml_patches(&document, &operations);

    // Should return an error about duplicate key
    assert!(result.is_err());
    let Err(err) = result else {
        panic!("expected an error");
    };
    assert!(err.to_string().contains("key 'bar' already exists at"));
}

#[test]
fn test_add_preserves_formatting() {
    let original = r#"
permissions:
  contents: read
  actions: write
"#;

    let document = yamlpath::Document::new(original).unwrap();

    let operations = vec![Patch {
        route: route!("permissions"),
        operation: Op::Add {
            key: "issues".to_string(),
            value: serde_yaml::Value::String("read".to_string()),
        },
    }];

    let result = apply_yaml_patches(&document, &operations).unwrap();

    // Preserves original content, adds new key while maintaining indentation
    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---

    permissions:
      contents: read
      actions: write
      issues: read

    --- END PATCH ---
    ");
}

#[test]
fn test_add_preserves_flow_mapping_formatting() {
    let original = r#"
foo: { bar: abc }
"#;

    let operations = vec![Patch {
        route: route!("foo"),
        operation: Op::Add {
            key: "baz".to_string(),
            value: serde_yaml::Value::String("qux".to_string()),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---

    foo: { bar: abc, baz: qux }

    --- END PATCH ---
    ");
}

#[test]
fn test_remove_preserves_structure() {
    let original = r#"
permissions:
  contents: read  # Keep this comment
  actions: write  # Remove this line
  issues: read
"#;

    let document = yamlpath::Document::new(original).unwrap();

    let operations = vec![Patch {
        route: route!("permissions", "actions"),
        operation: Op::Remove,
    }];

    let result = apply_yaml_patches(&document, &operations).unwrap();

    // Preserves other content, removes the target line
    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---

    permissions:
      contents: read  # Keep this comment
      issues: read

    --- END PATCH ---
    ");
}

#[test]
fn test_multiple_operations_preserve_comments() {
    let original = r#"
# Main configuration
name: Test Workflow
on:
  push: # Trigger on push
    branches: [main]

permissions:  # Security settings
  contents: read
  actions: read

jobs:
  build: # Main job
    runs-on: ubuntu-latest
"#;

    let operations = vec![
        Patch {
            route: route!("permissions", "contents"),
            operation: Op::Replace(serde_yaml::Value::String("write".to_string())),
        },
        Patch {
            route: route!("permissions"),
            operation: Op::Add {
                key: "issues".to_string(),
                value: serde_yaml::Value::String("write".to_string()),
            },
        },
    ];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    // All comments preserved, all changes applied
    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---

    # Main configuration
    name: Test Workflow
    on:
      push: # Trigger on push
        branches: [main]

    permissions:  # Security settings
      contents: write
      actions: read
      issues: write

    jobs:
      build: # Main job
        runs-on: ubuntu-latest

    --- END PATCH ---
    ");
}

#[test]
fn test_extract_leading_indentation_for_block_item() {
    let doc = r#"
foo:
  - four:

bar:
  -    foo: abc
       bar: abc

two:
  abc:
  def:

tricky-a:
  - -abc:

tricky-b:
  - --abc:

tricky-c:
  - -123:

tricky-d:
  - - abc: # nested block list

tricky-e:
    - - - --abc:

tricky-f:
  -
    foo:

tricky-g:
  -
      foo: bar

nested:
  - foo: bar
    baz:
      - abc: def
"#;

    let doc = yamlpath::Document::new(doc).unwrap();

    for (route, expected) in &[
        (route!("foo", 0), 4),
        (route!("bar", 0), 7),
        (route!("two"), 2),
        (route!("tricky-a"), 4),
        (route!("tricky-b"), 4),
        (route!("tricky-c"), 4),
        (route!("tricky-d"), 6),
        (route!("tricky-e"), 10),
        (route!("tricky-f"), 4),
        (route!("tricky-g"), 4), // BUG, should be 6
        (route!("nested", 0, "baz", 0), 8),
    ] {
        let feature = route_to_feature_exact(route, &doc).unwrap().unwrap();
        assert_eq!(
            extract_leading_indentation_for_block_item(&doc, &feature),
            *expected
        );
    }
}

#[test]
fn test_extract_leading_whitespace() {
    let doc = r#"
two:
  four:
    six:
      also-six: also eight
"#;
    let doc = yamlpath::Document::new(doc).unwrap();

    // Test leading whitespace extraction for various routes
    // The features are extracted in "exact" mode below, so the indentation
    // corresponds to the body rather than the key.
    for (route, expected) in &[
        (route!(), ""),
        (route!("two"), "  "),
        (route!("two", "four"), "    "),
        (route!("two", "four", "six"), "      "),
        (route!("two", "four", "six", "also-six"), "      "),
    ] {
        let feature = route_to_feature_exact(route, &doc).unwrap().unwrap();

        assert_eq!(extract_leading_whitespace(&doc, &feature), *expected);
    }
}

#[test]
fn test_find_content_end() {
    let doc = r#"
foo:
  bar: baz
  abc: def # comment
  # comment

interior-spaces:
  - foo

  - bar
  # hello
  - baz # hello
  # hello
# hello

normal:
  foo: bar
"#;

    let doc = yamlpath::Document::new(doc).unwrap();

    let feature = route_to_feature_exact(&route!("foo"), &doc)
        .unwrap()
        .unwrap();
    let end = find_content_end(&feature, &doc);

    insta::assert_snapshot!(doc.source()[feature.location.byte_span.0..end], @r"
    bar: baz
      abc: def # comment
    ");

    let feature = route_to_feature_exact(&route!("interior-spaces"), &doc)
        .unwrap()
        .unwrap();
    let end = find_content_end(&feature, &doc);
    insta::assert_snapshot!(doc.source()[feature.location.byte_span.0..end], @r"
    - foo

      - bar
      # hello
      - baz # hello
    ");

    let feature = route_to_feature_exact(&route!("normal"), &doc)
        .unwrap()
        .unwrap();
    let end = find_content_end(&feature, &doc);
    insta::assert_snapshot!(doc.source()[feature.location.byte_span.0..end], @"foo: bar");
}

#[test]
fn test_full_demo_workflow() {
    // This test demonstrates the complete workflow for comment-preserving YAML patches
    let original_yaml = r#"
# GitHub Actions Workflow
name: CI
on: push

# Security permissions
permissions: # This section defines permissions
  contents: read  # Only read access to repository contents
  actions: write  # Write access for GitHub Actions
  issues: read    # Read access to issues

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"#;

    let operations = vec![
        Patch {
            route: route!("permissions", "contents"),
            operation: Op::Replace(serde_yaml::Value::String("write".to_string())),
        },
        Patch {
            route: route!("permissions"),
            operation: Op::Add {
                key: "packages".to_string(),
                value: serde_yaml::Value::String("read".to_string()),
            },
        },
    ];

    let result = apply_yaml_patches(
        &yamlpath::Document::new(original_yaml).unwrap(),
        &operations,
    )
    .unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---

    # GitHub Actions Workflow
    name: CI
    on: push

    # Security permissions
    permissions: # This section defines permissions
      contents: write  # Only read access to repository contents
      actions: write  # Write access for GitHub Actions
      issues: read    # Read access to issues
      packages: read

    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4

    --- END PATCH ---
    ")
}

#[test]
fn test_empty_mapping_formatting() {
    let original = r#"name: Test
jobs:
  test:
    runs-on: ubuntu-latest"#;

    // Test empty mapping formatting
    let empty_mapping = serde_yaml::Mapping::new();
    let operations = vec![Patch {
        route: route!("jobs", "test"),
        operation: Op::Add {
            key: "permissions".to_string(),
            value: serde_yaml::Value::Mapping(empty_mapping),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    // Empty mapping should be formatted inline
    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---
    name: Test
    jobs:
      test:
        runs-on: ubuntu-latest
        permissions: {}

    --- END PATCH ---
    ");
}

#[test]
fn test_no_empty_lines_after_insertion() {
    let original = r#"name: Test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "test""#;

    // Test with trailing newline (common in real files)
    let original_with_newline = format!("{original}\n");

    let operations = vec![Patch {
        route: route!("jobs", "test"),
        operation: Op::Add {
            key: "permissions".to_string(),
            value: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        },
    }];

    let result = apply_yaml_patches(
        &yamlpath::Document::new(original_with_newline).unwrap(),
        &operations,
    )
    .unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r#"
    --- PATCH ---
    name: Test
    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - run: echo "test"
        permissions: {}

    --- END PATCH ---
    "#);
}

#[test]
fn test_debug_comments_and_spacing() {
    let original = r#"# GitHub Actions Workflow
name: Test
jobs:
  test:
    runs-on: ubuntu-latest  # Use latest Ubuntu

    # Steps section with comments
    steps:
      # Checkout step
      - name: Checkout repository
        uses: actions/checkout@v4  # Latest checkout action
        # No persist-credentials set

      # Build step
      - name: Build project
        run: echo "Building...""#;

    // Test what yamlpath extracts for the checkout step
    let doc = yamlpath::Document::new(original).unwrap();
    let checkout_query = route!("jobs", "test", "steps", 0);
    let checkout_feature = doc.query_pretty(&checkout_query).unwrap();

    // Test what yamlpath extracts for the test job
    let job_query = route!("jobs", "test");
    let job_feature = doc.query_pretty(&job_query).unwrap();

    // Assert that the checkout step extraction includes the expected content
    let checkout_content = doc.extract(&checkout_feature);
    assert!(checkout_content.contains("name: Checkout repository"));
    assert!(checkout_content.contains("uses: actions/checkout@v4"));

    // Assert that the job extraction includes the expected content
    let job_content = doc.extract(&job_feature);
    assert!(job_content.contains("runs-on: ubuntu-latest"));
    assert!(job_content.contains("steps:"));

    // Assert that byte spans are valid and non-overlapping
    let checkout_end = checkout_feature.location.byte_span.1;
    let job_end = job_feature.location.byte_span.1;

    assert!(checkout_feature.location.byte_span.0 < checkout_end);
    assert!(job_feature.location.byte_span.0 < job_end);
    assert!(checkout_end <= original.len());
    assert!(job_end <= original.len());

    // Assert that the checkout step is contained within the job
    assert!(checkout_feature.location.byte_span.0 >= job_feature.location.byte_span.0);
    assert!(checkout_feature.location.byte_span.1 <= job_feature.location.byte_span.1);
}

#[test]
fn test_step_insertion_with_comments() {
    let original = r#"steps:
  - name: Checkout
    uses: actions/checkout@v4
    # This is a comment after the step

  - name: Build
    run: echo "build""#;

    let operations = vec![Patch {
        route: route!("steps", 0),
        operation: Op::Add {
            key: "with".to_string(),
            value: serde_yaml::Value::Mapping({
                let mut map = serde_yaml::Mapping::new();
                map.insert(
                    serde_yaml::Value::String("persist-credentials".to_string()),
                    serde_yaml::Value::Bool(false),
                );
                map
            }),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    // The with section should be added to the first step correctly, not mixed with comments
    insta::assert_snapshot!(format_patch(result.source()), @r#"
    --- PATCH ---
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          persist-credentials: false
        # This is a comment after the step

      - name: Build
        run: echo "build"

    --- END PATCH ---
    "#);
}

#[test]
fn test_comment_boundary_issue() {
    let original = r#"steps:
  - name: Step1
    uses: actions/checkout@v4
    # Comment after step1

  # Comment before step2
  - name: Step2
    run: echo "test""#;

    // See what yamlpath extracts for step 0
    let doc = yamlpath::Document::new(original).unwrap();
    let step0_query = route!("steps", 0);
    let step0_feature = doc.query_pretty(&step0_query).unwrap();

    // See what yamlpath extracts for step 1
    let step1_query = route!("steps", 1);
    let step1_feature = doc.query_pretty(&step1_query).unwrap();

    // Check for overlaps
    if step0_feature.location.byte_span.1 > step1_feature.location.byte_span.0 {
        // Handle overlap case
    }

    // Assert that the steps have valid boundaries and content
    let content_between =
        &original[step0_feature.location.byte_span.1..step1_feature.location.byte_span.0];

    // Assert that there's content between the steps (whitespace and list marker)
    assert!(
        !content_between.is_empty(),
        "There should be content between steps. Content between: {content_between:?}"
    );

    // The content between is just whitespace and the list marker for step2
    // yamlpath includes comments as part of the respective steps
    assert!(
        content_between.contains("- "),
        "Should contain list marker for step2. Content between: {content_between:?}"
    );

    // Assert that step boundaries don't overlap
    assert!(
        step0_feature.location.byte_span.1 <= step1_feature.location.byte_span.0,
        "Step boundaries should not overlap"
    );

    // Assert that both steps have valid content
    let step0_content = doc.extract(&step0_feature);
    let step1_content = doc.extract(&step1_feature);
    assert!(
        step0_content.contains("name: Step1"),
        "Step0 should contain its name"
    );
    assert!(
        step1_content.contains("name: Step2"),
        "Step1 should contain its name"
    );

    // Assert that step0 includes the comment after it (yamlpath behavior)
    assert!(
        step0_content.contains("uses: actions/checkout@v4"),
        "Step0 should contain the uses directive"
    );

    // Verify that yamlpath includes comments with their respective steps
    assert!(
        step0_content.contains("# Comment after step1")
            || content_between.contains("# Comment after step1"),
        "Comment after step1 should be included somewhere"
    );
}

#[test]
fn test_add_root_level_preserves_formatting() {
    let original = r#"# GitHub Actions Workflow
name: CI
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"#;

    let operations = vec![Patch {
        route: route!(),
        operation: Op::Add {
            key: "permissions".to_string(),
            value: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---
    # GitHub Actions Workflow
    name: CI
    on: push

    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
    permissions: {}

    --- END PATCH ---
    ");
}

#[test]
fn test_add_root_level_path_handling() {
    // Test that root path is handled correctly
    let original = r#"name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest"#;

    let operations = vec![Patch {
        route: route!(),
        operation: Op::Add {
            key: "permissions".to_string(),
            value: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        },
    }];

    let result = apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations);
    assert!(result.is_ok());

    let result = result.unwrap();
    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---
    name: Test
    on: push
    jobs:
      test:
        runs-on: ubuntu-latest
    permissions: {}

    --- END PATCH ---
    ");
}

#[test]
fn test_step_content_end_detection() {
    let original = r#"steps:
  - name: Step1
    uses: actions/checkout@v4
    # Comment after step1

  # Comment before step2
  - name: Step2
    run: echo "test""#;

    let operations = vec![Patch {
        route: route!("steps", 0),
        operation: Op::Add {
            key: "with".to_string(),
            value: serde_yaml::Value::Mapping({
                let mut map = serde_yaml::Mapping::new();
                map.insert(
                    serde_yaml::Value::String("persist-credentials".to_string()),
                    serde_yaml::Value::Bool(false),
                );
                map
            }),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r#"
    --- PATCH ---
    steps:
      - name: Step1
        uses: actions/checkout@v4
        with:
          persist-credentials: false
        # Comment after step1

      # Comment before step2
      - name: Step2
        run: echo "test"

    --- END PATCH ---
    "#);
}

#[test]
fn test_merge_into_new_key() {
    // Test MergeInto when the key doesn't exist yet
    let original = r#"jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Test step
        run: echo "hello""#;

    let operations = vec![Patch {
        route: route!("jobs", "test", "steps", 0),
        operation: Op::MergeInto {
            key: "env".to_string(),
            updates: indexmap::IndexMap::from_iter([(
                "TEST_VAR".to_string(),
                serde_yaml::Value::String("test_value".to_string()),
            )]),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();
    insta::assert_snapshot!(format_patch(result.source()), @r#"
    --- PATCH ---
    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - name: Test step
            run: echo "hello"
            env:
              TEST_VAR: test_value

    --- END PATCH ---
    "#);
}

#[test]
fn test_merge_into_existing_key() {
    // Test MergeInto when the key already exists
    let original = r#"jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Test step
        run: echo "hello"
        env:
          EXISTING_VAR: existing_value"#;

    let operations = vec![Patch {
        route: route!("jobs", "test", "steps", 0),
        operation: Op::MergeInto {
            key: "env".to_string(),
            updates: indexmap::IndexMap::from_iter([(
                "NEW_VAR".to_string(),
                serde_yaml::Value::String("new_value".to_string()),
            )]),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    // Should merge the new mapping with the existing one
    insta::assert_snapshot!(format_patch(result.source()), @r#"
    --- PATCH ---
    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - name: Test step
            run: echo "hello"
            env:
              EXISTING_VAR: existing_value
              NEW_VAR: new_value

    --- END PATCH ---
    "#);
}

#[test]
fn test_merge_into_prevents_duplicate_keys() {
    // Test that MergeInto prevents duplicate env keys
    let original = r#"jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Test step
        run: echo "hello"
        env:
          EXISTING_VAR: existing_value
          ANOTHER_VAR: another_value"#;

    let operations = vec![Patch {
        route: route!("jobs", "test", "steps", 0),
        operation: Op::MergeInto {
            key: "env".to_string(),
            updates: indexmap::IndexMap::from_iter([(
                "NEW_VAR".to_string(),
                serde_yaml::Value::String("new_value".to_string()),
            )]),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    // Should only have one env: key
    assert_eq!(result.source().matches("env:").count(), 1);
    insta::assert_snapshot!(format_patch(result.source()), @r#"
    --- PATCH ---
    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - name: Test step
            run: echo "hello"
            env:
              EXISTING_VAR: existing_value
              ANOTHER_VAR: another_value
              NEW_VAR: new_value

    --- END PATCH ---
    "#);
}

#[test]
fn test_debug_indentation_issue() {
    let original = r#"jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Test step
        run: |
          echo "line 1"
          echo "line 2""#;

    // Test yamlpath extraction
    let doc = yamlpath::Document::new(original).unwrap();
    let step_query = route!("jobs", "build", "steps", 0);
    let step_feature = doc.query_pretty(&step_query).unwrap();

    // Test indentation calculation and content extraction
    let feature_with_ws = doc.extract_with_leading_whitespace(&step_feature);
    let step_content = doc.extract(&step_feature);

    // Assert that the step content contains expected elements
    assert!(step_content.contains("name: Test step"));
    assert!(step_content.contains("run: |"));
    assert!(step_content.contains("echo \"line 1\""));
    assert!(step_content.contains("echo \"line 2\""));

    // Assert that leading whitespace extraction includes the step content
    assert!(
        feature_with_ws.contains("name: Test step"),
        "Step should contain the step name. Actual content: {feature_with_ws:?}"
    );

    // Assert that the content includes the multiline run block
    assert!(
        feature_with_ws.contains("run: |"),
        "Step should contain multiline run block"
    );

    // Check if we're adding to a list item (should be true for step 0)
    let path = "/jobs/build/steps/0";
    let is_list_item = path
        .split('/')
        .next_back()
        .unwrap_or("")
        .parse::<usize>()
        .is_ok();
    assert!(is_list_item, "Path should indicate this is a list item");

    // Test indentation calculation for key-value pairs
    if let Some(first_line) = feature_with_ws.lines().next() {
        if let Some(_colon_pos) = first_line.find(':') {
            let key_indent = &first_line[..first_line.len() - first_line.trim_start().len()];
            let final_indent = format!("{key_indent}  ");

            // Assert that indentation calculation works correctly
            assert!(!final_indent.is_empty(), "Final indent should not be empty");
            assert!(
                final_indent.len() >= 2,
                "Final indent should have at least 2 spaces"
            );
        }
    }

    // Test leading whitespace extraction function
    let leading_ws = extract_leading_whitespace(&doc, &step_feature);
    assert!(
        !leading_ws.is_empty(),
        "Leading whitespace should not be empty for indented step"
    );

    // Test the actual add operation
    let operations = vec![Patch {
        route: route!("jobs", "build", "steps", 0),
        operation: Op::Add {
            key: "shell".to_string(),
            value: serde_yaml::Value::String("bash".to_string()),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r#"
    --- PATCH ---
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - name: Test step
            run: |
              echo "line 1"
              echo "line 2"
            shell: bash

    --- END PATCH ---
    "#);
}

#[test]
fn test_debug_merge_into_env_issue() {
    let original = r#"name: Test
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - name: Multiline step with env
        run: |
          echo "${{ steps.meta.outputs.tags }}" | xargs -I {} echo {}
        env:
          IDENTITY: ${{ secrets.IDENTITY }}
        shell: bash"#;

    // Test yamlpath extraction of the env section
    let doc = yamlpath::Document::new(original).unwrap();
    let env_query = route!("jobs", "test", "steps", 0, "env");

    if let Ok(env_feature) = doc.query_pretty(&env_query) {
        let env_content = doc.extract(&env_feature);

        // Assert that env content is extracted correctly
        assert!(env_content.contains("IDENTITY: ${{ secrets.IDENTITY }}"));

        // Try to parse it as YAML and verify structure
        match serde_yaml::from_str::<serde_yaml::Value>(env_content) {
            Ok(value) => {
                if let serde_yaml::Value::Mapping(outer_mapping) = value {
                    // Assert that the mapping contains expected keys
                    assert!(
                        !outer_mapping.is_empty(),
                        "Outer mapping should not be empty"
                    );

                    // The extracted content includes the "env:" key, so we need to look inside it
                    if let Some(env_value) =
                        outer_mapping.get(serde_yaml::Value::String("env".to_string()))
                    {
                        if let serde_yaml::Value::Mapping(env_mapping) = env_value {
                            // Verify that we can iterate over the env mapping
                            let mut found_identity = false;
                            for (k, _v) in env_mapping {
                                if let serde_yaml::Value::String(key_str) = k {
                                    if key_str == "IDENTITY" {
                                        found_identity = true;
                                    }
                                }
                            }
                            assert!(found_identity, "Should find IDENTITY key in env mapping");
                        } else {
                            panic!("Env value should be a mapping");
                        }
                    } else {
                        panic!("Should find env key in outer mapping");
                    }
                } else {
                    panic!(
                        "Env content should parse as a mapping. Actual content: {env_content:?}"
                    );
                }
            }
            Err(e) => {
                panic!(
                    "Env content should parse as valid YAML: {e}. Actual content: {env_content:?}"
                );
            }
        }
    } else {
        panic!("Should be able to query env section");
    }

    // Test the MergeInto operation
    let new_env = indexmap::IndexMap::from_iter([(
        "STEPS_META_OUTPUTS_TAGS".to_string(),
        serde_yaml::Value::String("${{ steps.meta.outputs.tags }}".to_string()),
    )]);

    let operations = vec![Patch {
        route: route!("jobs", "test", "steps", 0),
        operation: Op::MergeInto {
            key: "env".to_string(),
            updates: new_env,
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r#"
    --- PATCH ---
    name: Test
    on: push
    permissions: {}
    jobs:
      test:
        runs-on: ubuntu-latest
        permissions: {}
        steps:
          - name: Multiline step with env
            run: |
              echo "${{ steps.meta.outputs.tags }}" | xargs -I {} echo {}
            env:
              IDENTITY: ${{ secrets.IDENTITY }}
              STEPS_META_OUTPUTS_TAGS: ${{ steps.meta.outputs.tags }}
            shell: bash

    --- END PATCH ---
    "#);
}

#[test]
fn test_merge_into_complex_env_mapping() {
    // Test merging into an existing env section with multiple variables
    let original = r#"jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Test step
        run: echo "hello"
        env:
          IDENTITY: ${{ secrets.IDENTITY }}
          OIDC_ISSUER_URL: ${{ secrets.OIDC_ISSUER_URL }}
        shell: bash"#;

    let new_env = indexmap::IndexMap::from_iter([(
        "STEPS_META_OUTPUTS_TAGS".to_string(),
        serde_yaml::Value::String("${{ steps.meta.outputs.tags }}".to_string()),
    )]);

    let operations = vec![Patch {
        route: route!("jobs", "test", "steps", 0),
        operation: Op::MergeInto {
            key: "env".to_string(),
            updates: new_env,
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    // Should only have one env: key
    assert_eq!(result.source().matches("env:").count(), 1);
    insta::assert_snapshot!(format_patch(result.source()), @r#"
    --- PATCH ---
    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - name: Test step
            run: echo "hello"
            env:
              IDENTITY: ${{ secrets.IDENTITY }}
              OIDC_ISSUER_URL: ${{ secrets.OIDC_ISSUER_URL }}
              STEPS_META_OUTPUTS_TAGS: ${{ steps.meta.outputs.tags }}
            shell: bash

    --- END PATCH ---
    "#);
}

#[test]
fn test_merge_into_reuses_existing_key_no_duplicates() {
    // Test that MergeInto reuses an existing key instead of creating duplicates
    let original = r#"jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Test step
        run: echo "hello"
        env:
          EXISTING_VAR: existing_value
          ANOTHER_VAR: another_value"#;

    let operations = vec![Patch {
        route: route!("jobs", "test", "steps", 0),
        operation: Op::MergeInto {
            key: "env".to_string(),
            updates: indexmap::IndexMap::from_iter([(
                "NEW_VAR".to_string(),
                serde_yaml::Value::String("new_value".to_string()),
            )]),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r#"
    --- PATCH ---
    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - name: Test step
            run: echo "hello"
            env:
              EXISTING_VAR: existing_value
              ANOTHER_VAR: another_value
              NEW_VAR: new_value

    --- END PATCH ---
    "#);
}

#[test]
fn test_merge_into_with_mapping_merge_behavior() {
    // Test what true merging behavior would look like for mappings
    // This test documents what merging behavior could be if implemented
    let original = r#"jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Test step
        run: echo "hello"
        env:
          EXISTING_VAR: existing_value
          KEEP_THIS: keep_value"#;

    // Apply multiple MergeInto operations to see how they interact
    let operations = vec![
        Patch {
            route: route!("jobs", "test", "steps", 0),
            operation: Op::MergeInto {
                key: "env".to_string(),
                updates: indexmap::IndexMap::from_iter([(
                    "NEW_VAR_1".to_string(),
                    serde_yaml::Value::String("new_value_1".to_string()),
                )]),
            },
        },
        Patch {
            route: route!("jobs", "test", "steps", 0),
            operation: Op::MergeInto {
                key: "env".to_string(),
                updates: indexmap::IndexMap::from_iter([(
                    "NEW_VAR_2".to_string(),
                    serde_yaml::Value::String("new_value_2".to_string()),
                )]),
            },
        },
    ];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r#"
    --- PATCH ---
    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - name: Test step
            run: echo "hello"
            env:
              EXISTING_VAR: existing_value
              KEEP_THIS: keep_value
              NEW_VAR_1: new_value_1
              NEW_VAR_2: new_value_2

    --- END PATCH ---
    "#);
}

#[test]
fn test_mixed_flow_block_styles_github_workflow() {
    // GitHub Action workflow with mixed flow and block styles similar to the user's example
    let original = r#"
name: CI
on:
  push:
    branches: [main]   # Flow sequence inside block mapping
  pull_request: { branches: [main, develop] }  # Flow mapping with flow sequence

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - { os: ubuntu-latest, node: 18 }  # Flow mapping in block list
          - os: macos-latest                 # Block mapping in block list
            node: 20
            extra_flags: ["--verbose"]       # Flow sequence in block mapping
          - { os: windows-latest, node: 16, extra_flags: ["--silent", "--prod"] }  # Mixed flow
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with: { fetch-depth: 0 }           # Flow mapping in block context
      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node }}
          cache: npm
"#;

    // Test adding to the flow mapping in pull_request trigger
    let operations = vec![Patch {
        route: route!("on", "pull_request"),
        operation: Op::Add {
            key: "types".to_string(),
            value: serde_yaml::Value::Sequence(vec![
                serde_yaml::Value::String("opened".to_string()),
                serde_yaml::Value::String("synchronize".to_string()),
            ]),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r#"
    --- PATCH ---

    name: CI
    on:
      push:
        branches: [main]   # Flow sequence inside block mapping
      pull_request: { branches: [main, develop], types: [opened, synchronize] }  # Flow mapping with flow sequence

    jobs:
      test:
        runs-on: ubuntu-latest
        strategy:
          matrix:
            include:
              - { os: ubuntu-latest, node: 18 }  # Flow mapping in block list
              - os: macos-latest                 # Block mapping in block list
                node: 20
                extra_flags: ["--verbose"]       # Flow sequence in block mapping
              - { os: windows-latest, node: 16, extra_flags: ["--silent", "--prod"] }  # Mixed flow
        steps:
          - name: Checkout
            uses: actions/checkout@v4
            with: { fetch-depth: 0 }           # Flow mapping in block context
          - name: Setup Node
            uses: actions/setup-node@v4
            with:
              node-version: ${{ matrix.node }}
              cache: npm

    --- END PATCH ---
    "#);
}

#[test]
fn test_replace_value_in_flow_mapping_within_block_context() {
    let original = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Test step
        with: { timeout: 300 }
"#;

    let operations = vec![Patch {
        route: route!("jobs", "test", "steps", 0, "with", "timeout"),
        operation: Op::Replace(serde_yaml::Value::Number(serde_yaml::Number::from(600))),
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---

    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - name: Test step
            with: { timeout: 600 }

    --- END PATCH ---
    ");
}

#[test]
fn test_add_nested_mapping_with_comments() {
    let original = r#"
foo:
  bar:
    baz: abc # comment
    # another comment
# some nonsense here
"#;

    let operations = vec![Patch {
        route: route!("foo", "bar"),
        operation: Op::Add {
            key: "qux".to_string(),
            value: serde_yaml::Value::String("xyz".to_string()),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---

    foo:
      bar:
        baz: abc # comment
        qux: xyz
        # another comment
    # some nonsense here

    --- END PATCH ---
    ");
}

#[test]
fn test_add_to_block_mapping_in_block_list() {
    let original = r#"
matrix:
  include:
    - os: ubuntu-latest
      node: 18
    - os: macos-latest
      node: 20
"#;

    let operations = vec![Patch {
        route: route!("matrix", "include", 0),
        operation: Op::Add {
            key: "arch".to_string(),
            value: serde_yaml::Value::String("x64".to_string()),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---

    matrix:
      include:
        - os: ubuntu-latest
          node: 18
          arch: x64
        - os: macos-latest
          node: 20

    --- END PATCH ---
    ");
}

#[test]
fn test_add_to_block_mapping_in_block_list_funky_indentation() {
    let original = r#"
matrix:
   include:
      -   os: ubuntu-latest
          node: 18
      -   os: macos-latest
          node: 20
"#;

    let operations = vec![Patch {
        route: route!("matrix", "include", 0),
        operation: Op::Add {
            key: "arch".to_string(),
            value: serde_yaml::Value::String("x64".to_string()),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---

    matrix:
       include:
          -   os: ubuntu-latest
              node: 18
              arch: x64
          -   os: macos-latest
              node: 20

    --- END PATCH ---
    ");
}

#[test]
fn test_add_to_flow_mapping_nested_in_block_list() {
    let original = r#"
strategy:
  matrix:
    include:
      - { os: ubuntu-latest, node: 18 }
      - { os: macos-latest, node: 20 }
"#;

    let operations = vec![Patch {
        route: route!("strategy", "matrix", "include", 0),
        operation: Op::Add {
            key: "arch".to_string(),
            value: serde_yaml::Value::String("x64".to_string()),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---

    strategy:
      matrix:
        include:
          - { os: ubuntu-latest, node: 18, arch: x64 }
          - { os: macos-latest, node: 20 }

    --- END PATCH ---
    ");
}

#[test]
fn test_add_to_flow_mapping_trailing_comma() {
    let original = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    env: { NODE_ENV: "production", DEBUG: "true", }
"#;

    let operations = vec![Patch {
        route: route!("jobs", "test", "env"),
        operation: Op::Add {
            key: "LOG_LEVEL".to_string(),
            value: serde_yaml::Value::String("info".to_string()),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---

    jobs:
      test:
        runs-on: ubuntu-latest
        env: { NODE_ENV: production, DEBUG: true, LOG_LEVEL: info }

    --- END PATCH ---
    ");
}

#[test]
fn test_add_to_flow_mapping_trailing_comment() {
    let original = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    env: { NODE_ENV: "production", DEBUG: "true" } # trailing comment
"#;

    let operations = vec![Patch {
        route: route!("jobs", "test", "env"),
        operation: Op::Add {
            key: "LOG_LEVEL".to_string(),
            value: serde_yaml::Value::String("info".to_string()),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    // The trailing comment should be preserved after the mapping
    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---

    jobs:
      test:
        runs-on: ubuntu-latest
        env: { NODE_ENV: production, DEBUG: true, LOG_LEVEL: info } # trailing comment

    --- END PATCH ---
    ");
}

#[test]
#[ignore = "known issue"]
fn test_add_to_multiline_flow_mapping() {
    let original = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    env: {
      NODE_ENV: "production",
      DEBUG: "true"
    }
"#;

    let operations = vec![Patch {
        route: route!("jobs", "test", "env"),
        operation: Op::Add {
            key: "LOG_LEVEL".to_string(),
            value: serde_yaml::Value::String("info".to_string()),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r#"
        jobs:
          test:
            runs-on: ubuntu-latest
            env: {
              NODE_ENV: "production",
              DEBUG: "true",
              LOG_LEVEL: "info"
            }
        "#);
}

#[test]
#[ignore = "known issue"]
fn test_add_to_multiline_flow_mapping_funky() {
    let original = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    env: {
      NODE_ENV: "production", DEBUG: "true",
      BLAH: xyz
    }
"#;

    let operations = vec![Patch {
        route: route!("jobs", "test", "env"),
        operation: Op::Add {
            key: "LOG_LEVEL".to_string(),
            value: serde_yaml::Value::String("info".to_string()),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r#"
        jobs:
          test:
            runs-on: ubuntu-latest
            env: {
              NODE_ENV: "production",
              DEBUG: "true",
              BLAH: xyz,
              LOG_LEVEL: "info"
            }
        "#);
}

#[test]
fn test_add_complex_mixed_styles_permissions() {
    let original = r#"
permissions:
  contents: read
  actions: { read: true, write: false }  # Flow mapping in block context
  packages: write
"#;

    let operations = vec![Patch {
        route: route!("permissions", "actions"),
        operation: Op::Add {
            key: "delete".to_string(),
            value: serde_yaml::Value::Bool(true),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---

    permissions:
      contents: read
      actions: { read: true, write: false, delete: true }  # Flow mapping in block context
      packages: write

    --- END PATCH ---
    ");
}

#[test]
fn test_add_preserve_flow_sequence_in_block_mapping() {
    let original = r#"
on:
  push:
    branches: [main, develop]
  schedule:
    - cron: "0 0 * * *"
"#;

    let operations = vec![Patch {
        route: route!("on", "push"),
        operation: Op::Add {
            key: "tags".to_string(),
            value: serde_yaml::Value::Sequence(vec![serde_yaml::Value::String("v*".to_string())]),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r#"
    --- PATCH ---

    on:
      push:
        branches: [main, develop]
        tags: ["v*"]
      schedule:
        - cron: "0 0 * * *"

    --- END PATCH ---
    "#);
}

#[test]
fn test_add_empty_flow_mapping_expansion() {
    let original = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    env: {}
    steps:
      - run: echo "test"
"#;

    let operations = vec![Patch {
        route: route!("jobs", "test", "env"),
        operation: Op::Add {
            key: "NODE_ENV".to_string(),
            value: serde_yaml::Value::String("test".to_string()),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r#"
    --- PATCH ---

    jobs:
      test:
        runs-on: ubuntu-latest
        env: { NODE_ENV: test }
        steps:
          - run: echo "test"

    --- END PATCH ---
    "#);
}

#[test]
fn test_merge_into_preserves_comments_in_env_block() {
    // Test that comments are preserved when merging into an env block with existing comments
    let original = r#"jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Needs a redirection
        run: ${{ inputs.script }}
        env:
          # An existing comment about this wacky env-var
          WACKY: "It's just a wacky world""#;

    let new_env = indexmap::IndexMap::from_iter([(
        "INPUTS_SCRIPT".to_string(),
        serde_yaml::Value::String("${{ inputs.script }}".to_string()),
    )]);

    let operations = vec![Patch {
        route: route!("jobs", "test", "steps", 0),
        operation: Op::MergeInto {
            key: "env".to_string(),
            updates: new_env,
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    // Check that the comment is preserved
    assert!(
        result
            .source()
            .contains("# An existing comment about this wacky env-var")
    );

    insta::assert_snapshot!(format_patch(result.source()), @r#"
    --- PATCH ---
    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - name: Needs a redirection
            run: ${{ inputs.script }}
            env:
              # An existing comment about this wacky env-var
              WACKY: "It's just a wacky world"
              INPUTS_SCRIPT: ${{ inputs.script }}

    --- END PATCH ---
    "#);
}

#[test]
fn test_merge_into_flow_mapping() {
    let original = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Step1
        uses: actions/checkout@v4
        with: { persist-credentials: true }  # Flow mapping in block context
"#;

    let operations = vec![Patch {
        route: route!("jobs", "test", "steps", 0),
        operation: Op::MergeInto {
            key: "with".to_string(),
            updates: indexmap::IndexMap::from_iter([
                (
                    "persist-credentials".to_string(),
                    serde_yaml::Value::Bool(false),
                ),
                (
                    "another-key".to_string(),
                    serde_yaml::Value::String("some-value".to_string()),
                ),
            ]),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---

    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - name: Step1
            uses: actions/checkout@v4
            with: { persist-credentials: false, another-key: some-value }  # Flow mapping in block context

    --- END PATCH ---
    ");
}

#[test]
#[ignore = "known issue with empty body handling"]
fn test_merge_into_key_missing_body() {
    let original = r#"
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Step1
        uses: actions/checkout@v4
        # empty with: block
        with:
"#;

    let operations = vec![Patch {
        route: route!("jobs", "test", "steps", 0),
        operation: Op::MergeInto {
            key: "with".to_string(),
            updates: indexmap::IndexMap::from_iter([(
                "persist-credentials".to_string(),
                serde_yaml::Value::Bool(false),
            )]),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r#"
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - name: Step1
                uses: actions/checkout@v4
                with:
                  persist-credentials: false
        "#);
}

#[test]
fn test_preserve_trailing_newline_when_adding_at_end() {
    // Test case for dependabot cooldown: adding cooldown config at the end of
    // an ecosystem stanza should preserve the trailing newline
    let original = r#"version: 2

updates:
  - package-ecosystem: pip
    directory: /
    schedule:
      interval: daily
    labels:
      - A-deps
"#;

    let operations = vec![Patch {
        route: route!("updates", 0),
        operation: Op::Add {
            key: "cooldown".to_string(),
            value: serde_yaml::Value::Mapping({
                let mut map = serde_yaml::Mapping::new();
                map.insert(
                    serde_yaml::Value::String("default-days".to_string()),
                    serde_yaml::Value::Number(7.into()),
                );
                map
            }),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---
    version: 2

    updates:
      - package-ecosystem: pip
        directory: /
        schedule:
          interval: daily
        labels:
          - A-deps
        cooldown:
          default-days: 7

    --- END PATCH ---
    ");
}

#[test]
fn test_preserve_trailing_newline_replace_at_end() {
    // Test Replace operation preserves trailing newline when replacing value at end of document
    let original = r#"name: Test
version: 1.0
"#;

    let operations = vec![Patch {
        route: route!("version"),
        operation: Op::Replace(serde_yaml::Value::String("2.0".to_string())),
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---
    name: Test
    version: '2.0'

    --- END PATCH ---
    ");
}

#[test]
fn test_preserve_trailing_newline_replace_comment_at_end() {
    // Test ReplaceComment operation preserves trailing newline when replacing comment at end
    let original = r#"name: Test
version: 1.0  # old version
"#;

    let operations = vec![Patch {
        route: route!("version"),
        operation: Op::ReplaceComment {
            new: Cow::Owned("# updated version".to_string()),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---
    name: Test
    version: 1.0  # updated version

    --- END PATCH ---
    ");
}

#[test]
fn test_preserve_trailing_newline_rewrite_fragment_at_end() {
    // Test RewriteFragment operation preserves trailing newline when rewriting at end of document
    let original = r#"run: |
  echo "Hello ${{ env.NAME }}"
"#;

    let operations = vec![Patch {
        route: route!("run"),
        operation: Op::RewriteFragment {
            from: subfeature::Subfeature::new(0, "${{ env.NAME }}"),
            to: Cow::Borrowed("${NAME}"),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r#"
    --- PATCH ---
    run: |
      echo "Hello ${NAME}"

    --- END PATCH ---
    "#);
}

#[test]
fn test_preserve_trailing_newline_add_simple_at_end() {
    // Test Add operation preserves trailing newline when adding to mapping at end of document
    let original = r#"name: Test
key: value
"#;

    let operations = vec![Patch {
        route: route!(),
        operation: Op::Add {
            key: "newkey".to_string(),
            value: serde_yaml::Value::String("newvalue".to_string()),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---
    name: Test
    key: value
    newkey: newvalue

    --- END PATCH ---
    ");
}

#[test]
fn test_preserve_trailing_newline_replace_nested_at_end() {
    // Test Replace operation preserves trailing newline when replacing nested value at end
    let original = r#"jobs:
  test:
    runs-on: ubuntu-latest
    env:
      VAR: old
"#;

    let operations = vec![Patch {
        route: route!("jobs", "test", "env", "VAR"),
        operation: Op::Replace(serde_yaml::Value::String("new".to_string())),
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---
    jobs:
      test:
        runs-on: ubuntu-latest
        env:
          VAR: new

    --- END PATCH ---
    ");
}

#[test]
fn test_preserve_trailing_newline_add_to_nested_mapping_at_end() {
    // Test Add operation preserves trailing newline when adding to nested mapping at end
    let original = r#"jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "test"
"#;

    let operations = vec![Patch {
        route: route!("jobs", "test", "steps", 0),
        operation: Op::Add {
            key: "name".to_string(),
            value: serde_yaml::Value::String("Test step".to_string()),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r#"
    --- PATCH ---
    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - run: echo "test"
            name: Test step

    --- END PATCH ---
    "#);
}

#[test]
fn test_preserve_trailing_newline_replace_multiline_at_end() {
    // Test Replace operation preserves trailing newline when replacing multiline value at end
    let original = r#"description: |
  Line 1
  Line 2
"#;

    let operations = vec![Patch {
        route: route!("description"),
        operation: Op::Replace(serde_yaml::Value::String("New description".to_string())),
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---
    description: New description

    --- END PATCH ---
    ");

    // NOTE: Ensure that the trailing newline is preserved after replacement;
    // insta's snapshots are trimmed, so the above isn't a strong guarantee.
    assert!(result.source().ends_with('\n'));
}

#[test]
fn test_preserve_trailing_newline_no_newline_original() {
    // Test that operations don't add trailing newline if original document doesn't have one
    let original = r#"name: Test
key: value"#;

    let operations = vec![Patch {
        route: route!("key"),
        operation: Op::Replace(serde_yaml::Value::String("newvalue".to_string())),
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(format_patch(result.source()), @r"
    --- PATCH ---
    name: Test
    key: newvalue

    --- END PATCH ---
    ");
}

#[test]
fn test_append_simple_scalar_to_sequence() {
    let original = r#"
items:
  - first
  - second
"#;

    let operations = vec![Patch {
        route: route!("items"),
        operation: Op::Append {
            value: serde_yaml::Value::String("third".to_string()),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(result.source(), @r"

    items:
      - first
      - second
      - third
    ");
}

#[test]
fn test_append_mapping_to_sequence() {
    let original = r#"
databases:
  - name: primary
    host: db1.example.com
    port: 5432
    max_connections: 100
    ssl: true
    readonly: false
"#;

    let mut new_database = serde_yaml::Mapping::new();
    new_database.insert(
        serde_yaml::Value::String("name".to_string()),
        serde_yaml::Value::String("analytics".to_string()),
    );
    new_database.insert(
        serde_yaml::Value::String("host".to_string()),
        serde_yaml::Value::String("db2.example.com".to_string()),
    );
    new_database.insert(
        serde_yaml::Value::String("port".to_string()),
        serde_yaml::Value::Number(5433.into()),
    );
    new_database.insert(
        serde_yaml::Value::String("readonly".to_string()),
        serde_yaml::Value::Bool(true),
    );

    let operations = vec![Patch {
        route: route!("databases"),
        operation: Op::Append {
            value: serde_yaml::Value::Mapping(new_database),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(result.source(), @r"

    databases:
      - name: primary
        host: db1.example.com
        port: 5432
        max_connections: 100
        ssl: true
        readonly: false
      - name: analytics
        host: db2.example.com
        port: 5433
        readonly: true
    ");
}

#[test]
fn test_append_preserves_indentation() {
    let original = r#"
jobs:
  test:
    steps:
      - name: First step
        run: echo "first"
      - name: Second step
        run: echo "second"
"#;

    let mut new_step = serde_yaml::Mapping::new();
    new_step.insert(
        serde_yaml::Value::String("name".to_string()),
        serde_yaml::Value::String("Third step".to_string()),
    );
    new_step.insert(
        serde_yaml::Value::String("run".to_string()),
        serde_yaml::Value::String("echo \"third\"".to_string()),
    );

    let operations = vec![Patch {
        route: route!("jobs", "test", "steps"),
        operation: Op::Append {
            value: serde_yaml::Value::Mapping(new_step),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(result.source(), @r#"

    jobs:
      test:
        steps:
          - name: First step
            run: echo "first"
          - name: Second step
            run: echo "second"
          - name: Third step
            run: echo "third"
    "#);
}

#[test]
fn test_append_preserves_comments() {
    let original = r#"
servers:
  # Production server
  - name: prod
    host: prod.example.com
    port: 443
  # Staging server
  - name: staging
    host: staging.example.com  # internal only
    port: 8443
"#;

    let mut new_server = serde_yaml::Mapping::new();
    new_server.insert(
        serde_yaml::Value::String("name".to_string()),
        serde_yaml::Value::String("dev".to_string()),
    );
    new_server.insert(
        serde_yaml::Value::String("host".to_string()),
        serde_yaml::Value::String("localhost".to_string()),
    );
    new_server.insert(
        serde_yaml::Value::String("port".to_string()),
        serde_yaml::Value::Number(8080.into()),
    );

    let operations = vec![Patch {
        route: route!("servers"),
        operation: Op::Append {
            value: serde_yaml::Value::Mapping(new_server),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    assert!(result.source().contains("# Production server"));
    assert!(result.source().contains("# Staging server"));
    assert!(result.source().contains("# internal only"));

    insta::assert_snapshot!(result.source(), @r"

    servers:
      # Production server
      - name: prod
        host: prod.example.com
        port: 443
      # Staging server
      - name: staging
        host: staging.example.com  # internal only
        port: 8443
      - name: dev
        host: localhost
        port: 8080
    ");
}

#[test]
fn test_append_number_to_sequence() {
    let original = r#"
ports:
  - 8080
  - 8081
"#;

    let operations = vec![Patch {
        route: route!("ports"),
        operation: Op::Append {
            value: serde_yaml::Value::Number(8082.into()),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(result.source(), @r"

    ports:
      - 8080
      - 8081
      - 8082
    ");
}

#[test]
fn test_append_empty_mapping() {
    let original = r#"
configs:
  - name: config1
    value: 123
"#;

    let operations = vec![Patch {
        route: route!("configs"),
        operation: Op::Append {
            value: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(result.source(), @r"

    configs:
      - name: config1
        value: 123
      - {}
    ");
}

#[test]
fn test_append_nested_mapping() {
    let original = r#"
services:
  - name: api
    port: 8080
"#;

    let mut new_service = serde_yaml::Mapping::new();
    new_service.insert(
        serde_yaml::Value::String("name".to_string()),
        serde_yaml::Value::String("worker".to_string()),
    );
    new_service.insert(
        serde_yaml::Value::String("port".to_string()),
        serde_yaml::Value::Number(9090.into()),
    );

    let mut config = serde_yaml::Mapping::new();
    config.insert(
        serde_yaml::Value::String("replicas".to_string()),
        serde_yaml::Value::Number(3.into()),
    );

    new_service.insert(
        serde_yaml::Value::String("config".to_string()),
        serde_yaml::Value::Mapping(config),
    );

    let operations = vec![Patch {
        route: route!("services"),
        operation: Op::Append {
            value: serde_yaml::Value::Mapping(new_service),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(result.source(), @r"

    services:
      - name: api
        port: 8080
      - name: worker
        port: 9090
        config:
          replicas: 3
    ");
}

#[test]
fn test_append_fails_on_non_sequence() {
    let original = r#"
config:
  name: test
  value: 123
"#;

    let operations = vec![Patch {
        route: route!("config"),
        operation: Op::Append {
            value: serde_yaml::Value::String("item".to_string()),
        },
    }];

    let result = apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations);

    match result {
        Ok(_) => panic!("Expected an error but got Ok"),
        Err(err) => {
            assert!(
                err.to_string()
                    .contains("append operation is only permitted against sequence routes")
            );
        }
    }
}

#[test]
fn test_append_multiple_items() {
    let original = r#"
tasks:
  - task1
"#;

    let operations = vec![
        Patch {
            route: route!("tasks"),
            operation: Op::Append {
                value: serde_yaml::Value::String("task2".to_string()),
            },
        },
        Patch {
            route: route!("tasks"),
            operation: Op::Append {
                value: serde_yaml::Value::String("task3".to_string()),
            },
        },
    ];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(result.source(), @r"

    tasks:
      - task1
      - task2
      - task3
    ");
}

#[test]
fn test_append_real_world_github_workflow() {
    let original = r#"
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Run tests
        run: npm test
"#;

    let mut new_step = serde_yaml::Mapping::new();
    new_step.insert(
        serde_yaml::Value::String("name".to_string()),
        serde_yaml::Value::String("Upload coverage".to_string()),
    );
    new_step.insert(
        serde_yaml::Value::String("uses".to_string()),
        serde_yaml::Value::String("codecov/codecov-action@v3".to_string()),
    );

    let operations = vec![Patch {
        route: route!("jobs", "test", "steps"),
        operation: Op::Append {
            value: serde_yaml::Value::Mapping(new_step),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(result.source(), @r"

    name: CI
    on: push
    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - name: Checkout
            uses: actions/checkout@v4
          - name: Run tests
            run: npm test
          - name: Upload coverage
            uses: codecov/codecov-action@v3
    ");
}

#[test]
fn test_append_nested_sequence() {
    let original = r#"
foo:
  - abc
"#;

    let mut nested_sequence = serde_yaml::Sequence::new();
    nested_sequence.push(serde_yaml::Value::String("def".to_string()));
    nested_sequence.push(serde_yaml::Value::String("ghi".to_string()));

    let operations = vec![Patch {
        route: route!("foo"),
        operation: Op::Append {
            value: serde_yaml::Value::Sequence(nested_sequence),
        },
    }];

    let result =
        apply_yaml_patches(&yamlpath::Document::new(original).unwrap(), &operations).unwrap();

    insta::assert_snapshot!(result.source(), @r"

    foo:
      - abc
      - - def
        - ghi
    ");
}
