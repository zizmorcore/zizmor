use astral_yaml_serde::Value;
use subfeature::Subfeature;
use yamlpatch::{Error, Op, Patch, apply_yaml_patches};
use yamlpath::{Document, Route, route};

fn patch(source: &str, route: Route<'_>, operation: Op<'_>) -> Result<String, Error> {
    let doc = Document::new(source).expect("valid YAML fixture");
    apply_yaml_patches(&doc, &[Patch { route, operation }])
}

#[test]
fn replace_writes_a_boolean_looking_string_as_a_string() -> Result<(), Error> {
    let fixed = patch(
        "env:\n  FLAG: true # toggle\n  OTHER: false",
        route!("env", "FLAG"),
        Op::Replace(Value::String("false".into())),
    )?;
    insta::assert_snapshot!(fixed, @r#"
    env:
      FLAG: "false" # toggle
      OTHER: false
    "#);
    Ok(())
}

#[test]
fn rewrite_matches_the_decoded_string_after_the_offset() -> Result<(), Error> {
    let fixed = patch(
        r#"run: "é\nfirst\né\nfirst" # script"#,
        route!("run"),
        Op::RewriteString {
            from: Subfeature::new("é\nfirst\n".len(), "é\nfirst"),
            to: "updated".into(),
        },
    )?;
    insta::assert_snapshot!(fixed, @r#"run: "é\nfirst\nupdated" # script"#);
    Ok(())
}

#[test]
fn added_mappings_inherit_block_or_flow_style() -> Result<(), Error> {
    let add = Op::Add {
        key: "strategy".into(),
        value: astral_yaml_serde::from_str("{matrix: {version: [1, 2]}}")?,
    };

    let block = patch("runs-on: linux", route!(), add.clone())?;
    insta::assert_snapshot!(block, @r#"
    runs-on: linux
    strategy:
      "matrix":
        "version": [1, 2]
    "#);

    let flow = patch("{runs-on: linux}", route!(), add)?;
    insta::assert_snapshot!(flow, @r#"{runs-on: linux, strategy: {"matrix": {"version": [1, 2]}}}"#);
    Ok(())
}

#[test]
fn duplicate_add_fails_the_batch_and_allows_a_retry() -> Result<(), Error> {
    let doc = Document::new("env: {}").expect("valid YAML fixture");
    let add = Patch {
        route: route!("env"),
        operation: Op::Add {
            key: "007".into(),
            value: Value::Bool(true),
        },
    };

    let err = apply_yaml_patches(&doc, &[add.clone(), add.clone()])
        .expect_err("adding the same key twice must fail");
    assert_eq!(err.to_string(), "key '007' already exists");

    let retried = apply_yaml_patches(&doc, &[add])?;
    insta::assert_snapshot!(retried, @r#"env: {"007": true}"#);
    Ok(())
}

#[test]
fn set_field_uses_the_enclosing_or_existing_mapping_style() -> Result<(), Error> {
    let set = Op::SetField {
        mapping: "with",
        key: "persist-credentials".into(),
        value: Value::Bool(false),
    };

    let null = patch(
        "uses: actions/checkout@v4\nwith: # inputs",
        route!(),
        set.clone(),
    )?;
    insta::assert_snapshot!(null, @"
    uses: actions/checkout@v4
    with: # inputs
      persist-credentials: false
    ");

    let missing = patch("{uses: actions/checkout@v4}", route!(), set.clone())?;
    insta::assert_snapshot!(missing, @"{uses: actions/checkout@v4, with: {persist-credentials: false}}");

    let empty = patch("uses: actions/checkout@v4\nwith: {}", route!(), set)?;
    insta::assert_snapshot!(empty, @"
    uses: actions/checkout@v4
    with: {persist-credentials: false}
    ");
    Ok(())
}

#[test]
fn set_field_preserves_an_explicit_flow_value() -> Result<(), Error> {
    let set = Op::SetField {
        mapping: "strategy",
        key: "matrix".into(),
        value: astral_yaml_serde::from_str("{version: [1, 2]}")?,
    };

    let added = patch("strategy:\n  fail-fast: false", route!(), set.clone())?;
    insta::assert_snapshot!(added, @r#"
    strategy:
      fail-fast: false
      matrix:
        "version": [1, 2]
    "#);

    let replaced = patch("strategy:\n  matrix: {version: [0]}", route!(), set)?;
    insta::assert_snapshot!(replaced, @r#"
    strategy:
      matrix: {"version": [1, 2]}
    "#);
    Ok(())
}

#[test]
fn set_field_reuses_the_mapping_created_by_an_earlier_patch() -> Result<(), Error> {
    let doc = Document::new("steps:\n  - run: build # keep").expect("valid YAML fixture");
    let patches =
        [("MODE", "test"), ("CI", "true"), ("MODE", "release")].map(|(key, value)| Patch {
            route: route!("steps", 0),
            operation: Op::SetField {
                mapping: "env",
                key: key.into(),
                value: Value::String(value.into()),
            },
        });

    let fixed = apply_yaml_patches(&doc, &patches)?;
    insta::assert_snapshot!(fixed, @r#"
    steps:
      - run: build # keep
        env:
          MODE: "release"
          CI: "true"
    "#);
    Ok(())
}

#[test]
fn set_field_rejects_non_mapping_values() {
    let set = Op::SetField {
        mapping: "with",
        key: "flag".into(),
        value: Value::Bool(false),
    };
    for source in ["with: false", "with: ''", "with: [input]"] {
        assert!(patch(source, route!(), set.clone()).is_err(), "{source}");
    }
}

#[test]
fn removing_a_sequence_item_preserves_neighboring_comments() -> Result<(), Error> {
    let steps = "steps:\n  - run: first # remove\n  - run: second # keep";
    let block = patch(steps, route!("steps", 0), Op::Remove)?;
    insta::assert_snapshot!(block, @"
    steps:
      - run: second # keep
    ");

    let matrix = "matrix: {os: [linux, macos, windows]} # supported platforms";
    let flow = patch(matrix, route!("matrix", "os", 1), Op::Remove)?;
    insta::assert_snapshot!(flow, @"matrix: {os: [linux, windows]} # supported platforms");
    Ok(())
}

#[test]
fn removing_the_last_member_keeps_an_empty_collection() -> Result<(), Error> {
    let steps = "\
steps:
  - env:
      ACTIONS_ALLOW_UNSECURE_COMMANDS: true
    run: echo hi";
    let fixed = patch(
        steps,
        route!("steps", 0, "env", "ACTIONS_ALLOW_UNSECURE_COMMANDS"),
        Op::Remove,
    )?;
    insta::assert_snapshot!(fixed, @"
    steps:
      - env:
          {}
        run: echo hi
    ");

    let last = patch(
        "steps:\n  - run: build\nname: Build",
        route!("steps", 0),
        Op::Remove,
    )?;
    insta::assert_snapshot!(last, @"
    steps:
      []
    name: Build
    ");
    Ok(())
}

#[test]
fn remove_rejects_the_root_and_missing_members() {
    for route in [route!(), route!("missing"), route!("steps", 1)] {
        assert!(
            patch("steps: []", route.clone(), Op::Remove).is_err(),
            "{route:?}"
        );
    }
}

#[test]
fn editing_through_an_alias_changes_only_that_use() -> Result<(), Error> {
    let source = "\
defaults: &step {env: {CI: false}}
first: *step
second: *step";
    let fixed = patch(
        source,
        route!("first", "env", "CI"),
        Op::Replace(Value::Bool(true)),
    )?;
    insta::assert_snapshot!(fixed, @r#"
    defaults: &step {env: {CI: false}}
    first: {"env": {"CI": true}}
    second: *step
    "#);
    Ok(())
}

#[test]
fn set_field_extends_an_aliased_mapping_locally() -> Result<(), Error> {
    let source = "\
inputs: &inputs {fetch-depth: 1}
with: *inputs
other: *inputs";
    let fixed = patch(
        source,
        route!(),
        Op::SetField {
            mapping: "with",
            key: "persist-credentials".into(),
            value: Value::Bool(false),
        },
    )?;
    insta::assert_snapshot!(fixed, @r#"
    inputs: &inputs {fetch-depth: 1}
    with: {"fetch-depth": 1, persist-credentials: false}
    other: *inputs
    "#);
    Ok(())
}

#[test]
fn removing_an_alias_leaves_its_definition_and_other_uses() -> Result<(), Error> {
    let fixed = patch(
        "original: &input 1\nfirst: *input\nsecond: *input",
        route!("first"),
        Op::Remove,
    )?;
    insta::assert_snapshot!(fixed, @"
    original: &input 1
    second: *input
    ");
    Ok(())
}

#[test]
fn only_referenced_anchor_definitions_are_protected() -> Result<(), Error> {
    let change = Op::Replace(Value::Bool(true));
    let err = patch(
        "defaults: &env {CI: false}\ncopy: *env",
        route!("defaults", "CI"),
        change.clone(),
    )
    .expect_err("editing the definition would also change its alias");
    assert_eq!(err.to_string(), "cannot edit shared YAML anchor &env");

    let fixed = patch(
        "defaults: &env {CI: false}",
        route!("defaults", "CI"),
        change,
    )?;
    insta::assert_snapshot!(fixed, @"defaults: &env {CI: true}");
    Ok(())
}

#[test]
fn version_comment_edits_preserve_the_adjacent_ignore_comment() -> Result<(), Error> {
    let doc = Document::new(
        "\
steps:
  - uses: org/a@sha # v1
  - uses: org/b@sha # zizmor: ignore[unpinned-uses]
  - uses: org/c@sha",
    )
    .expect("valid YAML fixture");
    let fixed = apply_yaml_patches(
        &doc,
        &[
            Patch {
                route: route!("steps", 0, "uses"),
                operation: Op::ReplaceComment { new: "# v2".into() },
            },
            Patch {
                route: route!("steps", 2, "uses"),
                operation: Op::EmplaceComment { new: "# v3".into() },
            },
        ],
    )?;
    insta::assert_snapshot!(fixed, @"
    steps:
      - uses: org/a@sha # v2
      - uses: org/b@sha # zizmor: ignore[unpinned-uses]
      - uses: org/c@sha # v3
    ");
    Ok(())
}

#[test]
fn replacing_a_missing_inline_comment_leaves_the_source_alone() -> Result<(), Error> {
    let source = "uses: org/a@sha\n# a separate comment";
    let fixed = patch(
        source,
        route!("uses"),
        Op::ReplaceComment { new: "# v2".into() },
    )?;
    assert_eq!(fixed, source);
    Ok(())
}
