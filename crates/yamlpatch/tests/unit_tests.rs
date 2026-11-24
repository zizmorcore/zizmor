use astral_yaml_serde::Value;
use subfeature::Subfeature;
use yamlpatch::{Error, Op, Patch, apply_yaml_patches};
use yamlpath::{Document, Route, route};

fn patch(source: &str, route: Route<'_>, operation: Op<'_>) -> Result<String, Error> {
    let doc = Document::new(source).expect("valid YAML fixture");
    apply_yaml_patches(&doc, &[Patch { route, operation }])
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
fn add_rejects_a_key_inserted_earlier_in_the_batch() {
    let doc = Document::new("env: {}").expect("valid YAML fixture");
    let add = Patch {
        route: route!("env"),
        operation: Op::Add {
            key: "CI".into(),
            value: Value::Bool(true),
        },
    };

    let err = apply_yaml_patches(&doc, &[add.clone(), add])
        .expect_err("adding the same key twice must fail");
    assert_eq!(err.to_string(), "key 'CI' already exists");
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
fn set_field_rejects_a_quoted_null() {
    let set = Op::SetField {
        mapping: "with",
        key: "flag".into(),
        value: Value::Bool(false),
    };
    assert!(patch("with: 'null'", route!(), set).is_err());
}

#[test]
fn remove_rejects_the_root_and_missing_keys() {
    let root = patch("env: {}", route!(), Op::Remove).expect_err("the root has no parent");
    assert_eq!(root.to_string(), "cannot remove the document root");

    let missing =
        patch("env: {}", route!("env", "CI"), Op::Remove).expect_err("there is no CI entry");
    assert_eq!(missing.to_string(), "no such key: CI");
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
fn remove_distinguishes_an_alias_from_an_item_within_it() -> Result<(), Error> {
    let doc = Document::new(
        "\
versions: &versions [20, 22, 24]
linux: *versions
windows: *versions
macos: *versions",
    )
    .expect("valid YAML fixture");
    let patches = [route!("linux", 1), route!("windows")].map(|route| Patch {
        route,
        operation: Op::Remove,
    });
    let fixed = apply_yaml_patches(&doc, &patches)?;
    insta::assert_snapshot!(fixed, @"
    versions: &versions [20, 22, 24]
    linux: [20, 24]
    macos: *versions
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
