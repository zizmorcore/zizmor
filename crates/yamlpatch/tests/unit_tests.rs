use astral_yaml_serde::Value;
use subfeature::Subfeature;
use yamlpatch::{Op, Patch};
use yamlpath::{Document, Route, route};

fn apply_yaml_patches(source: &str, patches: &[Patch<'_>]) -> Result<String, yamlpatch::Error> {
    yamlpatch::apply_yaml_patches(&Document::new(source).unwrap(), patches)
}

fn value(yaml: &str) -> Value {
    astral_yaml_serde::from_str(yaml).unwrap()
}

fn apply(source: &str, route: Route<'_>, operation: Op<'_>) -> String {
    apply_yaml_patches(source, &[Patch { route, operation }]).unwrap()
}

#[test]
fn replace_preserves_yaml_types_and_siblings() {
    let original = "é: 'before\u{80}after' # keep\r\nsteps:\r  - run: old\r  - run: other\n";
    for replacement in [
        "'false'",
        "false",
        "'key: value'",
        "null",
        "{}",
        "[a, {b: 2}]",
    ] {
        let result = apply(
            original,
            route!("steps", 0, "run"),
            Op::Replace(value(replacement)),
        );
        assert_eq!(
            value(&result),
            value(&original.replace("run: old", &format!("run: {replacement}")))
        );
        let doc = Document::new(result).unwrap();
        assert_eq!(doc.stream().comments()[0].text, " keep");
    }
}

#[test]
fn add_rejects_an_existing_key() {
    let patch = Patch {
        route: route!("flow"),
        operation: Op::Add {
            key: "new".into(),
            value: value("{nested: [true]}"),
        },
    };
    let result = apply_yaml_patches("flow: {old: 1}", std::slice::from_ref(&patch)).unwrap();
    assert_eq!(
        value(&result),
        value("flow: {old: 1, new: {nested: [true]}}")
    );
    assert!(apply_yaml_patches(&result, &[patch]).is_err());
}

#[test]
fn set_nested_field() {
    for (original, expected) in [
        (
            "step: {uses: action}",
            "step: {uses: action, with: {flag: false}}",
        ),
        ("step:\n  with:", "step: {with: {flag: false}}"),
        ("step: {with: null}", "step: {with: {flag: false}}"),
        ("step: {with: {}}", "step: {with: {flag: false}}"),
        (
            "step:\n  with:\n    keep: 'é' # retain\n    flag: true",
            "step: {with: {keep: é, flag: false}}",
        ),
    ] {
        let result = apply(
            original,
            route!("step"),
            Op::SetField {
                mapping: "with",
                key: "flag".into(),
                value: Value::Bool(false),
            },
        );
        assert_eq!(value(&result), value(expected));
        if original.contains("# retain") {
            let doc = Document::new(result).unwrap();
            let span = doc.entry_range(&route!("step", "with", "keep")).unwrap();
            assert_eq!(doc.comments(span)[0].text, " retain");
        }
    }
    for invalid in ["{with: false}", "{with: ''}", "{with: [a]}"] {
        let patch = Patch {
            route: route!(),
            operation: Op::SetField {
                mapping: "with",
                key: "flag".into(),
                value: Value::Bool(false),
            },
        };
        assert!(apply_yaml_patches(invalid, &[patch]).is_err());
    }
}

#[test]
fn remove_only_the_selected_member() {
    for (original, route, expected) in [
        ("s: [a, b, c]", route!("s", 1), "s: [a, c]"),
        (
            "s:\n  - # item\n    a: 1\n  - other\n",
            route!("s", 0),
            "s: [other]",
        ),
        ("m: {k: {a: 1}, keep: 2}", route!("m", "k"), "m: {keep: 2}"),
        (
            "steps:\n  - env:\n      ONLY: 1\n    run: echo",
            route!("steps", 0, "env", "ONLY"),
            "steps: [{env: {}, run: echo}]",
        ),
        (
            "list:\n  - only\nother: 2",
            route!("list", 0),
            "list: []\nother: 2",
        ),
        ("single: true", route!("single"), "{}"),
        ("[single]", route!(0), "[]"),
        ("a: &x 1\nb: *x", route!("b"), "a: 1"),
    ] {
        assert_eq!(value(&apply(original, route, Op::Remove)), value(expected));
    }
    for route in [route!(), route!("missing"), route!("a", 1)] {
        assert!(
            apply_yaml_patches(
                "a: [x]",
                &[Patch {
                    route,
                    operation: Op::Remove
                }]
            )
            .is_err()
        );
    }
}

#[test]
fn rewrite_the_decoded_string() {
    let source = "run: \"é\\nold old\"\nother: old";
    let result = apply(
        source,
        route!("run"),
        Op::RewriteString {
            from: Subfeature::new("é\nold".len(), "old"),
            to: "quoted: 'x'".into(),
        },
    );
    assert_eq!(
        value(&result),
        value("run: |-\n  é\n  old quoted: 'x'\nother: old")
    );
}

#[test]
fn edits_through_an_alias_are_local_to_its_use() {
    let source =
        "original: &step {run: old, env: &env {a: 1}}\ncopy: *step\nother: *step\nvars: *env";
    let patches = [
        Patch {
            route: route!("copy", "run"),
            operation: Op::RewriteString {
                from: Subfeature::new(0, "old"),
                to: "new".into(),
            },
        },
        Patch {
            route: route!("copy"),
            operation: Op::SetField {
                mapping: "env",
                key: "b".into(),
                value: Value::Bool(false),
            },
        },
        Patch {
            route: route!("vars", "a"),
            operation: Op::Remove,
        },
    ];
    let result = apply_yaml_patches(source, &patches).unwrap();
    assert_eq!(
        value(&result),
        value(
            "original: &step {run: old, env: {a: 1}}\ncopy: {run: new, env: {a: 1, b: false}}\nother: *step\nvars: {}"
        )
    );
}

#[test]
fn version_comments_stay_on_the_selected_node() {
    let source = "steps:\n  - uses: 'org/a@sha' # v1\n  - uses: org/b@ref # zizmor: ignore[unpinned-uses]\n  - uses: org/c@sha\n";
    let patches = [
        Patch {
            route: route!("steps", 0, "uses"),
            operation: Op::ReplaceComment { new: "# v2".into() },
        },
        Patch {
            route: route!("steps", 2, "uses"),
            operation: Op::EmplaceComment { new: "# v3".into() },
        },
    ];
    let result = apply_yaml_patches(source, &patches).unwrap();
    assert_eq!(value(&result), value(source));
    let doc = Document::new(result).unwrap();
    for (i, text) in [" v2", " zizmor: ignore[unpinned-uses]", " v3"]
        .iter()
        .enumerate()
    {
        let span = doc.entry_range(&route!("steps", i, "uses")).unwrap();
        assert_eq!(doc.comments(span)[0].text, *text);
    }
    let plain = apply(
        "uses: org/a@sha",
        route!("uses"),
        Op::ReplaceComment { new: "# v2".into() },
    );
    assert!(Document::new(plain).unwrap().stream().comments().is_empty());
}

#[test]
fn failure_discards_the_whole_fix() {
    let original = "a: old\nb: other";
    let doc = Document::new(original).unwrap();
    let result = apply_yaml_patches(
        doc.source(),
        &[
            Patch {
                route: route!("a"),
                operation: Op::Replace(value("new")),
            },
            Patch {
                route: route!("b"),
                operation: Op::RewriteString {
                    from: Subfeature::new(0, "missing"),
                    to: "new".into(),
                },
            },
        ],
    );
    assert!(result.is_err());
    assert_eq!(doc.source(), original);
}

#[test]
fn a_context_specific_fix_cannot_change_other_users_of_a_definition() {
    let source = "steps:\n  - run: &script echo old\n  - run: *script";
    let patches = [
        Patch {
            route: route!("steps", 0, "run"),
            operation: Op::RewriteString {
                from: Subfeature::new(0, "old"),
                to: "$FIXED".into(),
            },
        },
        Patch {
            route: route!("steps", 0),
            operation: Op::SetField {
                mapping: "env",
                key: "FIXED".into(),
                value: Value::String("old".into()),
            },
        },
    ];
    assert!(apply_yaml_patches(source, &patches).is_err());
    let fixed = apply_yaml_patches("steps: [{run: &unused echo old}]", &patches).unwrap();
    assert_eq!(
        value(&fixed),
        value("steps: [{run: echo $FIXED, env: {FIXED: old}}]")
    );
}
