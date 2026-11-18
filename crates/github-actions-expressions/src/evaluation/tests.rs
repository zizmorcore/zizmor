use super::*;
use crate::Evaluation;

fn bindings(root: &TrackedValue) -> Scope {
    Scope::new(Definition::value(root.clone()))
}

#[test]
fn incomplete_control_dependencies_remain_incomplete() {
    let mut root = TrackedValue::new(AbstractValue::Reference(vec![]));
    root.provenance.incomplete = true;

    for source in [
        "case(inputs.value, 'a', 'b')",
        "!inputs.value",
        "inputs.value == 'expected'",
        "contains(inputs.value, 'expected')",
        "hashFiles(inputs.value)",
        r#"fromJSON('{"key":"fixed"}')[inputs.value]"#,
    ] {
        let parsed = Expr::parse(source).expect("valid expression");
        let values = bindings(&root).evaluate(&parsed);
        assert!(!values.is_empty(), "{source}");
        assert!(
            values
                .iter()
                .all(|outcome| outcome.value.dependencies().incomplete),
            "{source}"
        );
    }
}

#[test]
fn independent_choices_preserve_the_last_alternative() {
    let context = TrackedValue::new(AbstractValue::Reference(vec![]));
    for branch in [
        "case(flags.b{index}, '1', '0')",
        "(flags.b{index} && '1' || '0')",
    ] {
        let args = (0..8)
            .map(|index| branch.replace("{index}", &index.to_string()))
            .collect::<Vec<_>>()
            .join(", ");
        let source = format!(
            "format('{{0}}{{1}}{{2}}{{3}}{{4}}{{5}}{{6}}{{7}}', {args}) == '11111111' && payload.text"
        );
        let parsed = Expr::parse(&source).expect("valid expression");
        let mut analysis = State::default();
        let values = analysis.evaluate(&parsed, &bindings(&context));
        assert_eq!(values.len(), 1 << 8);
        assert!(
            values
                .iter()
                .all(|value| !value.value.provenance.incomplete)
        );
        assert!(
            values
                .iter()
                .any(|value| value.value.dependencies().sources.contains("payload.text"))
        );
    }
}

#[test]
fn bindings_preserve_typed_values_and_provenance() {
    let mut root = TrackedValue::new(AbstractValue::Reference(vec![]));
    root.provenance.evidence.insert(7);
    let parsed =
        Expr::parse(r#"case(flags.enabled, fromJSON('{"n":20}'), fromJSON('{"n":1}')).n"#).unwrap();
    let values = bindings(&root).evaluate(&parsed);
    assert_eq!(values.len(), 2);
    assert_eq!(values[0].value.concrete(), Some(Evaluation::Number(1.0)));
    assert_eq!(values[1].value.concrete(), Some(Evaluation::Number(20.0)));
    assert_ne!(values[0].choices, values[1].choices);
    for value in values {
        let provenance = value.value.dependencies();
        assert!(provenance.sources.is_empty());
        assert!(provenance.controls.contains("flags.enabled"));
        assert!(provenance.evidence.contains(&7));
    }

    let data = serde_json::json!({"config": {"n": 20}, "list": []});
    let root = TrackedValue::known(data.try_into().unwrap());
    for source in [
        "config == config",
        "list == list",
        "config.n == 20",
        "list != fromJSON('[]')",
    ] {
        let parsed = Expr::parse(source).unwrap();
        let values = bindings(&root).evaluate(&parsed);
        assert_eq!(values[0].value.concrete(), Some(Evaluation::Boolean(true)));
    }
}

#[test]
fn decisions_are_stable_across_reads_and_distinct_across_scopes() {
    let mut state = State::default();
    let external = state.decision();
    let parsed = Expr::parse("case(config.enabled, 1, 2)").unwrap();
    let scope = TrackedValue::new(AbstractValue::Reference(vec![]));
    let first = state.evaluate(&parsed, &bindings(&scope));
    let repeated = state.evaluate(&parsed, &bindings(&scope));
    assert!(!first[0].choices.contains_key(&external));
    assert_eq!(state.product(first.clone(), repeated, |a, _| a).len(), 2);

    let scope = TrackedValue::new(AbstractValue::Reference(vec![Access::Key("other".into())]));
    let other = state.evaluate(&parsed, &bindings(&scope));
    assert_eq!(state.product(first, other, |a, _| a).len(), 4);
}

#[test]
fn nested_definition_preserves_shared_choices_and_short_circuits() {
    let known = |value| Definition::known(Evaluation::Boolean(value));
    let mut producer = Scope::default();
    producer.bind("flag", Definition::choice(vec![known(false), known(true)]));
    let output = Definition::template(
        "${{ flag || (false && fromJSON('invalid')) }}".into(),
        producer,
    );
    let mut consumer = Scope::default();
    consumer.bind("first", output.clone());
    consumer.bind("second", output);
    let values = consumer.evaluate(&Expr::parse("first == second").unwrap());
    assert_eq!(values.len(), 2);
    assert!(
        values
            .iter()
            .all(|o| o.value.concrete() == Some(Evaluation::Boolean(true)))
    );
}

#[test]
fn bound_collections_preserve_identity_and_field_sources() {
    let mut scope = Scope::default();
    scope.bind(
        "config",
        Definition::object(std::collections::BTreeMap::from([(
            "field".into(),
            Definition::runtime(String::new()),
        )])),
    );
    let values = scope.evaluate(&Expr::parse("config == CONFIG && config.field").unwrap());
    assert_eq!(values.len(), 1);
    assert!(
        values[0]
            .value
            .dependencies()
            .sources
            .contains("config.field")
    );
}

#[test]
fn expansion_charges_only_the_branch_that_reads_it() {
    let value = Definition::known(Evaluation::Boolean(true)).expand(|value, budget| {
        // Even discarded intermediate candidates count toward the evaluation limits.
        budget.bound(std::iter::repeat(()));
        vec![value.clone()]
    });
    let mut scope = Scope::default();
    scope.bind("value", value);

    let skipped = scope.evaluate(&Expr::parse("false && value").unwrap());
    assert_eq!(skipped.len(), 1);
    assert!(!skipped[0].value.provenance.incomplete);

    let read = scope.evaluate(&Expr::parse("value").unwrap());
    assert!(
        read.iter()
            .any(|outcome| outcome.value.provenance.incomplete)
    );
}
