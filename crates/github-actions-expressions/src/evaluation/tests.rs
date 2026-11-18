use super::*;
use crate::Evaluation;

fn bindings(root: &TrackedValue) -> impl FnMut(&mut State, &[Access]) -> Outcomes {
    |_, path| {
        let value = path
            .iter()
            .fold(root.clone(), |value, key| value.apply_access(key));
        vec![Outcome::new(value)]
    }
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
        let values = parsed.evaluate(&mut State::default(), bindings(&root));
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
        let values = parsed.evaluate(&mut analysis, bindings(&context));
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
    let values = parsed.evaluate(&mut State::default(), bindings(&root));
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
        let values = parsed.evaluate(&mut State::default(), bindings(&root));
        assert_eq!(values[0].value.concrete(), Some(Evaluation::Boolean(true)));
    }
}

#[test]
fn decisions_are_stable_across_reads_and_distinct_across_scopes() {
    let mut state = State::default();
    let external = state.decision();
    let parsed = Expr::parse("case(config.enabled, 1, 2)").unwrap();
    let scope = TrackedValue::new(AbstractValue::Reference(vec![]));
    let first = parsed.evaluate(&mut state, bindings(&scope));
    let repeated = parsed.evaluate(&mut state, bindings(&scope));
    assert!(!first[0].choices.contains_key(&external));
    assert_eq!(state.product(first.clone(), repeated, |a, _| a).len(), 2);

    let scope = TrackedValue::new(AbstractValue::Reference(vec![Access::Key("other".into())]));
    let other = parsed.evaluate(&mut state, bindings(&scope));
    assert_eq!(state.product(first, other, |a, _| a).len(), 4);
}
