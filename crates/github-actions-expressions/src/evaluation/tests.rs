use super::*;
use crate::Evaluation;

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
        let values = Evaluator::default().evaluate(&parsed, &mut root.clone());
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
        let mut analysis = Evaluator::default();
        let values = analysis.evaluate(&parsed, &mut context.clone());
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
    let values = Evaluator::default().evaluate(&parsed, &mut root.clone());
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
        let values = Evaluator::default().evaluate(&parsed, &mut root.clone());
        assert_eq!(values[0].value.concrete(), Some(Evaluation::Boolean(true)));
    }
}

#[test]
fn partial_object_distinguishes_unknown_field_contents_from_a_missing_field() {
    let mut field = TrackedValue::unknown();
    field.provenance.sources.insert("config.field".into());
    let mut root = TrackedValue::new(AbstractValue::Object(std::sync::Arc::new(
        [("field".into(), field)].into_iter().collect(),
    )));
    let values =
        Evaluator::default().evaluate(&Expr::parse("missing || field").unwrap(), &mut root);
    assert_eq!(values.len(), 1);
    assert!(values[0].value.concrete().is_none());
    assert!(
        values[0]
            .value
            .dependencies()
            .sources
            .contains("config.field")
    );
}

#[test]
fn decisions_are_stable_across_reads_and_distinct_across_scopes() {
    let mut state = Evaluator::default();
    let external = state.decision();
    let parsed = Expr::parse("case(config.enabled, 1, 2)").unwrap();
    let scope = TrackedValue::new(AbstractValue::Reference(vec![]));
    let first = state.evaluate(&parsed, &mut scope.clone());
    let repeated = state.evaluate(&parsed, &mut scope.clone());
    assert!(!first[0].choices.contains_key(&external));
    assert_eq!(state.product(first.clone(), repeated, |a, _| a).len(), 2);

    let scope = TrackedValue::new(AbstractValue::Reference(vec![Access::Key("other".into())]));
    let other = state.evaluate(&parsed, &mut scope.clone());
    assert_eq!(state.product(first, other, |a, _| a).len(), 4);
}

#[test]
fn nested_lookup_uses_the_producers_bindings() {
    struct Consumer(TrackedValue);
    impl Bindings for Consumer {
        fn lookup(&mut self, _: &[Access], evaluator: &mut Evaluator) -> Outcomes {
            evaluator.template("${{ case(flag, true, false) }}", &mut self.0)
        }
    }

    let mut consumer = Consumer(TrackedValue::new(AbstractValue::Reference(vec![])));
    let values =
        Evaluator::default().evaluate(&Expr::parse("first == second").unwrap(), &mut consumer);
    assert_eq!(values.len(), 2);
    assert!(
        values
            .iter()
            .all(|o| o.value.concrete() == Some(Evaluation::Boolean(true)))
    );
}

#[test]
fn bindings_share_the_budget_only_when_read() {
    struct Expensive;
    impl Bindings for Expensive {
        fn lookup(&mut self, _: &[Access], evaluator: &mut Evaluator) -> Outcomes {
            evaluator.budget.bound(std::iter::repeat(()));
            vec![Outcome::known(Evaluation::Boolean(true))]
        }
    }
    let skipped =
        Evaluator::default().evaluate(&Expr::parse("false && value").unwrap(), &mut Expensive);
    assert_eq!(skipped.len(), 1);
    assert!(!skipped[0].value.provenance.incomplete);

    let read = Evaluator::default().evaluate(&Expr::parse("value").unwrap(), &mut Expensive);
    assert!(
        read.iter()
            .any(|outcome| outcome.value.provenance.incomplete)
    );
}
