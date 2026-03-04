use std::collections::HashMap;
use std::path::Path;

use github_actions_expressions::{Evaluation, Expr};
use serde::Deserialize;

/// Top level: HashMap<GroupName, Vec<TestCase>>
type TestSuite = HashMap<String, Vec<TestCase>>;

#[derive(Deserialize)]
struct TestCase {
    expr: String,
    result: Option<TestResult>,
    contexts: Option<serde_json::Value>,
    err: Option<TestError>,
    #[allow(dead_code)]
    options: Option<TestOptions>,
}

#[derive(Deserialize)]
struct TestResult {
    kind: String,
    value: serde_json::Value,
}

#[derive(Deserialize)]
struct TestError {
    kind: String,
    value: String,
}

#[derive(Deserialize)]
struct TestOptions {
    #[allow(dead_code)]
    skip: Option<Vec<String>>,
}

fn to_evaluation(result: &TestResult) -> Result<Evaluation, String> {
    match result.kind.as_str() {
        "Boolean" => Ok(Evaluation::Boolean(result.value.as_bool().unwrap())),
        "Number" => Ok(Evaluation::Number(result.value.as_f64().unwrap())),
        "String" => Ok(Evaluation::String(
            result.value.as_str().unwrap().to_string(),
        )),
        "Null" => Ok(Evaluation::Null),
        other => Err(format!("unknown result kind {other:?}")),
    }
}

fn eval_eq(a: &Evaluation, b: &Evaluation) -> bool {
    match (a, b) {
        (Evaluation::Number(x), Evaluation::Number(y)) => (x.is_nan() && y.is_nan()) || x == y,
        (Evaluation::String(a), Evaluation::String(b)) => a == b,
        _ => a == b,
    }
}

/// Group name prefixes to skip
const SKIP_GROUP_PREFIXES: &[&str] = &[
    // Depth/memory limit tests: our parser doesn't enforce these limits
    // and will stack-overflow on deeply nested expressions.
    "depth-errors",
    "memory-errors",
    // case() is not a standard GitHub Actions expression function.
    "case",
];

fn should_skip_group(group: &str) -> bool {
    SKIP_GROUP_PREFIXES
        .iter()
        .any(|prefix| group.starts_with(prefix))
}

fn run_test_file(filename: &str, failures: &mut Vec<String>) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/testdata")
        .join(filename);
    let content = std::fs::read_to_string(&path).unwrap();
    let suite: TestSuite = serde_json::from_str(&content).unwrap();

    for (group, cases) in &suite {
        if should_skip_group(group) {
            continue;
        }

        for (i, case) in cases.iter().enumerate() {
            let label = format!("{filename}::{group}[{i}] `{}`", case.expr);

            // Skip cases that require context variables
            if case.contexts.is_some() {
                continue;
            }

            if let Some(err) = &case.err {
                match err.kind.as_str() {
                    // Parse/lex errors
                    "parsing" | "lexing" => {
                        if Expr::parse(&case.expr).is_ok() {
                            failures.push(format!(
                                "{label}: expected {} error {:?} but parsed OK",
                                err.kind, err.value
                            ));
                        }
                    }
                    // Evaluation errors
                    "evaluation" => {
                        if let Ok(parsed) = Expr::parse(&case.expr) {
                            if parsed.consteval().is_some() {
                                failures.push(format!(
                                    "{label}: expected eval error {:?} but got a result",
                                    err.value
                                ));
                            }
                        }
                    }
                    other => {
                        failures.push(format!("{label}: unknown error kind {other:?}"));
                    }
                }
            } else if let Some(expected) = &case.result {
                let parsed = match Expr::parse(&case.expr) {
                    Ok(p) => p,
                    Err(e) => {
                        failures.push(format!("{label}: expected result but parse failed: {e}"));
                        continue;
                    }
                };
                match to_evaluation(expected) {
                    Ok(expected_eval) => match parsed.consteval() {
                        Some(actual) => {
                            if !eval_eq(&actual, &expected_eval) {
                                failures.push(format!(
                                    "{label}: expected {expected_eval:?}, got {actual:?}"
                                ));
                            }
                        }
                        None => {
                            failures.push(format!(
                                "{label}: expected {expected_eval:?}, but consteval returned None"
                            ));
                        }
                    },
                    Err(e) => {
                        failures.push(format!("{label}: {e}"));
                    }
                }
            }
        }
    }
}

#[test]
fn test_upstream_kat() {
    let testdata_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/testdata");

    let mut json_files: Vec<_> = std::fs::read_dir(&testdata_dir)
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                Some(path)
            } else {
                None
            }
        })
        .collect();

    json_files.sort();

    let mut failures = Vec::new();

    for path in &json_files {
        let filename = path.file_name().unwrap().to_str().unwrap();
        run_test_file(filename, &mut failures);
    }

    assert!(
        failures.is_empty(),
        "{} upstream KAT failure(s):\n{}",
        failures.len(),
        failures
            .iter()
            .enumerate()
            .map(|(i, f)| format!("{:>4}. {f}", i + 1))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
