//! Known-answer tests (KATs) derived from GitHub's official
//! `actions/languageservices` tests.
//!
//! See `support/sync-expression-tests.py` for how the KATs themselves
//! are synchronized from the upstream test suite.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::LazyLock;

use github_actions_expressions::{
    Evaluation, Expr,
    evaluation::{Evaluator, TrackedValue},
};
use serde::Deserialize;

/// Top level: HashMap<GroupName, Vec<TestCase>>
type TestSuite = HashMap<String, Vec<TestCase>>;

#[derive(Deserialize)]
struct TestCase {
    expr: String,
    result: Option<TestResult>,
    contexts: Option<Evaluation>,
    err: Option<TestError>,
}

#[derive(Deserialize)]
struct TestResult {
    value: Evaluation,
}

#[derive(Copy, Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ErrorKind {
    Parsing,
    Lexing,
    Evaluation,
}

#[derive(Deserialize)]
struct TestError {
    kind: ErrorKind,
    value: String,
}

/// Entire test suite groups to skip.
static SKIPPED_GROUPS: LazyLock<HashSet<(&str, &str)>> = LazyLock::new(|| {
    HashSet::from_iter([
        // GitHub also applies its depth limit to iterative postfix chains,
        // while we only limit recursive parser productions.
        ("syntax-errors.json", "depth-errors"),
        // We don't enforce memory limits at the moment.
        // It's not clear whether we should, since GitHub's TypeScript implementation
        // doesn't either.
        ("syntax-errors.json", "memory-errors"),
    ])
});

/// Specific test cases within a suite/group to skip.
const SKIPPED_CASES: LazyLock<HashSet<(&str, &str, usize)>> = LazyLock::new(|| {
    HashSet::from_iter([
        // We're currently permissive about unknown contexts.
        ("basic.json", "unknown context", 0),
        // We don't parse '' (an empty expression) as valid.
        ("basic.json", "empty_expression", 0),
    ])
});

fn run_test_file(suite_name: &str, failures: &mut Vec<String>) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/testdata")
        .join(suite_name);
    let content = std::fs::read_to_string(&path).unwrap();
    let suite: TestSuite = serde_json::from_str(&content).unwrap();

    for (group, cases) in &suite {
        if SKIPPED_GROUPS.contains(&(suite_name, group.as_str())) {
            continue;
        }

        for (i, case) in cases.iter().enumerate() {
            if SKIPPED_CASES.contains(&(suite_name, group.as_str(), i)) {
                continue;
            }

            let label = format!("{suite_name}::{group}[{i}] `{}`", case.expr);

            let evaluate = |expr: &Expr<'_>| match &case.contexts {
                None => expr.consteval(),
                Some(contexts) => {
                    let mut bindings = TrackedValue::known(contexts.clone());
                    let outcomes = Evaluator::default().evaluate(expr, &mut bindings);
                    let [outcome] = outcomes.as_slice() else {
                        return None;
                    };
                    outcome.value.concrete()
                }
            };

            if let Some(err) = &case.err {
                match err.kind {
                    // Parse/lex errors
                    ErrorKind::Parsing | ErrorKind::Lexing => {
                        if Expr::parse(&case.expr).is_ok() {
                            failures.push(format!(
                                "{label}: expected {:?} error {:?} but parsed OK",
                                err.kind, err.value
                            ));
                        }
                    }
                    // Evaluation errors
                    ErrorKind::Evaluation => {
                        if let Ok(parsed) = Expr::parse(&case.expr)
                            && evaluate(&parsed).is_some()
                        {
                            failures.push(format!(
                                "{label}: expected eval error {:?} but got a result",
                                err.value
                            ));
                        }
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
                let actual = evaluate(&parsed);
                if actual.as_ref() != Some(&expected.value) {
                    failures.push(format!(
                        "{label}: expected {:?}, got {actual:?}",
                        expected.value
                    ));
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
