//! Known-answer tests (KATs) derived from GitHub's official
//! `actions/languageservices` tests.
//!
//! See `support/sync-expression-tests.py` for how the KATs themselves
//! are synchronized from the upstream test suite.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::LazyLock;

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

#[derive(Copy, Clone, Debug, Deserialize)]
enum ValueKind {
    Boolean,
    Number,
    String,
    Null,
    Array,
    Object,
}

#[derive(Deserialize)]
struct TestResult {
    kind: ValueKind,
    value: serde_json::Value,
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

#[derive(Deserialize)]
struct TestOptions {
    #[allow(dead_code)]
    skip: Option<Vec<String>>,
}

fn to_evaluation(result: &TestResult) -> Result<Evaluation, String> {
    match result.kind {
        ValueKind::Boolean => Ok(Evaluation::Boolean(result.value.as_bool().unwrap())),
        ValueKind::Number => Ok(Evaluation::Number(result.value.as_f64().unwrap())),
        ValueKind::String => Ok(Evaluation::String(
            result.value.as_str().unwrap().to_string(),
        )),
        ValueKind::Null => Ok(Evaluation::Null),
        ValueKind::Array | ValueKind::Object => Evaluation::try_from(result.value.clone())
            .map_err(|()| format!("failed to convert {:?} value to Evaluation", result.kind)),
    }
}

/// Entire test suite groups to skip.
static SKIPPED_GROUPS: LazyLock<HashSet<(&str, &str)>> = LazyLock::new(|| {
    HashSet::from_iter([
        // We don't enforce recursion limits at the moment.
        // TODO: Do so?
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
        // We don't currently support context evaluation on `fromJSON` in consteval.
        // TODO: We should support this.
        ("op_dot.json", "property-basics", 7),
        ("op_dot.json", "property-basics", 8),
        // We don't currently support index evaluation on `fromJSON` in consteval.
        // TODO: We should support this.
        ("op_idx.json", "index-following-group", 0),
        ("op_idx.json", "index-following-function", 0),
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

            // Skip cases that require context variables.
            // TODO: We should probably test these too, and broaden
            // `consteval` to include support for known contexts.
            if case.contexts.is_some() {
                continue;
            }

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
                        if let Ok(parsed) = Expr::parse(&case.expr) {
                            if parsed.consteval().is_some() {
                                failures.push(format!(
                                    "{label}: expected eval error {:?} but got a result",
                                    err.value
                                ));
                            }
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
                match to_evaluation(expected) {
                    Ok(expected_eval) => match parsed.consteval() {
                        Some(actual) => {
                            if expected_eval != actual {
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
