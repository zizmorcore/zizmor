use std::path::Path;

use serde::Deserialize;
use yamlpath::{Component, Document, Route};

#[test]
fn test_integration() {
    let testcases = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/testcases");
    assert!(testcases.is_dir());

    for testcase_path in std::fs::read_dir(&testcases).unwrap() {
        let testcase_path = testcase_path.unwrap().path();

        run_testcase(&testcase_path)
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum QueryComponent {
    Key(String),
    Index(usize),
}

#[derive(Deserialize)]
struct TestcaseQuery {
    query: Vec<QueryComponent>,
    mode: Option<String>,
    expected: String,
}

#[derive(Deserialize)]
struct Testcase {
    #[serde(rename = "testcase")]
    _testcase: astral_yaml_serde::Value,
    queries: Vec<TestcaseQuery>,
}

impl<'a> From<&'a TestcaseQuery> for Route<'a> {
    fn from(query: &'a TestcaseQuery) -> Self {
        let mut components = vec![Component::Key("testcase".into())];

        for component in &query.query {
            match component {
                QueryComponent::Index(idx) => components.push(Component::Index(*idx)),
                QueryComponent::Key(key) => components.push(Component::Key(key.into())),
            }
        }

        Self::from(components)
    }
}

fn run_testcase(path: &Path) {
    let raw_testcase = std::fs::read_to_string(path).unwrap();
    let testcase = astral_yaml_serde::from_str::<Testcase>(&raw_testcase).unwrap();

    let document = Document::new(raw_testcase).unwrap();
    for q in &testcase.queries {
        let route = q.into();
        let range = match q.mode.as_deref() {
            Some("exact") => document.value_range(&route).unwrap(),
            Some("key-only") => Some(document.key_range(&route).unwrap()),
            Some("pretty") | None => Some(document.entry_range(&route).unwrap()),
            Some(other) => panic!("unknown query mode: {other}"),
        };
        assert_eq!(
            range.map(|r| &document.source()[r]).unwrap_or("<<empty>>"),
            q.expected,
            "testcase: {path:?}, route: {route:?}",
        );
    }
}
