use std::path::Path;

use serde::Deserialize;
use yamlpath::{Document, Query, QueryBuilder};

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
    _testcase: serde_yaml::Value,
    queries: Vec<TestcaseQuery>,
}

impl<'a> From<&'a TestcaseQuery> for Query<'a> {
    fn from(query: &'a TestcaseQuery) -> Self {
        let mut builder = QueryBuilder::new().key("testcase");

        for component in &query.query {
            builder = match component {
                QueryComponent::Index(idx) => builder.index(*idx),
                QueryComponent::Key(key) => builder.key(key),
            }
        }

        builder.build()
    }
}

fn run_testcase(path: &Path) {
    let raw_testcase = std::fs::read_to_string(path).unwrap();
    let testcase = serde_yaml::from_str::<Testcase>(&raw_testcase).unwrap();

    for q in &testcase.queries {
        let document = Document::new(raw_testcase.clone()).unwrap();
        let query: Query = q.into();

        let feature = match q.mode.as_deref() {
            Some("pretty") | None => Some(document.query_pretty(&query).unwrap()),
            Some("exact") => document.query_exact(&query).unwrap(),
            Some("key-only") => Some(document.query_key_only(&query).unwrap()),
            Some(o) => panic!("invalid testcase mode: {o}"),
        };

        let expected = q.expected.as_str();

        match feature {
            Some(feature) => {
                assert_eq!(document.extract_with_leading_whitespace(&feature), expected)
            }
            None => assert_eq!(expected, "<<empty>>"),
        }
    }
}
