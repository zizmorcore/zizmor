//! End-to-end integration tests for `--format=json-v1`.

use insta::assert_snapshot;

use crate::common::{input_under_test, zizmor};

#[test]
fn test_json_v1() {
    let output = zizmor()
        .args(["--format=json-v1"])
        .input(input_under_test("template-injection.yml"))
        .input(input_under_test("unpinned-uses.yml"))
        .input(input_under_test("unsound-contains.yml"))
        .run()
        .expect("Failed to run zizmor with JSON v1 format");

    assert_snapshot!(output);
}
