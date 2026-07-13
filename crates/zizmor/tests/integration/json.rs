//! Tests for zizmor's JSON output formats.

use crate::common::{input_under_test, zizmor};

/// The v1 JSON output includes symbolic fix metadata (`fixes`) for findings
/// that carry an auto-fix: the fix's `title`, target `key`, and `disposition`,
/// but no concrete patch/offset data.
#[test]
fn v1_output_includes_fix_metadata() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "dependabot-execution/basic/dependabot.yml"
            ))
            .args(["--format", "json"])
            .run()?,
        @r#"
    [
      {
        "ident": "dependabot-execution",
        "desc": "external code execution in Dependabot updates",
        "url": "https://docs.zizmor.sh/audits/#dependabot-execution",
        "determinations": {
          "confidence": "High",
          "severity": "High",
          "persona": "Regular"
        },
        "locations": [
          {
            "symbolic": {
              "key": {
                "Local": {
                  "verbatim_path": "@@INPUT@@"
                }
              },
              "annotation": "enabled here",
              "route": {
                "route": [
                  {
                    "Key": "updates"
                  },
                  {
                    "Index": 0
                  },
                  {
                    "Key": "insecure-external-code-execution"
                  }
                ]
              },
              "feature_kind": "Normal",
              "kind": "Primary"
            },
            "concrete": {
              "location": {
                "start_point": {
                  "row": 9,
                  "column": 4
                },
                "end_point": {
                  "row": 9,
                  "column": 43
                },
                "offset_span": {
                  "start": 141,
                  "end": 180
                }
              },
              "feature": "    insecure-external-code-execution: allow",
              "comments": []
            }
          },
          {
            "symbolic": {
              "key": {
                "Local": {
                  "verbatim_path": "@@INPUT@@"
                }
              },
              "annotation": "this ecosystem",
              "route": {
                "route": [
                  {
                    "Key": "updates"
                  },
                  {
                    "Index": 0
                  },
                  {
                    "Key": "package-ecosystem"
                  }
                ]
              },
              "feature_kind": "Normal",
              "kind": "Related"
            },
            "concrete": {
              "location": {
                "start_point": {
                  "row": 3,
                  "column": 4
                },
                "end_point": {
                  "row": 3,
                  "column": 26
                },
                "offset_span": {
                  "start": 25,
                  "end": 47
                }
              },
              "feature": "package-ecosystem: pip",
              "comments": []
            }
          }
        ],
        "ignored": false,
        "fixes": [
          {
            "title": "set insecure-external-code-execution to deny",
            "key": {
              "Local": {
                "verbatim_path": "@@INPUT@@"
              }
            },
            "disposition": "unsafe"
          }
        ]
      }
    ]
    "#
    );

    Ok(())
}
