use crate::common::zizmor;

/// Test that `-` reads a workflow from stdin.
#[test]
fn test_stdin_workflow() -> anyhow::Result<()> {
    let workflow = "\
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
";
    // NOTE: We use .args(["-"]) instead of .input("-") because the
    // test harness replaces all occurrences of the input string in the
    // output, and `-` would corrupt arrows, flags, etc.
    insta::assert_snapshot!(
        zizmor().stdin(workflow).no_config(true).args(["-"]).run()?,
        @"
    warning[artipacked]: credential persistence through GitHub Actions artifacts
     --> <stdin>:6:9
      |
    6 |       - uses: actions/checkout@v3
      |         ^^^^^^^^^^^^^^^^^^^^^^^^^ does not set persist-credentials: false
      |
      = note: audit confidence → Low
      = note: this finding has an auto-fix

    warning[excessive-permissions]: overly broad permissions
     --> <stdin>:3:3
      |
    3 | /   test:
    4 | |     runs-on: ubuntu-latest
    5 | |     steps:
    6 | |       - uses: actions/checkout@v3
      | |                                  ^
      | |                                  |
      | |__________________________________this job
      |                                    default permissions used due to no permissions: block
      |
      = note: audit confidence → Medium

    error[unpinned-uses]: unpinned action reference
     --> <stdin>:6:15
      |
    6 |       - uses: actions/checkout@v3
      |               ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
      |
      = note: audit confidence → High

    7 findings (4 suppressed): 0 informational, 0 low, 2 medium, 1 high
    "
    );

    Ok(())
}

/// Test that `-` reads an action definition from stdin.
#[test]
fn test_stdin_action() -> anyhow::Result<()> {
    let action = "\
name: My Action
description: Test action
runs:
  using: composite
  steps:
    - uses: actions/checkout@v3
";
    insta::assert_snapshot!(
        zizmor().stdin(action).no_config(true).args(["-"]).run()?,
        @"
    warning[artipacked]: credential persistence through GitHub Actions artifacts
     --> <stdin>:6:7
      |
    6 |     - uses: actions/checkout@v3
      |       ^^^^^^^^^^^^^^^^^^^^^^^^^ does not set persist-credentials: false
      |
      = note: audit confidence → Low
      = note: this finding has an auto-fix

    error[unpinned-uses]: unpinned action reference
     --> <stdin>:6:13
      |
    6 |     - uses: actions/checkout@v3
      |             ^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
      |
      = note: audit confidence → High

    2 findings: 0 informational, 0 low, 1 medium, 1 high
    "
    );

    Ok(())
}

/// Test that `-` reads a Dependabot config from stdin.
#[test]
fn test_stdin_dependabot() -> anyhow::Result<()> {
    let dependabot = "\
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
";
    insta::assert_snapshot!(
        zizmor()
            .stdin(dependabot)
            .no_config(true)
            .args(["-"])
            .run()?,
        @"
    warning[dependabot-cooldown]: insufficient cooldown in Dependabot updates
     --> <stdin>:3:5
      |
    3 |   - package-ecosystem: github-actions
      |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ missing cooldown configuration
      |
      = note: audit confidence → High
      = note: this finding has an auto-fix

    1 finding: 0 informational, 0 low, 1 medium, 0 high
    "
    );

    Ok(())
}

/// Test that `-` cannot be combined with other inputs.
#[test]
fn test_stdin_with_other_inputs() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .stdin("on: push")
            .no_config(true)
            .expects_failure(2)
            .args(["-", "some-dir/"])
            .run()?,
        @"
     INFO zizmor: 🌈 zizmor v@@VERSION@@
    error: `-` (stdin) cannot be combined with other inputs

    Usage: zizmor [OPTIONS] <INPUT>...

    For more information, try '--help'.
    "
    );

    Ok(())
}

/// Test that `--fix` cannot be used with `-`.
#[test]
fn test_stdin_with_fix() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .stdin("on: push")
            .no_config(true)
            .expects_failure(2)
            .args(["--fix", "-"])
            .run()?,
        @"
     INFO zizmor: 🌈 zizmor v@@VERSION@@
    error: `--fix` cannot be used with `-` (stdin)

    Usage: zizmor [OPTIONS] <INPUT>...

    For more information, try '--help'.
    "
    );

    Ok(())
}

/// Test that invalid YAML on stdin produces a helpful error.
#[test]
fn test_stdin_invalid_yaml() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .stdin("{[invalid")
            .no_config(true)
            .expects_failure(1)
            .args(["-"])
            .run()?,
        @"
     INFO zizmor: 🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    failed to load <stdin> as workflow

    Caused by:
        0: invalid YAML syntax: did not find expected ',' or ']' at line 2 column 1, while parsing a flow sequence at line 1 column 2
        1: did not find expected ',' or ']' at line 2 column 1, while parsing a flow sequence at line 1 column 2
    "
    );

    Ok(())
}

/// Test that invalid YAML on stdin with `--strict-collection` fails.
#[test]
fn test_stdin_invalid_yaml_strict() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .stdin("{[invalid")
            .no_config(true)
            .expects_failure(1)
            .args(["--strict-collection", "-"])
            .run()?,
        @"
     INFO zizmor: 🌈 zizmor v@@VERSION@@
    fatal: no audit was performed
    failed to load <stdin> as workflow

    Caused by:
        0: invalid YAML syntax: did not find expected ',' or ']' at line 2 column 1, while parsing a flow sequence at line 1 column 2
        1: did not find expected ',' or ']' at line 2 column 1, while parsing a flow sequence at line 1 column 2
    "
    );

    Ok(())
}

/// Test that empty stdin produces a collection error.
#[test]
fn test_stdin_empty() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .stdin("")
            .no_config(true)
            .expects_failure(3)
            .args(["-"])
            .run()?,
        @"
     INFO zizmor: 🌈 zizmor v@@VERSION@@
     WARN collect_inputs: zizmor::registry::input: stdin: could not parse as any known input type
    fatal: no audit was performed
    error: no inputs collected
      |
      = help: collection yielded no auditable inputs
      = help: inputs must contain at least one valid workflow, action, or Dependabot config

    Caused by:
        no inputs collected
    "
    );

    Ok(())
}

/// Test that SARIF output works with stdin input.
#[test]
fn test_stdin_sarif_output() -> anyhow::Result<()> {
    let workflow = "\
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
";
    let output = zizmor()
        .stdin(workflow)
        .no_config(true)
        .args(["--format=sarif", "-"])
        .run()?;

    insta::assert_snapshot!(output, @r#"
    {
      "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
      "runs": [
        {
          "invocations": [
            {
              "executionSuccessful": true
            }
          ],
          "results": [
            {
              "codeFlows": [
                {
                  "threadFlows": [
                    {
                      "locations": [
                        {
                          "importance": "essential",
                          "location": {
                            "logicalLocations": [
                              {
                                "properties": {
                                  "symbolic": {
                                    "annotation": "does not set persist-credentials: false",
                                    "feature_kind": "Normal",
                                    "key": {
                                      "Stdin": {}
                                    },
                                    "kind": "Primary",
                                    "route": {
                                      "route": [
                                        {
                                          "Key": "jobs"
                                        },
                                        {
                                          "Key": "test"
                                        },
                                        {
                                          "Key": "steps"
                                        },
                                        {
                                          "Index": 0
                                        }
                                      ]
                                    }
                                  }
                                }
                              }
                            ],
                            "message": {
                              "text": "does not set persist-credentials: false"
                            },
                            "physicalLocation": {
                              "artifactLocation": {
                                "uri": "<stdin>"
                              },
                              "region": {
                                "endColumn": 1,
                                "endLine": 7,
                                "snippet": {
                                  "text": "uses: actions/checkout@v3\n"
                                },
                                "sourceLanguage": "yaml",
                                "startColumn": 9,
                                "startLine": 6
                              }
                            }
                          }
                        }
                      ]
                    }
                  ]
                }
              ],
              "kind": "fail",
              "level": "warning",
              "locations": [
                {
                  "logicalLocations": [
                    {
                      "properties": {
                        "symbolic": {
                          "annotation": "does not set persist-credentials: false",
                          "feature_kind": "Normal",
                          "key": {
                            "Stdin": {}
                          },
                          "kind": "Primary",
                          "route": {
                            "route": [
                              {
                                "Key": "jobs"
                              },
                              {
                                "Key": "test"
                              },
                              {
                                "Key": "steps"
                              },
                              {
                                "Index": 0
                              }
                            ]
                          }
                        }
                      }
                    }
                  ],
                  "message": {
                    "text": "does not set persist-credentials: false"
                  },
                  "physicalLocation": {
                    "artifactLocation": {
                      "uri": "<stdin>"
                    },
                    "region": {
                      "endColumn": 1,
                      "endLine": 7,
                      "snippet": {
                        "text": "uses: actions/checkout@v3\n"
                      },
                      "sourceLanguage": "yaml",
                      "startColumn": 9,
                      "startLine": 6
                    }
                  }
                }
              ],
              "message": {
                "text": "credential persistence through GitHub Actions artifacts"
              },
              "properties": {
                "zizmor/confidence": "Low",
                "zizmor/persona": "Regular",
                "zizmor/severity": "Medium"
              },
              "ruleId": "zizmor/artipacked"
            },
            {
              "codeFlows": [
                {
                  "threadFlows": [
                    {
                      "locations": [
                        {
                          "importance": "important",
                          "location": {
                            "logicalLocations": [
                              {
                                "properties": {
                                  "symbolic": {
                                    "annotation": "this job",
                                    "feature_kind": "Normal",
                                    "key": {
                                      "Stdin": {}
                                    },
                                    "kind": "Related",
                                    "route": {
                                      "route": [
                                        {
                                          "Key": "jobs"
                                        },
                                        {
                                          "Key": "test"
                                        }
                                      ]
                                    }
                                  }
                                }
                              }
                            ],
                            "message": {
                              "text": "this job"
                            },
                            "physicalLocation": {
                              "artifactLocation": {
                                "uri": "<stdin>"
                              },
                              "region": {
                                "endColumn": 1,
                                "endLine": 7,
                                "snippet": {
                                  "text": "  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v3\n"
                                },
                                "sourceLanguage": "yaml",
                                "startColumn": 3,
                                "startLine": 3
                              }
                            }
                          }
                        },
                        {
                          "importance": "essential",
                          "location": {
                            "logicalLocations": [
                              {
                                "properties": {
                                  "symbolic": {
                                    "annotation": "default permissions used due to no permissions: block",
                                    "feature_kind": "Normal",
                                    "key": {
                                      "Stdin": {}
                                    },
                                    "kind": "Primary",
                                    "route": {
                                      "route": [
                                        {
                                          "Key": "jobs"
                                        },
                                        {
                                          "Key": "test"
                                        }
                                      ]
                                    }
                                  }
                                }
                              }
                            ],
                            "message": {
                              "text": "default permissions used due to no permissions: block"
                            },
                            "physicalLocation": {
                              "artifactLocation": {
                                "uri": "<stdin>"
                              },
                              "region": {
                                "endColumn": 1,
                                "endLine": 7,
                                "snippet": {
                                  "text": "  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v3\n"
                                },
                                "sourceLanguage": "yaml",
                                "startColumn": 3,
                                "startLine": 3
                              }
                            }
                          }
                        }
                      ]
                    }
                  ]
                }
              ],
              "kind": "fail",
              "level": "warning",
              "locations": [
                {
                  "logicalLocations": [
                    {
                      "properties": {
                        "symbolic": {
                          "annotation": "default permissions used due to no permissions: block",
                          "feature_kind": "Normal",
                          "key": {
                            "Stdin": {}
                          },
                          "kind": "Primary",
                          "route": {
                            "route": [
                              {
                                "Key": "jobs"
                              },
                              {
                                "Key": "test"
                              }
                            ]
                          }
                        }
                      }
                    }
                  ],
                  "message": {
                    "text": "default permissions used due to no permissions: block"
                  },
                  "physicalLocation": {
                    "artifactLocation": {
                      "uri": "<stdin>"
                    },
                    "region": {
                      "endColumn": 1,
                      "endLine": 7,
                      "snippet": {
                        "text": "  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v3\n"
                      },
                      "sourceLanguage": "yaml",
                      "startColumn": 3,
                      "startLine": 3
                    }
                  }
                }
              ],
              "message": {
                "text": "overly broad permissions"
              },
              "properties": {
                "zizmor/confidence": "Medium",
                "zizmor/persona": "Regular",
                "zizmor/severity": "Medium"
              },
              "ruleId": "zizmor/excessive-permissions"
            },
            {
              "codeFlows": [
                {
                  "threadFlows": [
                    {
                      "locations": [
                        {
                          "importance": "essential",
                          "location": {
                            "logicalLocations": [
                              {
                                "properties": {
                                  "symbolic": {
                                    "annotation": "action is not pinned to a hash (required by blanket policy)",
                                    "feature_kind": {
                                      "Subfeature": {
                                        "after": 0,
                                        "fragment": {
                                          "Raw": "actions/checkout@v3"
                                        }
                                      }
                                    },
                                    "key": {
                                      "Stdin": {}
                                    },
                                    "kind": "Primary",
                                    "route": {
                                      "route": [
                                        {
                                          "Key": "jobs"
                                        },
                                        {
                                          "Key": "test"
                                        },
                                        {
                                          "Key": "steps"
                                        },
                                        {
                                          "Index": 0
                                        },
                                        {
                                          "Key": "uses"
                                        }
                                      ]
                                    }
                                  }
                                }
                              }
                            ],
                            "message": {
                              "text": "action is not pinned to a hash (required by blanket policy)"
                            },
                            "physicalLocation": {
                              "artifactLocation": {
                                "uri": "<stdin>"
                              },
                              "region": {
                                "endColumn": 34,
                                "endLine": 6,
                                "snippet": {
                                  "text": "actions/checkout@v3"
                                },
                                "sourceLanguage": "yaml",
                                "startColumn": 15,
                                "startLine": 6
                              }
                            }
                          }
                        }
                      ]
                    }
                  ]
                }
              ],
              "kind": "fail",
              "level": "error",
              "locations": [
                {
                  "logicalLocations": [
                    {
                      "properties": {
                        "symbolic": {
                          "annotation": "action is not pinned to a hash (required by blanket policy)",
                          "feature_kind": {
                            "Subfeature": {
                              "after": 0,
                              "fragment": {
                                "Raw": "actions/checkout@v3"
                              }
                            }
                          },
                          "key": {
                            "Stdin": {}
                          },
                          "kind": "Primary",
                          "route": {
                            "route": [
                              {
                                "Key": "jobs"
                              },
                              {
                                "Key": "test"
                              },
                              {
                                "Key": "steps"
                              },
                              {
                                "Index": 0
                              },
                              {
                                "Key": "uses"
                              }
                            ]
                          }
                        }
                      }
                    }
                  ],
                  "message": {
                    "text": "action is not pinned to a hash (required by blanket policy)"
                  },
                  "physicalLocation": {
                    "artifactLocation": {
                      "uri": "<stdin>"
                    },
                    "region": {
                      "endColumn": 34,
                      "endLine": 6,
                      "snippet": {
                        "text": "actions/checkout@v3"
                      },
                      "sourceLanguage": "yaml",
                      "startColumn": 15,
                      "startLine": 6
                    }
                  }
                }
              ],
              "message": {
                "text": "unpinned action reference"
              },
              "properties": {
                "zizmor/confidence": "High",
                "zizmor/persona": "Regular",
                "zizmor/severity": "High"
              },
              "ruleId": "zizmor/unpinned-uses"
            }
          ],
          "tool": {
            "driver": {
              "downloadUri": "https://github.com/zizmorcore/zizmor",
              "informationUri": "https://docs.zizmor.sh",
              "name": "zizmor",
              "rules": [
                {
                  "help": {
                    "markdown": "`artipacked`: credential persistence through GitHub Actions artifacts\n\nDocs: <https://docs.zizmor.sh/audits/#artipacked>",
                    "text": "credential persistence through GitHub Actions artifacts"
                  },
                  "helpUri": "https://docs.zizmor.sh/audits/#artipacked",
                  "id": "zizmor/artipacked",
                  "name": "artipacked",
                  "properties": {
                    "tags": [
                      "security"
                    ]
                  }
                },
                {
                  "help": {
                    "markdown": "`excessive-permissions`: overly broad permissions\n\nDocs: <https://docs.zizmor.sh/audits/#excessive-permissions>",
                    "text": "overly broad permissions"
                  },
                  "helpUri": "https://docs.zizmor.sh/audits/#excessive-permissions",
                  "id": "zizmor/excessive-permissions",
                  "name": "excessive-permissions",
                  "properties": {
                    "tags": [
                      "security"
                    ]
                  }
                },
                {
                  "help": {
                    "markdown": "`unpinned-uses`: unpinned action reference\n\nDocs: <https://docs.zizmor.sh/audits/#unpinned-uses>",
                    "text": "unpinned action reference"
                  },
                  "helpUri": "https://docs.zizmor.sh/audits/#unpinned-uses",
                  "id": "zizmor/unpinned-uses",
                  "name": "unpinned-uses",
                  "properties": {
                    "tags": [
                      "security"
                    ]
                  }
                }
              ],
              "semanticVersion": "@@VERSION@@",
              "version": "@@VERSION@@"
            }
          }
        }
      ],
      "version": "2.1.0"
    }
    "#);

    Ok(())
}

/// Test that valid YAML matching no known schema produces a collection error.
#[test]
fn test_stdin_valid_yaml_unknown_schema() -> anyhow::Result<()> {
    let unknown = "foo: bar\nbaz: 42\n";
    insta::assert_snapshot!(
        zizmor()
            .stdin(unknown)
            .no_config(true)
            .expects_failure(3)
            .args(["-"])
            .run()?,
        @"
     INFO zizmor: 🌈 zizmor v@@VERSION@@
     WARN collect_inputs: zizmor::registry::input: stdin: could not parse as any known input type
    fatal: no audit was performed
    error: no inputs collected
      |
      = help: collection yielded no auditable inputs
      = help: inputs must contain at least one valid workflow, action, or Dependabot config

    Caused by:
        no inputs collected
    "
    );

    Ok(())
}

/// Test that valid YAML matching no known schema fails in strict mode.
#[test]
fn test_stdin_valid_yaml_unknown_schema_strict() -> anyhow::Result<()> {
    let unknown = "foo: bar\nbaz: 42\n";
    insta::assert_snapshot!(
        zizmor()
            .stdin(unknown)
            .no_config(true)
            .expects_failure(3)
            .args(["--strict-collection", "-"])
            .run()?,
        @"
     INFO zizmor: 🌈 zizmor v@@VERSION@@
     WARN collect_inputs: zizmor::registry::input: stdin: could not parse as any known input type
    fatal: no audit was performed
    error: no inputs collected
      |
      = help: collection yielded no auditable inputs
      = help: inputs must contain at least one valid workflow, action, or Dependabot config

    Caused by:
        no inputs collected
    "
    );

    Ok(())
}
