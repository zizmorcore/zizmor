//! Minimal in-tree data models for [SARIF 2.1.0].
//!
//! Only the subset of SARIF that `zizmor` actually emits is modelled.
//!
//! [SARIF 2.1.0]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

use std::collections::BTreeMap;

use serde::Serialize;

/// Top-level SARIF log object (SARIF §3.13).
#[derive(Debug, Clone, Serialize)]
pub struct Sarif {
    #[serde(rename = "$schema", skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub runs: Vec<Run>,
    pub version: String,
}

/// A single tool invocation's results (SARIF §3.14).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Run {
    pub invocations: Vec<Invocation>,
    pub results: Vec<Result>,
    pub tool: Tool,
}

/// Tool metadata wrapper (SARIF §3.18).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    pub driver: ToolComponent,
}

/// Tool driver metadata (SARIF §3.19).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolComponent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub information_uri: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<ReportingDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Invocation describing the tool execution (SARIF §3.20).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Invocation {
    pub execution_successful: bool,
}

/// A reporting descriptor, i.e. a rule definition (SARIF §3.49).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportingDescriptor {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<MultiformatMessageString>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<PropertyBag>,
}

/// Plain-text + markdown message (SARIF §3.12).
#[derive(Debug, Clone, Serialize)]
pub struct MultiformatMessageString {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub markdown: Option<String>,
    pub text: String,
}

/// Property bag (SARIF §3.8).
#[derive(Debug, Clone, Default, Serialize)]
pub struct PropertyBag {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(flatten)]
    pub additional_properties: BTreeMap<String, serde_json::Value>,
}

/// A single finding within a run (SARIF §3.27).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Result {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub code_flows: Vec<CodeFlow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<ResultKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<ResultLevel>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<Location>,
    pub message: Message,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<PropertyBag>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
}

/// A human-readable message (SARIF §3.11).
#[derive(Debug, Clone, Serialize)]
pub struct Message {
    pub text: String,
}

/// A location (SARIF §3.28).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub logical_locations: Vec<LogicalLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physical_location: Option<PhysicalLocation>,
}

/// A logical location (SARIF §3.33).
#[derive(Debug, Clone, Serialize)]
pub struct LogicalLocation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<PropertyBag>,
}

/// A physical location (SARIF §3.29).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhysicalLocation {
    pub artifact_location: ArtifactLocation,
    pub region: Region,
}

/// Pointer to a single artifact (SARIF §3.4).
#[derive(Debug, Clone, Serialize)]
pub struct ArtifactLocation {
    pub uri: String,
}

/// A region within an artifact (SARIF §3.30).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Region {
    pub end_column: i64,
    pub end_line: i64,
    pub snippet: ArtifactContent,
    pub source_language: String,
    pub start_column: i64,
    pub start_line: i64,
}

/// The literal contents of a region (SARIF §3.3).
#[derive(Debug, Clone, Serialize)]
pub struct ArtifactContent {
    pub text: String,
}

/// A code flow (SARIF §3.36) — a sequence of [`ThreadFlow`]s.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeFlow {
    pub thread_flows: Vec<ThreadFlow>,
}

/// A thread flow (SARIF §3.37).
#[derive(Debug, Clone, Serialize)]
pub struct ThreadFlow {
    pub locations: Vec<ThreadFlowLocation>,
}

/// A location within a thread flow (SARIF §3.38).
#[derive(Debug, Clone, Serialize)]
pub struct ThreadFlowLocation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub importance: Option<ThreadFlowLocationImportance>,
    pub location: Location,
}

/// Classification of a result (SARIF §3.27.9). Serialized as a lowercase
/// string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ResultKind {
    NotApplicable,
    Pass,
    Fail,
    Review,
    Open,
    Informational,
}

/// Severity of a result (SARIF §3.27.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ResultLevel {
    None,
    Note,
    Warning,
    Error,
}

/// Importance of a thread-flow location (SARIF §3.38.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreadFlowLocationImportance {
    Essential,
    Important,
    Unimportant,
}

#[cfg(test)]
mod tests {
    use crate::{
        ArtifactContent, ArtifactLocation, Invocation, Location, Message, PhysicalLocation,
        PropertyBag, Region, ReportingDescriptor, Result, ResultKind, ResultLevel, Run, Sarif,
        ThreadFlowLocationImportance, Tool, ToolComponent,
    };

    /// Minimal end-to-end serialization.
    #[test]
    fn serializes_minimal_document_in_expected_shape() {
        let sarif = Sarif {
            schema: Some("https://example/schema".into()),
            runs: vec![Run {
                invocations: vec![Invocation {
                    execution_successful: true,
                }],
                results: vec![Result {
                    code_flows: vec![],
                    kind: Some(ResultKind::Fail),
                    level: Some(ResultLevel::Error),
                    locations: vec![Location {
                        id: None,
                        logical_locations: vec![],
                        message: Some(Message {
                            text: "primary".into(),
                        }),
                        physical_location: Some(PhysicalLocation {
                            artifact_location: ArtifactLocation {
                                uri: "wf.yml".into(),
                            },
                            region: Region {
                                end_column: 2,
                                end_line: 3,
                                snippet: ArtifactContent { text: "x".into() },
                                source_language: "yaml".into(),
                                start_column: 1,
                                start_line: 2,
                            },
                        }),
                    }],
                    message: Message { text: "msg".into() },
                    properties: None,
                    rule_id: Some("zizmor/example".into()),
                }],
                tool: Tool {
                    driver: ToolComponent {
                        download_uri: None,
                        information_uri: None,
                        name: "zizmor".into(),
                        rules: vec![ReportingDescriptor {
                            help: None,
                            help_uri: None,
                            id: "zizmor/example".into(),
                            name: Some("example".into()),
                            properties: Some(PropertyBag {
                                tags: vec!["security".into()],
                                additional_properties: Default::default(),
                            }),
                        }],
                        semantic_version: None,
                        version: None,
                    },
                },
            }],
            version: "2.1.0".into(),
        };

        // Use compact serialization for the assertion so we test key order
        // independent of pretty-printer whitespace.
        let json = serde_json::to_string(&sarif).expect("serialization failed");
        let expected = r#"{"$schema":"https://example/schema","runs":[{"invocations":[{"executionSuccessful":true}],"results":[{"kind":"fail","level":"error","locations":[{"message":{"text":"primary"},"physicalLocation":{"artifactLocation":{"uri":"wf.yml"},"region":{"endColumn":2,"endLine":3,"snippet":{"text":"x"},"sourceLanguage":"yaml","startColumn":1,"startLine":2}}}],"message":{"text":"msg"},"ruleId":"zizmor/example"}],"tool":{"driver":{"name":"zizmor","rules":[{"id":"zizmor/example","name":"example","properties":{"tags":["security"]}}]}}}],"version":"2.1.0"}"#;
        assert_eq!(json, expected);
    }

    #[test]
    fn importance_serializes_as_lowercase_string() {
        assert_eq!(
            serde_json::to_string(&ThreadFlowLocationImportance::Essential)
                .expect("serialization failed"),
            "\"essential\""
        );
        assert_eq!(
            serde_json::to_string(&ThreadFlowLocationImportance::Important)
                .expect("serialization failed"),
            "\"important\""
        );
    }
}
