//! SARIF output.

use std::collections::{BTreeMap, HashSet};

use zizmor_sarif::{
    ArtifactContent, ArtifactLocation, CodeFlow, Invocation, Location as SarifLocation,
    LogicalLocation, Message, MultiformatMessageString, PhysicalLocation, PropertyBag, Region,
    ReportingDescriptor, Result as SarifResult, ResultKind, ResultLevel, Run, Sarif, ThreadFlow,
    ThreadFlowLocation, ThreadFlowLocationImportance, Tool, ToolComponent,
};

use crate::finding::{Finding, Severity, location::Location};

impl From<Severity> for ResultKind {
    fn from(value: Severity) -> Self {
        // TODO: Does this mapping make sense?
        match value {
            Severity::Informational => ResultKind::Review,
            Severity::Low => ResultKind::Fail,
            Severity::Medium => ResultKind::Fail,
            Severity::High => ResultKind::Fail,
        }
    }
}

impl From<Severity> for ResultLevel {
    fn from(value: Severity) -> Self {
        match value {
            Severity::Informational => ResultLevel::Note,
            Severity::Low => ResultLevel::Note,
            Severity::Medium => ResultLevel::Warning,
            Severity::High => ResultLevel::Error,
        }
    }
}

pub(crate) fn build(findings: &[Finding]) -> Sarif {
    Sarif {
        schema: Some(
            "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
                .into(),
        ),
        runs: vec![build_run(findings)],
        version: "2.1.0".into(),
    }
}

fn build_run(findings: &[Finding]) -> Run {
    Run {
        invocations: vec![Invocation {
            // We only produce results on successful executions.
            execution_successful: true,
        }],
        results: build_results(findings),
        tool: Tool {
            driver: ToolComponent {
                download_uri: Some(env!("CARGO_PKG_REPOSITORY").into()),
                information_uri: Some(env!("CARGO_PKG_HOMEPAGE").into()),
                name: env!("CARGO_CRATE_NAME").into(),
                rules: build_rules(findings),
                semantic_version: Some(env!("CARGO_PKG_VERSION").into()),
                version: Some(env!("CARGO_PKG_VERSION").into()),
            },
        },
    }
}

fn build_rules(findings: &[Finding]) -> Vec<ReportingDescriptor> {
    // use the set to filter out duplicate rules
    let mut unique_rules = HashSet::new();
    findings
        .iter()
        .filter(|finding| unique_rules.insert(finding.ident))
        .map(|finding| build_rule(finding))
        .collect()
}

fn build_rule(finding: &Finding) -> ReportingDescriptor {
    ReportingDescriptor {
        help: Some(MultiformatMessageString {
            markdown: Some(finding.to_markdown()),
            text: finding.desc.into(),
        }),
        help_uri: Some(finding.url.into()),
        id: format!("zizmor/{id}", id = finding.ident),
        name: Some(finding.ident.into()),
        properties: Some(PropertyBag {
            tags: vec!["security".into()],
            additional_properties: BTreeMap::new(),
        }),
    }
}

fn build_results(findings: &[Finding]) -> Vec<SarifResult> {
    findings.iter().map(build_result).collect()
}

fn build_result(finding: &Finding<'_>) -> SarifResult {
    let primary = finding.primary_location();

    // Build code flows for better visualization of location chains.
    // GitHub renders these as step-by-step traces in security alerts.
    let thread_flow_locations: Vec<ThreadFlowLocation> = finding
        .visible_locations()
        .map(|loc| {
            let importance = if loc.symbolic.is_primary() {
                ThreadFlowLocationImportance::Essential
            } else {
                ThreadFlowLocationImportance::Important
            };
            ThreadFlowLocation {
                importance: Some(importance),
                location: build_location(loc, None),
            }
        })
        .collect();
    let code_flows = vec![CodeFlow {
        thread_flows: vec![ThreadFlow {
            locations: thread_flow_locations,
        }],
    }];

    let mut additional_properties = BTreeMap::new();
    additional_properties.insert(
        "zizmor/confidence".into(),
        serde_json::value::to_value(finding.determinations.confidence)
            .expect("failed to serialize confidence"),
    );
    additional_properties.insert(
        "zizmor/severity".into(),
        serde_json::value::to_value(finding.determinations.severity)
            .expect("failed to serialize severity"),
    );
    additional_properties.insert(
        "zizmor/persona".into(),
        serde_json::value::to_value(finding.determinations.persona)
            .expect("failed to serialize persona"),
    );

    SarifResult {
        code_flows,
        kind: Some(ResultKind::from(finding.determinations.severity)),
        level: Some(ResultLevel::from(finding.determinations.severity)),
        locations: vec![build_location(primary, None)],
        // NOTE: Between 1.4.0 and 1.9.0 we used the primary location's
        // annotation for the message here. This produced a _slightly_
        // nicer message in some cases, but also produced meaningless
        // code security alert titles when the primary annotation was
        // terse. So now we use the finding's description again, like
        // we did before 1.4.0.
        message: Message {
            text: format!(
                "{desc}: {annotation}",
                desc = finding.desc,
                annotation = primary.symbolic.annotation
            ),
        },
        properties: Some(PropertyBag {
            tags: vec![],
            additional_properties,
        }),
        rule_id: Some(format!("zizmor/{id}", id = finding.ident)),
    }
}

fn build_physical_location(location: &Location<'_>) -> PhysicalLocation {
    PhysicalLocation {
        artifact_location: ArtifactLocation {
            uri: location.symbolic.key.best_relative_path().into(),
        },
        region: Region {
            // NOTE: SARIF lines/columns are 1-based.
            end_column: (location.concrete.location.end_point.column as i64) + 1,
            end_line: (location.concrete.location.end_point.row as i64) + 1,
            snippet: ArtifactContent {
                text: location.concrete.feature.into(),
            },
            source_language: "yaml".into(),
            start_column: (location.concrete.location.start_point.column as i64) + 1,
            start_line: (location.concrete.location.start_point.row as i64) + 1,
        },
    }
}

fn build_logical_locations(location: &Location<'_>) -> Vec<LogicalLocation> {
    let mut additional_properties = BTreeMap::new();
    additional_properties.insert(
        "symbolic".into(),
        serde_json::value::to_value(location.symbolic.clone())
            .expect("failed to serialize symbolic location"),
    );
    vec![LogicalLocation {
        properties: Some(PropertyBag {
            tags: vec![],
            additional_properties,
        }),
    }]
}

fn build_location(location: &Location<'_>, id: Option<i64>) -> SarifLocation {
    SarifLocation {
        id,
        logical_locations: build_logical_locations(location),
        message: Some(Message {
            text: location.symbolic.annotation.as_ref().into(),
        }),
        physical_location: Some(build_physical_location(location)),
    }
}

#[cfg(test)]
mod tests {
    use zizmor_sarif::ResultKind;

    use crate::finding::Severity;

    #[test]
    fn test_resultkind_from_severity() {
        assert_eq!(
            serde_json::to_string(&ResultKind::from(Severity::High)).unwrap(),
            "\"fail\""
        );
    }
}
