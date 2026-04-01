//! SARIF output.

use std::collections::HashSet;

use serde_sarif::sarif::{
    ArtifactContent, ArtifactLocation, CodeFlow, Invocation, Location as SarifLocation,
    LogicalLocation, Message, MultiformatMessageString, PhysicalLocation, PropertyBag, Region,
    ReportingDescriptor, Result as SarifResult, ResultKind, ResultLevel, Run, Sarif, ThreadFlow,
    ThreadFlowLocation, Tool, ToolComponent,
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
    Sarif::builder()
        .version("2.1.0")
        .schema("https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json")
        .runs([build_run(findings)])
        .build()
}

fn build_run(findings: &[Finding]) -> Run {
    Run::builder()
        .tool(
            Tool::builder()
                .driver(
                    ToolComponent::builder()
                        .name(env!("CARGO_CRATE_NAME"))
                        .version(env!("CARGO_PKG_VERSION"))
                        .semantic_version(env!("CARGO_PKG_VERSION"))
                        .download_uri(env!("CARGO_PKG_REPOSITORY"))
                        .information_uri(env!("CARGO_PKG_HOMEPAGE"))
                        .rules(build_rules(findings))
                        .build(),
                )
                .build(),
        )
        .results(build_results(findings))
        .invocations([Invocation::builder()
            // We only produce results on successful executions.
            .execution_successful(true)
            .build()])
        .build()
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
    ReportingDescriptor::builder()
        .id(format!("zizmor/{id}", id = finding.ident))
        .name(finding.ident)
        .help_uri(finding.url)
        .help(
            MultiformatMessageString::builder()
                .text(finding.desc)
                .markdown(finding.to_markdown())
                .build(),
        )
        .properties(PropertyBag::builder().tags(["security".into()]).build())
        .build()
}

fn build_results(findings: &[Finding]) -> Vec<SarifResult> {
    findings.iter().map(|f| build_result(f)).collect()
}

fn build_result(finding: &Finding<'_>) -> SarifResult {
    let primary = finding.primary_location();
    let related: Vec<_> = finding
        .visible_locations()
        .filter(|l| !l.symbolic.is_primary())
        .collect();

    // Build the message with back-links to related locations.
    // SARIF embedded links use [text](id) syntax, where id references
    // a related location's integer ID. GitHub renders these as clickable
    // modals that users can click through to see more context.
    let message = if related.is_empty() {
        finding.desc.to_string()
    } else {
        let mut msg = format!("{msg}\n\n via:", msg = finding.desc);
        for (i, loc) in related.iter().enumerate() {
            msg.push_str(&format!(
                "- [{annotation}]({id})",
                annotation = loc.symbolic.annotation.as_ref(),
                id = i + 1
            ));
        }
        msg
    };

    // Build related locations with sequential IDs for back-linking.
    let related_locations: Vec<SarifLocation> = related
        .iter()
        .enumerate()
        .map(|(i, loc)| build_location(loc, Some((i + 1) as i64)))
        .collect();

    // Build code flows for better visualization of location chains.
    // GitHub renders these as step-by-step traces in security alerts.
    let all_locations: Vec<_> = std::iter::once(primary)
        .chain(related.iter().copied())
        .collect();
    let code_flows = if all_locations.len() > 1 {
        let thread_flow_locations: Vec<ThreadFlowLocation> = all_locations
            .iter()
            .map(|loc| {
                let importance = if loc.symbolic.is_primary() {
                    "essential"
                } else {
                    "important"
                };
                ThreadFlowLocation::builder()
                    .location(build_location(loc, None))
                    .importance(serde_json::Value::String(importance.into()))
                    .build()
            })
            .collect();
        vec![
            CodeFlow::builder()
                .thread_flows(vec![
                    ThreadFlow::builder()
                        .locations(thread_flow_locations)
                        .build(),
                ])
                .build(),
        ]
    } else {
        vec![]
    };

    SarifResult::builder()
        .rule_id(format!("zizmor/{id}", id = finding.ident))
        // NOTE: Between 1.4.0 and 1.9.0 we used the primary location's
        // annotation for the message here. This produced a _slightly_
        // nicer message in some cases, but also produced meaningless
        // code security alert titles when the primary annotation was
        // terse. So now we use the finding's description again, like
        // we did before 1.4.0.
        .message(Message::builder().text(message).build())
        .locations(vec![build_location(primary, None)])
        .related_locations(related_locations)
        .code_flows(code_flows)
        .level(ResultLevel::from(finding.determinations.severity))
        .kind(ResultKind::from(finding.determinations.severity))
        .properties(
            PropertyBag::builder()
                .additional_properties([
                    (
                        "zizmor/confidence".into(),
                        serde_json::value::to_value(finding.determinations.confidence)
                            .expect("failed to serialize confidence"),
                    ),
                    (
                        "zizmor/severity".into(),
                        serde_json::value::to_value(finding.determinations.severity)
                            .expect("failed to serialize severity"),
                    ),
                    (
                        "zizmor/persona".into(),
                        serde_json::value::to_value(finding.determinations.persona)
                            .expect("failed to serialize persona"),
                    ),
                ])
                .build(),
        )
        .build()
}

fn build_physical_location(location: &Location<'_>) -> PhysicalLocation {
    PhysicalLocation::builder()
        .artifact_location(
            ArtifactLocation::builder()
                .uri(location.symbolic.key.sarif_path())
                .build(),
        )
        .region(
            Region::builder()
                // NOTE: SARIF lines/columns are 1-based.
                .start_line((location.concrete.location.start_point.row as i64) + 1)
                .end_line((location.concrete.location.end_point.row as i64) + 1)
                .start_column((location.concrete.location.start_point.column as i64) + 1)
                .end_column((location.concrete.location.end_point.column as i64) + 1)
                .source_language("yaml")
                .snippet(
                    ArtifactContent::builder()
                        .text(location.concrete.feature)
                        .build(),
                )
                .build(),
        )
        .build()
}

fn build_logical_locations(location: &Location<'_>) -> Vec<LogicalLocation> {
    vec![
        LogicalLocation::builder()
            .properties(
                PropertyBag::builder()
                    .additional_properties([(
                        "symbolic".into(),
                        serde_json::value::to_value(location.symbolic.clone())
                            .expect("failed to serialize symbolic location"),
                    )])
                    .build(),
            )
            .build(),
    ]
}

fn build_location(location: &Location<'_>, id: Option<i64>) -> SarifLocation {
    let message = Message::builder()
        .text(location.symbolic.annotation.as_ref())
        .build();
    let physical = build_physical_location(location);
    let logical = build_logical_locations(location);

    match id {
        Some(id) => SarifLocation::builder()
            .id(id)
            .logical_locations(logical)
            .physical_location(physical)
            .message(message)
            .build(),
        None => SarifLocation::builder()
            .logical_locations(logical)
            .physical_location(physical)
            .message(message)
            .build(),
    }
}

#[cfg(test)]
mod tests {
    use serde_sarif::sarif::ResultKind;

    use crate::finding::Severity;

    #[test]
    fn test_resultkind_from_severity() {
        assert_eq!(
            serde_json::to_string(&ResultKind::from(Severity::High)).unwrap(),
            "\"fail\""
        );
    }
}
