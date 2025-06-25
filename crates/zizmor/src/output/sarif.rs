//! SARIF output.

use std::collections::HashSet;

use serde_sarif::sarif::{
    ArtifactContent, ArtifactLocation, Invocation, Location as SarifLocation, LogicalLocation,
    Message, MultiformatMessageString, PhysicalLocation, PropertyBag, Region, ReportingDescriptor,
    Result as SarifResult, ResultKind, ResultLevel, Run, Sarif, Tool, ToolComponent,
};

use crate::finding::{Finding, Severity, location::Location};

impl From<Severity> for ResultKind {
    fn from(value: Severity) -> Self {
        // TODO: Does this mapping make sense?
        match value {
            Severity::Unknown => ResultKind::Review,
            Severity::Informational => ResultKind::Review,
            Severity::Low => ResultKind::Fail,
            Severity::Medium => ResultKind::Fail,
            Severity::High => ResultKind::Fail,
        }
    }
}

impl From<Severity> for ResultLevel {
    fn from(value: Severity) -> Self {
        // TODO: Does this mapping make sense?
        match value {
            Severity::Unknown => ResultLevel::None,
            Severity::Informational => ResultLevel::Note,
            Severity::Low => ResultLevel::Warning,
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

    SarifResult::builder()
        .rule_id(format!("zizmor/{id}", id = finding.ident))
        // NOTE: Between 1.4.0 and 1.9.0 we used the primary location's
        // annotation for the message here. This produced a _slightly_
        // nicer message in some cases, but also produced meaningless
        // code security alert titles when the primary annotation was
        // terse. So now we use the finding's description again, like
        // we did before 1.4.0.
        .message(finding.desc)
        .locations(build_locations(std::iter::once(primary)))
        // TODO: Evaluate including the related locations via CodeFlows
        // instead -- GitHub seems to do a better job of rendering these,
        // but still doesn't do a great job of putting all of the locations
        // into the same render.
        // TODO: Give related locations IDs and back-link to them in the
        // main location's message -- GitHub renders these as modals that
        // users can click through to see more context.
        .related_locations(build_locations(
            finding
                .visible_locations()
                .filter(|l| !l.symbolic.is_primary()),
        ))
        .level(ResultLevel::from(finding.determinations.severity))
        .kind(ResultKind::from(finding.determinations.severity))
        .build()
}

fn build_locations<'a>(locations: impl Iterator<Item = &'a Location<'a>>) -> Vec<SarifLocation> {
    locations
        .map(|location| {
            SarifLocation::builder()
                .logical_locations([LogicalLocation::builder()
                    .properties(
                        PropertyBag::builder()
                            .additional_properties([(
                                "symbolic".into(),
                                serde_json::value::to_value(location.symbolic.clone()).unwrap(),
                            )])
                            .build(),
                    )
                    .build()])
                .physical_location(
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
                                .start_column(
                                    (location.concrete.location.start_point.column as i64) + 1,
                                )
                                .end_column(
                                    (location.concrete.location.end_point.column as i64) + 1,
                                )
                                .source_language("yaml")
                                .snippet(
                                    ArtifactContent::builder()
                                        .text(location.concrete.feature)
                                        .build(),
                                )
                                .build(),
                        )
                        .build(),
                )
                .message(
                    Message::builder()
                        .text(&location.symbolic.annotation)
                        .build(),
                )
                .build()
        })
        .collect()
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
