//! APIs for rendering SARIF outputs.

use serde_sarif::sarif::{
    ArtifactContent, ArtifactLocation, Location as SarifLocation, LogicalLocation, Message,
    PhysicalLocation, PropertyBag, Region, Result as SarifResult, Run, Sarif, Tool, ToolComponent,
};

use crate::finding::{Finding, Location};

pub(crate) fn build(findings: Vec<Finding<'_>>) -> Sarif {
    Sarif::builder()
        .version("2.1.0")
        .schema("https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-external-property-file-schema-2.1.0.json")
        .runs([build_run(findings)])
        .build()
}

fn build_run(findings: Vec<Finding<'_>>) -> Run {
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
                        .build(),
                )
                .build(),
        )
        .results(build_results(findings))
        .build()
}

fn build_results(findings: Vec<Finding<'_>>) -> Vec<SarifResult> {
    findings.iter().map(|f| build_result(f)).collect()
}

fn build_result(finding: &Finding<'_>) -> SarifResult {
    SarifResult::builder()
        .message(finding.ident)
        .rule_id(finding.ident)
        .locations(build_locations(&finding.locations))
        .build()
}

fn build_locations(locations: &[Location<'_>]) -> Vec<SarifLocation> {
    locations
        .iter()
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
                                .uri(location.symbolic.name)
                                .uri_base_id("%workflows%")
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
