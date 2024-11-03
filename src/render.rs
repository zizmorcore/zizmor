//! APIs for rendering zizmor's "plain" (i.e. terminal) output format.

use std::collections::{hash_map::Entry, HashMap};

use crate::{
    finding::{Finding, Location, Severity},
    registry::WorkflowRegistry,
};
use annotate_snippets::{Level, Renderer, Snippet};
use anstream::println;
use owo_colors::OwoColorize;
use terminal_link::Link;

impl From<&Severity> for Level {
    fn from(sev: &Severity) -> Self {
        match sev {
            Severity::Unknown => Level::Note,
            Severity::Informational => Level::Info,
            Severity::Low => Level::Help,
            Severity::Medium => Level::Warning,
            Severity::High => Level::Error,
        }
    }
}

pub(crate) fn finding_snippet<'w>(
    registry: &'w WorkflowRegistry,
    finding: &'w Finding<'w>,
) -> Vec<Snippet<'w>> {
    // Our finding might span multiple workflows, so we need to group locations
    // by their enclosing workflow to generate each snippet correctly.
    let mut locations_by_workflow: HashMap<&str, Vec<&Location<'w>>> = HashMap::new();
    for location in &finding.locations {
        match locations_by_workflow.entry(location.symbolic.name) {
            Entry::Occupied(mut e) => {
                e.get_mut().push(location);
            }
            Entry::Vacant(e) => {
                e.insert(vec![location]);
            }
        }
    }

    let mut snippets = vec![];
    for (workflow_name, locations) in locations_by_workflow {
        let workflow = registry.get_workflow(workflow_name);

        snippets.push(
            Snippet::source(workflow.document.source())
                .fold(true)
                .line_start(1)
                .origin(&workflow.path)
                .annotations(locations.iter().map(|loc| {
                    let annotation = match loc.symbolic.link {
                        Some(ref link) => link,
                        None => &loc.symbolic.annotation,
                    };

                    Level::from(&finding.determinations.severity)
                        .span(loc.concrete.location.start_offset..loc.concrete.location.end_offset)
                        .label(annotation)
                })),
        );
    }

    snippets
}

pub(crate) fn render_findings(
    registry: &WorkflowRegistry,
    findings: &[Finding],
    ignored: &[Finding],
) {
    for finding in findings {
        render_finding(registry, finding);
        println!();
    }

    if findings.is_empty() {
        println!("{}", "No findings to report. Good job!".green());
    } else {
        let mut findings_by_severity = HashMap::new();

        for finding in findings {
            match findings_by_severity.entry(&finding.determinations.severity) {
                Entry::Occupied(mut e) => {
                    *e.get_mut() += 1;
                }
                Entry::Vacant(e) => {
                    e.insert(1);
                }
            }
        }

        println!(
            "{nfindings} findings ({nignored} ignored): {nunknown} unknown, {ninformational} informational, {nlow} low, {nmedium} medium, {nhigh} high",
            nfindings = (findings.len() + ignored.len()).green(),
            nignored = ignored.len().bright_yellow(),
            nunknown = findings_by_severity.get(&Severity::Unknown).unwrap_or(&0),
            ninformational = findings_by_severity.get(&Severity::Informational).unwrap_or(&0).purple(),
            nlow = findings_by_severity.get(&Severity::Low).unwrap_or(&0).cyan(),
            nmedium = findings_by_severity.get(&Severity::Medium).unwrap_or(&0).yellow(),
            nhigh = findings_by_severity.get(&Severity::High).unwrap_or(&0).red(),
        );
    }
}

fn render_finding(registry: &WorkflowRegistry, finding: &Finding) {
    let link = Link::new(finding.ident, &finding.url()).to_string();

    let message = Level::from(&finding.determinations.severity)
        .title(finding.desc)
        .id(&link)
        .snippets(finding_snippet(registry, finding));

    let renderer = Renderer::styled();
    println!("{}", renderer.render(message));
}
