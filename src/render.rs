use std::collections::{hash_map::Entry, HashMap};

use crate::{
    finding::{Finding, Location, Severity},
    registry::WorkflowRegistry,
};
use annotate_snippets::{Level, Renderer, Snippet};
use anstream::println;
use owo_colors::OwoColorize;

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
                    Level::from(&finding.determinations.severity)
                        .span(loc.concrete.location.start_offset..loc.concrete.location.end_offset)
                        .label(&loc.symbolic.annotation)
                })),
        );
    }

    snippets
}

pub(crate) fn render_findings(registry: &WorkflowRegistry, findings: &[Finding]) {
    for finding in findings {
        render_finding(registry, finding);
        println!();
    }

    if findings.is_empty() {
        println!("{}", "No findings to report. Good job!".green());
    } else {
        //
    }
}

fn render_finding(registry: &WorkflowRegistry, finding: &Finding) {
    let message = Level::from(&finding.determinations.severity)
        .title(finding.desc)
        .id(finding.ident)
        .snippets(finding_snippet(registry, finding));

    let renderer = Renderer::styled();
    println!("{}", renderer.render(message));
}
