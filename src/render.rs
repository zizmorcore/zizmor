use crate::{
    finding::{Finding, Severity},
    registry::WorkflowRegistry,
};
use annotate_snippets::{Level, Renderer, Snippet};
use anstream::println;

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

pub(crate) fn finding_snippets<'w>(
    registry: &'w WorkflowRegistry,
    finding: &'w Finding<'w>,
) -> Vec<Snippet<'w>> {
    finding
        .locations
        .iter()
        .map(|location| {
            let workflow = registry.get_workflow(location.symbolic.name);

            let source = location.concrete.parent_feature;
            // Our internal spans are absolute, so we have to recompute
            // the span here to be relative to its parent feature.
            let span_start = source
                .find(location.concrete.feature)
                .expect("impossible: extracted feature and parent diverge");
            let span_end = span_start + location.concrete.feature.as_bytes().len();

            Snippet::source(&source)
                .fold(false)
                .line_start(location.concrete.parent_location.start_point.row + 1)
                .origin(&workflow.path)
                .annotation(
                    Level::from(&finding.determinations.severity)
                        .span(span_start..span_end)
                        .label(&location.symbolic.annotation),
                )
        })
        .collect()
}

pub(crate) fn render_findings(registry: &WorkflowRegistry, findings: &[Finding]) {
    for finding in findings {
        render_finding(registry, finding);
        println!();
    }
}

fn render_finding(registry: &WorkflowRegistry, finding: &Finding) {
    let message = Level::from(&finding.determinations.severity)
        .title(finding.desc)
        .id(finding.ident)
        .snippets(finding_snippets(registry, finding));

    let renderer = Renderer::styled();
    println!("{}", renderer.render(message));
}
