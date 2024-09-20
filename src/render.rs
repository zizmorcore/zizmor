use crate::finding::{Finding, Location, Severity};
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

impl<'w> From<&'w Location<'w>> for Snippet<'w> {
    fn from(location: &'w Location<'w>) -> Self {
        // TODO: Use the whole-workflow source here so that we can
        // use the actual span below, rather than a span representing
        // the entire extracted feature.
        Snippet::source(location.concrete.feature)
            .line_start(location.concrete.location.start_point.row)
            .origin(&location.symbolic.name)
            .annotation(
                Level::Info
                    .span(0..location.concrete.feature.len())
                    .label(location.symbolic.annotation.as_deref().unwrap_or("lol")),
            )
    }
}

pub(crate) fn render_findings(findings: &[Finding]) {
    for finding in findings {
        render_finding(finding);
        println!();
    }
}

fn render_finding(finding: &Finding) {
    let message = Level::from(&finding.determinations.severity)
        .title(&finding.ident)
        .id(&finding.ident)
        .snippets(finding.locations.iter().map(|l| l.into()));

    let renderer = Renderer::styled();
    println!("{}", renderer.render(message));
}
