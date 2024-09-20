use crate::finding::{Finding, Severity};
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

pub(crate) fn finding_snippets<'w>(finding: &'w Finding<'w>) -> Vec<Snippet<'w>> {
    finding
        .locations
        .iter()
        .map(|location| {
            Snippet::source(dbg!(location.concrete.feature))
                .fold(true)
                .line_start(location.concrete.location.start_point.row)
                .origin(location.symbolic.name)
                .annotation(
                    Level::from(&finding.determinations.severity)
                        .span(0..location.concrete.feature.len())
                        .label(&location.symbolic.annotation),
                )
        })
        .collect()
}

pub(crate) fn render_findings(findings: &[Finding]) {
    for finding in findings {
        render_finding(finding);
        println!();
    }
}

fn render_finding(finding: &Finding) {
    let message = Level::from(&finding.determinations.severity)
        .title(finding.desc)
        .id(finding.ident)
        .snippets(finding_snippets(finding));

    let renderer = Renderer::styled();
    println!("{}", renderer.render(message));
}
