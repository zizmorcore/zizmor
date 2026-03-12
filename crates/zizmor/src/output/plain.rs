//! "plain" (i.e. cargo-style) output.

use std::collections::{HashMap, hash_map::Entry};

use annotate_snippets::{Annotation, AnnotationKind, Group, Level, Renderer, Snippet};
use anstream::{eprintln, print, println};
use owo_colors::OwoColorize;

use crate::{
    RenderLinks, ShowAuditUrls,
    finding::{
        Finding, Severity,
        location::{Location, LocationKind},
    },
    models::AsDocument,
    registry::{
        FindingRegistry,
        input::{InputKey, InputRegistry},
    },
};

impl From<LocationKind> for AnnotationKind {
    fn from(kind: LocationKind) -> Self {
        match kind {
            LocationKind::Primary => AnnotationKind::Primary,
            LocationKind::Related => AnnotationKind::Context,
            // Unreachable because we filter out hidden locations earlier.
            LocationKind::Hidden => unreachable!(),
        }
    }
}

impl From<&Severity> for Level<'_> {
    fn from(sev: &Severity) -> Self {
        match sev {
            Severity::Informational => Level::INFO,
            Severity::Low => Level::HELP,
            Severity::Medium => Level::WARNING,
            Severity::High => Level::ERROR,
        }
    }
}

pub(crate) fn finding_snippets<'doc>(
    registry: &'doc InputRegistry,
    finding: &'doc Finding<'doc>,
    render_links_mode: &RenderLinks,
) -> Vec<Snippet<'doc, Annotation<'doc>>> {
    // Our finding might span multiple workflows, so we need to group locations
    // by their enclosing workflow to generate each snippet correctly.
    let mut locations_by_workflow: HashMap<&InputKey, Vec<&Location<'doc>>> = HashMap::new();
    for location in &finding.locations {
        // Never include hidden locations in the output.
        if location.symbolic.is_hidden() {
            continue;
        }

        match locations_by_workflow.entry(location.symbolic.key) {
            Entry::Occupied(mut e) => {
                e.get_mut().push(location);
            }
            Entry::Vacant(e) => {
                e.insert(vec![location]);
            }
        }
    }

    let mut snippets = vec![];
    for (input_key, locations) in locations_by_workflow {
        let input = registry.get_input(input_key);

        let path = match render_links_mode {
            RenderLinks::Always => input.link().unwrap_or(input_key.presentation_path()),
            RenderLinks::Never => input_key.presentation_path(),
        };

        snippets.push(
            Snippet::source(input.as_document().source())
                .fold(true)
                .line_start(1)
                .path(path)
                .annotations(locations.iter().map(|loc| {
                    let annotation = match (loc.symbolic.link.as_deref(), render_links_mode) {
                        (Some(link), RenderLinks::Always) => link,
                        _ => &loc.symbolic.annotation,
                    };

                    AnnotationKind::from(loc.symbolic.kind)
                        .span(
                            loc.concrete.location.offset_span.start
                                ..loc.concrete.location.offset_span.end,
                        )
                        .label(annotation)
                })),
        );
    }

    snippets
}

pub(crate) fn render_findings(
    registry: &InputRegistry,
    findings: &FindingRegistry,
    show_urls_mode: &ShowAuditUrls,
    render_links_mode: &RenderLinks,
    naches_mode: bool,
    quiet: bool,
) {
    for finding in findings.findings() {
        render_finding(registry, finding, show_urls_mode, render_links_mode);
        println!();
    }

    if !quiet {
        let mut qualifiers = vec![];

        if !findings.ignored().is_empty() {
            qualifiers.push(format!(
                "{nignored} ignored",
                nignored = findings.ignored().len().bright_yellow()
            ));
        }

        if !findings.suppressed().is_empty() {
            qualifiers.push(format!(
                "{nsuppressed} suppressed",
                nsuppressed = findings.suppressed().len().bright_yellow()
            ));
        }

        let nfixable = findings.fixable_findings().count();
        if nfixable > 0 {
            qualifiers.push(format!(
                "{nfixable} fixable",
                nfixable = nfixable.bright_green()
            ));
        }

        if findings.findings().is_empty() {
            if qualifiers.is_empty() {
                println!("{}", "No findings to report. Good job!".green());
            } else {
                println!(
                    "{no_findings} ({qualifiers})",
                    no_findings = "No findings to report. Good job!".green(),
                    qualifiers = qualifiers.join(", ").bold(),
                );
            }

            if naches_mode {
                naches();
            }
        } else {
            let mut findings_by_severity = HashMap::new();

            for finding in findings.findings() {
                match findings_by_severity.entry(&finding.determinations.severity) {
                    Entry::Occupied(mut e) => {
                        *e.get_mut() += 1;
                    }
                    Entry::Vacant(e) => {
                        e.insert(1);
                    }
                }
            }

            if qualifiers.is_empty() {
                let nfindings = findings.count();
                print!(
                    "{nfindings} finding{s}: ",
                    nfindings = nfindings.green(),
                    s = if nfindings == 1 { "" } else { "s" },
                );
            } else {
                print!(
                    "{nfindings} findings ({qualifiers}): ",
                    nfindings = findings.count().green(),
                    qualifiers = qualifiers.join(", ").bold(),
                );
            }

            println!(
                "{ninformational} informational, {nlow} low, {nmedium} medium, {nhigh} high",
                ninformational = findings_by_severity
                    .get(&Severity::Informational)
                    .unwrap_or(&0)
                    .purple(),
                nlow = findings_by_severity
                    .get(&Severity::Low)
                    .unwrap_or(&0)
                    .cyan(),
                nmedium = findings_by_severity
                    .get(&Severity::Medium)
                    .unwrap_or(&0)
                    .yellow(),
                nhigh = findings_by_severity
                    .get(&Severity::High)
                    .unwrap_or(&0)
                    .red(),
            );
        }
    }
}

fn render_finding(
    registry: &InputRegistry,
    finding: &Finding,
    show_urls_mode: &ShowAuditUrls,
    render_links_mode: &RenderLinks,
) {
    let mut title = Level::from(&finding.determinations.severity)
        .primary_title(finding.desc)
        .id(finding.ident);

    if matches!(render_links_mode, RenderLinks::Always) {
        title = title.id_url(finding.url);
    }

    let confidence = format!(
        "audit confidence → {:?}",
        &finding.determinations.confidence
    );

    let mut group = Group::with_title(title)
        .elements(finding_snippets(registry, finding, render_links_mode))
        .element(Level::NOTE.message(confidence));

    if let Some(tip) = &finding.tip {
        group = group.element(Level::HELP.with_name("tip").message(tip));
    }

    if !finding.fixes.is_empty() {
        group = group.element(Level::NOTE.message("this finding has an auto-fix"));
    }

    if matches!(show_urls_mode, ShowAuditUrls::Always) {
        group = group.element(Level::HELP.message(format!(
            "audit documentation → {url}",
            url = finding.url.green()
        )))
    }

    // TODO: Evaluate alternative decor styles.
    let renderer = Renderer::styled();
    println!("{}", renderer.render(&[group]));
}

fn naches() {
    eprintln!(
        "
    ⣿⣿⣿⠟⠋⠙⣉⡉⣉⡙⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⠟⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
    ⣿⡿⠋⠀⠀⣶⣾⣿⣿⣿⣷⡄⠙⠻⣿⣿⣿⣿⣿⡿⠿⠿⠟⠛⠛⠋⠍⠉⢡⢰⡦⠔⠀⠀⠁⠚⣿⣿⣿⣿⠿⠿⠛⠛⠋⠉⠉⢸
    ⣿⡇⠀⠀⡾⣿⣿⣿⣿⣿⣿⣿⣖⠀⢻⣿⡏⢩⠉⠁⣄⣀⡄⣤⡥⢸⠂⣴⣿⢸⠇⠠⠇⠞⠒⡃⠛⠛⠉⠉⠀⠀⢀⣤⠀⢰⡆⢸
    ⣿⡃⠀⠐⡵⢾⣿⣿⣿⣿⣿⣿⣿⠀⠈⣿⣷⣀⠇⠼⠋⠃⡃⢛⠁⠄⢉⡅⠀⠂⠁⠂⠈⠀⣡⡤⠄⠀⠀⡟⢷⡄⠀⣿⡄⠘⣷⢸
    ⣿⡇⠀⡉⢌⠁⠨⢹⣯⡑⢊⢭⣻⡇⠠⣿⣿⣤⣬⣤⣷⡾⠶⠚⠋⠉⠀⠀⠀⠀⣶⡘⣧⠀⠸⣷⠒⠠⣀⣗⢩⠻⣦⢚⠓⠮⢩⢹
    ⣿⡇⠐⡈⣀⣈⣰⢺⣿⣷⣾⣷⣾⡇⣶⣿⣿⡟⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣇⠈⡟⢀⠙⢳⠈⢹⠀⠂⡀⠒⣀⡀⠀⠑⢸
    ⣿⣇⢡⢘⡵⣟⠣⠊⢟⣯⣿⣿⣿⢿⠊⠉⠀⠀⠀⠀⠀⠀⠀⠀⡀⠠⣀⠢⣌⠴⡡⠻⠊⢓⡁⠄⠑⠂⠈⠘⠠⠁⠄⢠⠐⡈⡮⢹
    ⣿⣿⣤⡞⣰⠃⠧⣝⣿⣻⢟⣿⡻⠏⠀⠀⠀⠀⡀⠠⣀⠢⢌⣲⣈⡱⠊⡑⠈⣰⠀⠀⠂⢈⠀⠄⡐⣠⢂⡜⡤⣍⣞⣤⣟⢶⣿⣿
    ⣿⣿⠛⠼⣥⣛⢴⣩⣟⣿⢯⣾⠅⠀⡀⡶⣚⡔⢠⡡⠌⡑⢾⣊⠁⠠⠁⠄⡁⢄⢠⡘⡰⣌⡞⣼⣱⣶⣯⣾⣷⣿⣾⣿⣿⣿⣿⣿
    ⣿⢁⠉⡄⢈⢹⣌⣧⣹⣿⣿⢿⡄⡌⢁⠧⠹⠀⢀⠀⡀⠄⡀⠠⢈⡀⢇⠸⣸⣸⣤⣹⣧⣿⣿⣿⣿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
    ⣿⣦⡓⠜⣦⡄⢋⠞⣿⣻⣭⣻⣿⣶⡶⢬⣤⣅⡀⠠⡀⢤⠈⡰⣸⣀⣤⣃⣅⣯⣑⣃⣀⣂⣎⣸⡐⣄⣅⢿⣠⣀⣹⣐⣜⣿⣿⣿
    ⣿⣿⣵⡊⠴⣻⣽⣮⡗⠻⢿⣿⣿⣿⣧⣼⣥⣥⢵⠤⠵⠢⢱⡤⠠⠧⠧⠼⡤⢤⡵⠧⢴⠭⠤⡤⠮⡬⠼⠤⢬⣼⡤⣼⣶⣤⣾⣿
    ⠿⠿⠿⠿⠦⠽⠿⠟⠀⠸⠁⠝⠿⠿⠿⠿⠿⠿⠾⠶⠶⠷⠺⠷⠶⠶⠶⠶⠿⠷⠷⠶⠿⠶⠶⠿⠶⠷⠷⠶⢷⣶⣶⣿⢿⣿⣿⣿
                thank you, dr. zizmor!"
    )
}
