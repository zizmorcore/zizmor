//! GitHub workflow command-formatted output.
//!
//! See: <https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions>

use std::io;

use anyhow::Result;
use zizmor_audit::finding::Finding;
use zizmor_core::finding::Severity;

/// Converts a `Severity` to a GitHub Actions command command.
fn severity_as_github_command(severity: &Severity) -> &str {
    // TODO: Does this mapping make sense?
    match severity {
        Severity::Informational => "notice",
        Severity::Low => "warning",
        Severity::Medium => "warning",
        Severity::High => "error",
    }
}

fn format_command(finding: &Finding<'_>, sink: &mut impl io::Write) -> Result<()> {
    let primary = finding.primary_location();

    // NOTE: We intentionally only use the start line, since our spans
    // sometimes end at EOF and GitHub's annotations don't handle that
    // gracefully.
    let filepath = primary.symbolic.key.best_identifier();
    let start_line = primary.concrete.location.start_point.row + 1;
    let title = finding.ident;

    let message = format!(
        "{filename}:{start_line}: {desc}: {annotation}",
        filename = primary.symbolic.key.filename(),
        desc = finding.desc,
        annotation = primary.symbolic.annotation,
    );

    writeln!(
        sink,
        "::{} file={filepath},line={start_line},title={title}::{message}",
        severity_as_github_command(&finding.determinations.severity)
    )?;

    Ok(())
}

pub(crate) fn output(sink: impl io::Write, findings: &[Finding]) -> Result<()> {
    let mut sink = sink;

    for finding in findings {
        format_command(finding, &mut sink)?;
    }

    Ok(())
}
