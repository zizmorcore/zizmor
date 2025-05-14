//! GitHub workflow command-formatted output.
//!
//! See: <https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions>

use std::io;

use anyhow::Result;

use crate::{Severity, finding::Finding};

impl Severity {
    /// Converts a `Severity` to a GitHub Actions command command.
    fn as_github_command(&self) -> &str {
        // TODO: Does this mapping make sense?
        match self {
            Severity::Unknown => "notice",
            Severity::Informational => "notice",
            Severity::Low => "warning",
            Severity::Medium => "warning",
            Severity::High => "error",
        }
    }
}

impl Finding<'_> {
    fn format_command(&self, sink: &mut impl io::Write) -> Result<()> {
        let primary = self
            .visible_locations()
            .find(|l| l.symbolic.is_primary())
            .unwrap();

        // NOTE: We intentionally only use the start line, since our spans
        // sometimes end at EOF and GitHub's annotations don't handle that
        // gracefully.
        let filepath = primary.symbolic.key.sarif_path();
        let start_line = primary.concrete.location.start_point.row + 1;
        let title = self.ident;

        let message = format!(
            "{filename}:{start_line}: {desc}: {annotation}",
            filename = primary.symbolic.key.filename(),
            desc = self.desc,
            annotation = primary.symbolic.annotation,
        );

        writeln!(
            sink,
            "::{} file={filepath},line={start_line},title={title}::{message}",
            self.determinations.severity.as_github_command()
        )?;

        Ok(())
    }
}

pub(crate) fn output(sink: impl io::Write, findings: &[Finding]) -> Result<()> {
    let mut sink = sink;

    for finding in findings {
        finding.format_command(&mut sink)?;
    }

    Ok(())
}
