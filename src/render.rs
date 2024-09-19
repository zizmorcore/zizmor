use std::io;

use crate::finding::{Confidence, Finding, Severity};
use anyhow::Result;
use colored::{ColoredString, Colorize};

trait Colorized {
    fn render(&self) -> ColoredString;
}

impl Colorized for Confidence {
    fn render(&self) -> ColoredString {
        match self {
            Confidence::Unknown => "unknown".magenta(),
            Confidence::Low => "low".yellow(),
            Confidence::Medium => "medium".cyan(),
            Confidence::High => "high".red(),
        }
    }
}

impl Colorized for Severity {
    fn render(&self) -> ColoredString {
        match self {
            Severity::Unknown => "unknown".magenta(),
            Severity::Informational => "informational".green(),
            Severity::Low => "low".green(),
            Severity::Medium => "medium".cyan(),
            Severity::High => "high".red(),
        }
    }
}

pub(crate) fn render_findings<W>(writer: W, findings: &[Finding]) -> Result<()>
where
    W: io::Write,
{
    let mut writer = writer;
    for finding in findings {
        render_finding(&mut writer, finding)?;
        writer.write_all(b"\n")?;
    }

    Ok(())
}

fn render_finding<W>(writer: W, finding: &Finding) -> Result<()>
where
    W: io::Write,
{
    let mut writer = writer;
    writeln!(
        &mut writer,
        "{ident} (C: {confidence}, S: {severity})",
        ident = finding.ident,
        confidence = finding.determinations.confidence.render(),
        severity = finding.determinations.severity.render(),
    )?;

    for location in &finding.locations {
        writeln!(
            &mut writer,
            "in {workflow}:{line}:{col}",
            workflow = location.symbolic.name,
            line = location.concrete.location.start_point.row,
            col = location.concrete.location.start_point.column,
        )?;
    }

    Ok(())
}
