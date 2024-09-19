use std::io;

use crate::finding::{Confidence, Finding, Severity};
use anyhow::Result;
use nu_ansi_term::{AnsiString, Color};

trait Colorized {
    fn render(&self) -> AnsiString;
}

impl Colorized for Confidence {
    fn render(&self) -> AnsiString {
        match self {
            Confidence::Unknown => Color::Magenta.paint("unknown"),
            Confidence::Low => Color::Yellow.paint("low"),
            Confidence::Medium => Color::Cyan.paint("medium"),
            Confidence::High => Color::Red.paint("high"),
        }
    }
}

impl Colorized for Severity {
    fn render(&self) -> AnsiString {
        match self {
            Severity::Unknown => Color::Magenta.paint("unknown"),
            Severity::Informational => Color::Green.paint("informational"),
            Severity::Low => Color::Green.paint("low"),
            Severity::Medium => Color::Cyan.paint("medium"),
            Severity::High => Color::Red.paint("high"),
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
        writeln!(&mut writer, "")?;
    }

    Ok(())
}
