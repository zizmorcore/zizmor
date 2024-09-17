use std::io;

use crate::finding::Finding;
use anyhow::Result;

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
        "{ident} ({confidence:?} confidence, {severity:?} severity)",
        ident = finding.ident,
        confidence = finding.determinations.confidence,
        severity = finding.determinations.severity,
    )?;

    Ok(())
}
