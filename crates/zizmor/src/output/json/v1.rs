//! zizmor's "v1" JSON output format.
//!
//! The "v1" format is a flat array of findings, each represented as an object.
//!
//! This was originally represented as an exact dump of zizmor's internal
//! [`Finding`] type, leading to both development friction and unnecessary
//! user disruption when the internal representation changed.

use std::io;

use crate::finding;

// NOTE: Internally this format still uses a lot of zizmor's internal types.
// As those change, this module will gain "frozen" copies with converters.

#[derive(serde::Serialize)]
struct V1Finding<'a> {
    ident: &'a str,
    desc: &'a str,
    url: &'a str,
    determinations: finding::Determinations,
    locations: &'a [finding::location::Location<'a>],
    ignored: bool,
    fixes: Vec<V1Fix<'a>>,
}

#[derive(serde::Serialize)]
struct V1Fix<'a> {
    title: &'a str,
    key: &'a crate::InputKey,
    disposition: finding::FixDisposition,
}

impl<'a> From<&'a finding::Fix<'a>> for V1Fix<'a> {
    fn from(fix: &'a finding::Fix<'a>) -> Self {
        Self {
            title: fix.title.as_str(),
            key: fix.key,
            disposition: fix.disposition,
        }
    }
}

impl<'a> From<&'a finding::Finding<'a>> for V1Finding<'a> {
    fn from(finding: &'a finding::Finding<'a>) -> Self {
        Self {
            ident: finding.ident,
            desc: finding.desc,
            url: finding.url,
            determinations: finding.determinations,
            locations: &finding.locations,
            ignored: finding.ignored,
            fixes: finding.fixes.iter().map(V1Fix::from).collect(),
        }
    }
}

pub(crate) fn output<'a>(
    sink: impl io::Write,
    findings: &[finding::Finding<'a>],
) -> anyhow::Result<()> {
    serde_json::to_writer_pretty(
        sink,
        &findings.iter().map(V1Finding::from).collect::<Vec<_>>(),
    )?;
    Ok(())
}
