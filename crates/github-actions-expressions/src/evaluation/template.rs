//! Fenced expressions in YAML string values.
use super::*;
use crate::Origin;
use std::ops::Range;

/// Find the next expression, ignoring closing braces inside Actions strings.
pub fn fenced_span(text: &str, offset: usize) -> Option<Range<usize>> {
    let start = offset + text.get(offset..)?.find("${{")?;
    let mut quoted = false;
    for (i, byte) in text.bytes().enumerate().skip(start + 3) {
        if byte == b'\'' {
            quoted = !quoted;
        } else if !quoted && text.as_bytes()[i..].starts_with(b"}}") {
            return Some(start..i + 2);
        }
    }
    None
}

impl State {
    pub(super) fn template(&mut self, text: &str, scope: &Scope) -> Outcomes {
        if !text.contains("${{") {
            return vec![Outcome::known(Evaluation::String(text.into()))];
        }

        let escape = |literal: &str| literal.replace('{', "{{").replace('}', "}}");
        let mut format = String::new();
        let mut args = vec![];
        let mut offset = 0;
        while let Some(span) = fenced_span(text, offset) {
            let parsed = match Expr::parse(&text[span.start + 3..span.end - 2]) {
                Ok(parsed) => parsed,
                Err(crate::Error::Depth) => {
                    return vec![Outcome::new(TrackedValue::incomplete())];
                }
                Err(_) => return Outcomes::default(),
            };
            if span == (0..text.len()) {
                return self.evaluate(&parsed, scope);
            }
            format.push_str(&escape(&text[offset..span.start]));
            format.push_str(&format!("{{{}}}", args.len()));
            args.push(parsed);
            offset = span.end;
        }
        if text[offset..].contains("${{") {
            return Outcomes::default();
        }

        // Use format for interpolation so arguments retain their sources.
        format.push_str(&escape(&text[offset..]));
        let synthetic = |inner| SpannedExpr {
            inner,
            origin: Origin::new(0..0, ""),
        };
        args.insert(0, synthetic(Expr::from(format)));
        let expr = Expr::Call(Call {
            func: Function::Format,
            args,
        });
        self.evaluate(&expr, scope)
    }
}
