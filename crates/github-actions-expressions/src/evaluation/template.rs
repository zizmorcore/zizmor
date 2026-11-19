//! Fenced expressions in YAML string values.
use super::*;
use crate::call::FormatString;
use indexmap::IndexSet;
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

impl Evaluator {
    /// A format argument is evaluated once, and only if a placeholder uses it.
    pub(super) fn format(
        &mut self,
        args: &[SpannedExpr<'_>],
        bindings: &mut dyn Bindings,
    ) -> Outcomes {
        let Some((template, args)) = args.split_first() else {
            return vec![];
        };
        let templates = self
            .evaluate(template, bindings)
            .map(TrackedValue::formatted);
        self.flat_map(templates, |state, template| {
            state.interpolate(template, args, bindings)
        })
    }

    fn interpolate(
        &mut self,
        template: &TrackedValue,
        args: &[SpannedExpr<'_>],
        bindings: &mut dyn Bindings,
    ) -> Outcomes {
        let AbstractValue::Known(Evaluation::String(text)) = &template.inner else {
            // Any argument could be selected by a format string supplied at runtime.
            let mut result = template.clone();
            if matches!(result.inner, AbstractValue::Unknown(Shape::Hash)) {
                return vec![Outcome::new(result)];
            }
            for arg in args {
                for value in self.evaluate(arg, bindings).map(TrackedValue::formatted) {
                    result.provenance.extend(&value.value.provenance);
                }
            }
            return vec![Outcome::new(result)];
        };
        let Some(format) = FormatString::parse(text) else {
            return vec![];
        };
        let indices: IndexSet<_> = format.arguments().collect();
        if indices.iter().any(|&i| i >= args.len()) {
            return vec![];
        }
        self.sequence(&indices, |state, &i| {
            state
                .evaluate(&args[i], bindings)
                .map(TrackedValue::formatted)
        })
        .map(|values| {
            let mut provenance = template.provenance.clone();
            for value in &values {
                provenance.extend(&value.provenance);
            }
            let text = format.render(|i| {
                let value = &values[indices.get_index_of(&i)?];
                match &value.inner {
                    AbstractValue::Known(Evaluation::String(text)) => Some(text.as_str()),
                    _ => None,
                }
            });
            let inner = match text {
                Some(text) => AbstractValue::Known(Evaluation::String(text)),
                None => AbstractValue::Unknown(Shape::String),
            };
            TrackedValue { inner, provenance }
        })
    }

    /// Evaluate a YAML string. A single fenced expression retains its value type.
    pub fn template(&mut self, text: &str, bindings: &mut dyn Bindings) -> Outcomes {
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
                return self.evaluate(&parsed, bindings);
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
        let format = TrackedValue::known(Evaluation::String(format));
        self.within_limits(|state| state.interpolate(&format, &args, bindings))
    }
}
