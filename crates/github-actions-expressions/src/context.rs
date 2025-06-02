//! Parsing and matching APIs for GitHub Actions expressions
//! contexts (e.g. `github.event.name`).

use super::Expr;

/// Represents a context in a GitHub Actions expression.
///
/// These typically look something like `github.actor` or `inputs.foo`,
/// although they can also be a "call" context like `fromJSON(...).foo.bar`,
/// i.e. where the head of the context is a function call rather than an
/// identifier.
#[derive(Debug)]
pub struct Context<'src> {
    raw: &'src str,
    /// The individual parts of the context.
    pub parts: Vec<Expr<'src>>,
}

impl<'src> Context<'src> {
    pub(crate) fn new(raw: &'src str, parts: impl Into<Vec<Expr<'src>>>) -> Self {
        Self {
            raw,
            parts: parts.into(),
        }
    }

    /// Returns the raw string representation of the context.
    pub fn as_str(&self) -> &str {
        self.raw
    }

    /// Returns whether the context is a child of the given pattern.
    ///
    /// A context is considered its own child, i.e. `foo.bar` is a child of
    /// `foo.bar`.
    pub fn child_of(&self, parent: impl TryInto<ContextPattern<'src>>) -> bool {
        let Ok(parent) = parent.try_into() else {
            return false;
        };

        parent.parent_of(self)
    }

    /// Returns the tail of the context if the head matches the given string.
    pub fn pop_if(&self, head: &str) -> Option<&str> {
        match self.parts.first()? {
            Expr::Identifier(ident) if ident == head => Some(self.raw.split_once('.')?.1),
            _ => None,
        }
    }

    /// Returns the "pattern equivalent" of this context.
    ///
    /// This is a string that can be used to efficiently match the context,
    /// such as is done in `zizmor`'s template-injection audit via a
    /// finite state transducer.
    ///
    /// Returns None if the context doesn't have a sensible pattern
    /// equivalent, e.g. if it starts with a call.
    pub fn as_pattern(&self) -> Option<String> {
        fn push_part(part: &Expr<'_>, pattern: &mut String) {
            match part {
                Expr::Identifier(ident) => pattern.push_str(ident.0),
                Expr::Star => pattern.push('*'),
                Expr::Index(idx) => match idx.as_ref() {
                    // foo['bar'] -> foo.bar
                    Expr::String(idx) => pattern.push_str(idx),
                    // any kind of numeric or computed index, e.g.:
                    // foo[0], foo[1 + 2], foo[bar]
                    _ => pattern.push('*'),
                },
                _ => unreachable!("unexpected part in context pattern"),
            }
        }

        // TODO: Optimization ideas:
        // 1. Add a happy path for contexts that contain only
        //    identifiers? Problem: case normalization.
        // 2. Use `regex-automata` to return a case insensitive
        //    automation here?
        let mut pattern = String::with_capacity(self.raw.len());

        let mut parts = self.parts.iter().peekable();

        let head = parts.next()?;
        if matches!(head, Expr::Call { .. }) {
            return None;
        }

        push_part(head, &mut pattern);
        for part in parts {
            pattern.push('.');
            push_part(part, &mut pattern);
        }

        pattern.make_ascii_lowercase();
        Some(pattern)
    }
}

impl PartialEq for Context<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.raw.eq_ignore_ascii_case(other.raw)
    }
}

impl PartialEq<str> for Context<'_> {
    fn eq(&self, other: &str) -> bool {
        self.raw.eq_ignore_ascii_case(other)
    }
}

enum Comparison {
    Child,
    Match,
}

/// A `ContextPattern` is a pattern that matches one or more contexts.
///
/// It uses a restricted subset of the syntax used by contexts themselves:
/// a pattern is always in dotted form and can only contain identifiers
/// and wildcards.
///
/// Indices are not allowed in patterns themselves, although contexts
/// that contain indices can be matched against patterns. For example,
/// `github.event.pull_request.assignees.*.name` will match the context
/// `github.event.pull_request.assignees[0].name`.
pub struct ContextPattern<'src>(
    // NOTE: Kept as a string as a potentially premature optimization;
    // re-parsing should be faster in terms of locality.
    // TODO: Vec instead?
    &'src str,
);

impl<'src> TryFrom<&'src str> for ContextPattern<'src> {
    type Error = anyhow::Error;

    fn try_from(val: &'src str) -> anyhow::Result<Self> {
        Self::new(val).ok_or_else(|| anyhow::anyhow!("invalid context pattern"))
    }
}

impl<'src> ContextPattern<'src> {
    /// Creates a new `ContextPattern` from the given string.
    ///
    /// Returns `None` if the pattern is invalid.
    pub fn new(pattern: &'src str) -> Option<Self> {
        let parts = pattern.split('.');
        let mut count = 0;
        for part in parts {
            if part.is_empty() {
                return None;
            }

            match part {
                "*" => {}
                // TODO: `bytes()` is probably a little faster.
                _ if part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') => {}
                _ => return None,
            }
            count += 1;
        }

        match count {
            0 => None,
            _ => Some(Self(pattern)),
        }
    }

    fn compare_part(pattern: &str, part: &Expr<'src>) -> bool {
        if pattern == "*" {
            true
        } else {
            match part {
                Expr::Identifier(part) => pattern.eq_ignore_ascii_case(part.0),
                Expr::Index(part) => match part.as_ref() {
                    Expr::String(part) => pattern.eq_ignore_ascii_case(part),
                    _ => false,
                },
                _ => false,
            }
        }
    }

    fn compare(&self, ctx: &Context<'src>) -> Option<Comparison> {
        let mut pattern_parts = self.0.split('.').peekable();
        let mut ctx_parts = ctx.parts.iter().peekable();

        while let (Some(pattern), Some(part)) = (pattern_parts.peek(), ctx_parts.peek()) {
            if !Self::compare_part(pattern, part) {
                return None;
            }

            pattern_parts.next();
            ctx_parts.next();
        }

        match (pattern_parts.next(), ctx_parts.next()) {
            // If both are exhausted, we have an exact match.
            (None, None) => Some(Comparison::Match),
            // If the pattern is exhausted but the context isn't, then
            // the context is a child of the pattern.
            (None, Some(_)) => Some(Comparison::Child),
            _ => None,
        }
    }

    /// Returns true if the given context is a child of the pattern.
    ///
    /// This is a loose parent-child relationship; for example, `foo` is its
    /// own parent, as well as the parent of `foo.bar` and `foo.bar.baz`.
    pub fn parent_of(&self, ctx: &Context<'src>) -> bool {
        matches!(
            self.compare(ctx),
            Some(Comparison::Child | Comparison::Match)
        )
    }

    /// Returns true if the given context exactly matches the pattern.
    ///
    /// See [`ContextPattern`] for a description of the matching rules.
    pub fn matches(&self, ctx: &Context<'src>) -> bool {
        matches!(self.compare(ctx), Some(Comparison::Match))
    }
}

#[cfg(test)]
mod tests {
    use crate::Expr;

    use super::{Context, ContextPattern};

    impl<'a> TryFrom<&'a str> for Context<'a> {
        type Error = anyhow::Error;

        fn try_from(val: &'a str) -> anyhow::Result<Self> {
            let expr = Expr::parse(val)?;

            match expr {
                Expr::Context(ctx) => Ok(ctx),
                _ => Err(anyhow::anyhow!("expected context, found {:?}", expr)),
            }
        }
    }

    #[test]
    fn test_context_eq() {
        let ctx = Context::try_from("foo.bar.baz").unwrap();
        assert_eq!(&ctx, "foo.bar.baz");
        assert_eq!(&ctx, "FOO.BAR.BAZ");
        assert_eq!(&ctx, "Foo.Bar.Baz");
    }

    #[test]
    fn test_context_child_of() {
        let ctx = Context::try_from("foo.bar.baz").unwrap();

        for (case, child) in &[
            // Trivial child cases.
            ("foo", true),
            ("foo.bar", true),
            // Case-insensitive cases.
            ("FOO", true),
            ("FOO.BAR", true),
            ("Foo", true),
            ("Foo.Bar", true),
            // We consider a context to be a child of itself.
            ("foo.bar.baz", true),
            // Trivial non-child cases.
            ("foo.bar.baz.qux", false),
            ("foo.bar.qux", false),
            ("foo.qux", false),
            ("qux", false),
            // Invalid cases.
            ("foo.", false),
            (".", false),
            ("", false),
        ] {
            assert_eq!(ctx.child_of(*case), *child);
        }
    }

    #[test]
    fn test_context_pop_if() {
        let ctx = Context::try_from("foo.bar.baz").unwrap();

        for (case, expected) in &[
            ("foo", Some("bar.baz")),
            ("Foo", Some("bar.baz")),
            ("FOO", Some("bar.baz")),
            ("foo.", None),
            ("bar", None),
        ] {
            assert_eq!(ctx.pop_if(case), *expected);
        }
    }

    #[test]
    fn test_context_as_pattern() {
        for (case, expected) in &[
            // Basic cases.
            ("foo", Some("foo")),
            ("foo.bar", Some("foo.bar")),
            ("foo.bar.baz", Some("foo.bar.baz")),
            ("foo.bar.baz_baz", Some("foo.bar.baz_baz")),
            ("foo.bar.baz-baz", Some("foo.bar.baz-baz")),
            ("foo.*", Some("foo.*")),
            ("foo.bar.*", Some("foo.bar.*")),
            ("foo.*.baz", Some("foo.*.baz")),
            ("foo.*.*", Some("foo.*.*")),
            // Case sensitivity.
            ("FOO", Some("foo")),
            ("FOO.BAR", Some("foo.bar")),
            ("FOO.BAR.BAZ", Some("foo.bar.baz")),
            ("FOO.BAR.BAZ_BAZ", Some("foo.bar.baz_baz")),
            ("FOO.BAR.BAZ-BAZ", Some("foo.bar.baz-baz")),
            ("FOO.*", Some("foo.*")),
            ("FOO.BAR.*", Some("foo.bar.*")),
            ("FOO.*.BAZ", Some("foo.*.baz")),
            ("FOO.*.*", Some("foo.*.*")),
            // Indexes.
            ("foo.bar.baz[0]", Some("foo.bar.baz.*")),
            ("foo.bar.baz['abc']", Some("foo.bar.baz.abc")),
            ("foo.bar.baz[0].qux", Some("foo.bar.baz.*.qux")),
            ("foo.bar.baz[0].qux[1]", Some("foo.bar.baz.*.qux.*")),
            ("foo[1][2][3]", Some("foo.*.*.*")),
            ("foo.bar[abc]", Some("foo.bar.*")),
            ("foo.bar[abc()]", Some("foo.bar.*")),
            // Invalid cases
            ("foo().bar", None),
        ] {
            let ctx = Context::try_from(*case).unwrap();
            assert_eq!(ctx.as_pattern().as_deref(), *expected);
        }
    }

    #[test]
    fn test_contextpattern_new() {
        for (case, expected) in &[
            // Well-formed patterns.
            ("foo", Some("foo")),
            ("foo.bar", Some("foo.bar")),
            ("foo.bar.baz", Some("foo.bar.baz")),
            ("foo.bar.baz_baz", Some("foo.bar.baz_baz")),
            ("foo.bar.baz-baz", Some("foo.bar.baz-baz")),
            ("foo.*", Some("foo.*")),
            ("foo.bar.*", Some("foo.bar.*")),
            ("foo.*.baz", Some("foo.*.baz")),
            ("foo.*.*", Some("foo.*.*")),
            // Invalid patterns.
            ("", None),
            ("foo.", None),
            ("foo.**", None),
            (".", None),
            ("foo.bar.", None),
            ("foo..bar", None),
            ("foo.bar.baz[0]", None),
            ("foo.bar.baz['abc']", None),
            ("foo.bar.baz[0].qux", None),
            ("foo.bar.baz[0].qux[1]", None),
            ("❤", None),
            ("❤.*", None),
        ] {
            assert_eq!(ContextPattern::new(case).map(|p| p.0), *expected);
        }
    }

    #[test]
    fn test_contextpattern_parent_of() {
        for (pattern, ctx, expected) in &[
            // Exact contains.
            ("foo", "foo", true),
            ("foo.bar", "foo.bar", true),
            ("foo.bar", "foo['bar']", true),
            ("foo.bar", "foo['BAR']", true),
            // Parent relationships
            ("foo", "foo.bar", true),
            ("foo.bar", "foo.bar.baz", true),
            ("foo.*", "foo.bar", true),
            ("foo.*.baz", "foo.bar.baz", true),
            ("foo.*.*", "foo.bar.baz.qux", true),
            ("foo", "foo.bar.baz.qux", true),
            ("foo.*", "foo.bar.baz.qux", true),
            (
                "secrets",
                "fromJson(steps.runs.outputs.data).workflow_runs[0].id",
                false,
            ),
        ] {
            let pattern = ContextPattern::new(pattern).unwrap();
            let ctx = Context::try_from(*ctx).unwrap();
            assert_eq!(pattern.parent_of(&ctx), *expected);
        }
    }

    #[test]
    fn test_context_pattern_matches() {
        for (pattern, ctx, expected) in &[
            // Normal matches.
            ("foo", "foo", true),
            ("*", "foo", true),
            ("foo.bar", "foo.bar", true),
            ("foo.bar.baz", "foo.bar.baz", true),
            ("foo.*", "foo.bar", true),
            ("foo.*.baz", "foo.bar.baz", true),
            ("foo.*.*", "foo.bar.baz", true),
            ("foo.*.*.*", "foo.bar.baz.qux", true),
            // Case-insensitive matches.
            ("foo.bar", "FOO.BAR", true),
            ("foo.bar.baz", "Foo.Bar.Baz", true),
            ("foo.*", "FOO.BAR", true),
            ("foo.*.baz", "Foo.Bar.Baz", true),
            ("foo.*.*", "FOO.BAR.BAZ", true),
            ("FOO.BAR", "foo.bar", true),
            ("FOO.BAR.BAZ", "foo.bar.baz", true),
            ("FOO.*", "foo.bar", true),
            ("FOO.*.BAZ", "foo.bar.baz", true),
            ("FOO.*.*", "foo.bar.baz", true),
            // Indices also match correctly.
            ("foo.bar.baz.*", "foo.bar.baz[0]", true),
            ("foo.bar.baz.*", "foo.bar.baz[123]", true),
            ("foo.bar.baz.*", "foo.bar.baz['abc']", true),
            ("foo.bar.baz.*", "foo['bar']['baz']['abc']", true),
            ("foo.bar.baz.*", "foo['bar']['BAZ']['abc']", true),
            // Contexts containing stars match correctly.
            ("foo.bar.baz.*", "foo.bar.baz.*", true),
            ("foo.bar.*.*", "foo.bar.*.*", true),
            ("foo.bar.baz.qux", "foo.bar.baz.*", false), // patterns are one way
            ("foo.bar.baz.qux", "foo.bar.baz[*]", false), // patterns are one way
            // False normal matches.
            ("foo", "bar", false),                     // different identifier
            ("foo.bar", "foo.baz", false),             // different identifier
            ("foo.bar", "foo['baz']", false),          // different index
            ("foo.bar.baz", "foo.bar.baz.qux", false), // pattern too short
            ("foo.bar.baz", "foo.bar", false),         // context too short
            ("foo.*.baz", "foo.bar.baz.qux", false),   // pattern too short
            ("foo.*.qux", "foo.bar.baz.qux", false),   // * does not match multiple parts
            ("foo.*.*", "foo.bar.baz.qux", false),     // pattern too short
            ("foo.1", "foo[1]", false),                // .1 means a string key, not an index
        ] {
            let pattern = ContextPattern::new(pattern).unwrap();
            let ctx = Context::try_from(*ctx).unwrap();
            assert_eq!(pattern.matches(&ctx), *expected);
        }
    }
}
