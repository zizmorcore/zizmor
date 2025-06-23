//! Parsing and matching APIs for GitHub Actions expressions
//! contexts (e.g. `github.event.name`).

use crate::Literal;

use super::{Expr, SpannedExpr};

/// Represents a context in a GitHub Actions expression.
///
/// These typically look something like `github.actor` or `inputs.foo`,
/// although they can also be a "call" context like `fromJSON(...).foo.bar`,
/// i.e. where the head of the context is a function call rather than an
/// identifier.
#[derive(Debug, PartialEq)]
pub struct Context<'src> {
    /// The individual parts of the context.
    pub parts: Vec<SpannedExpr<'src>>,
}

impl<'src> Context<'src> {
    pub(crate) fn new(parts: impl Into<Vec<SpannedExpr<'src>>>) -> Self {
        Self {
            parts: parts.into(),
        }
    }

    /// Returns whether the context matches the given pattern exactly.
    pub fn matches(&self, pattern: impl TryInto<ContextPattern<'src>>) -> bool {
        let Ok(pattern) = pattern.try_into() else {
            return false;
        };

        pattern.matches(self)
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

    /// Return this context's "single tail," if it has one.
    ///
    /// This is useful primarily for contexts under `env` and `inputs`,
    /// where we expect only a single tail part, e.g. `env.FOO` or
    /// `inputs['bar']`.
    ///
    /// Returns `None` if the context has more than one tail part,
    /// or if the context's head part is not an identifier.
    pub fn single_tail(&self) -> Option<&str> {
        if self.parts.len() != 2 || !matches!(*self.parts[0], Expr::Identifier(_)) {
            return None;
        }

        match &self.parts[1].inner {
            Expr::Identifier(ident) => Some(ident.as_str()),
            Expr::Index(idx) => match &idx.inner {
                Expr::Literal(Literal::String(idx)) => Some(idx),
                _ => None,
            },
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
                Expr::Index(idx) => match &idx.inner {
                    // foo['bar'] -> foo.bar
                    Expr::Literal(Literal::String(idx)) => pattern.push_str(idx),
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
        let mut pattern = String::new();

        let mut parts = self.parts.iter().peekable();

        let head = parts.next()?;
        if matches!(**head, Expr::Call { .. }) {
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
        Self::try_new(val).ok_or_else(|| anyhow::anyhow!("invalid context pattern"))
    }
}

impl<'src> ContextPattern<'src> {
    /// Creates a new [`ContextPattern`] from the given string.
    ///
    /// Panics if the pattern is invalid.
    pub const fn new(pattern: &'src str) -> Self {
        Self::try_new(pattern).expect("invalid context pattern; use try_new to handle errors")
    }

    /// Creates a new [`ContextPattern`] from the given string.
    ///
    /// Returns `None` if the pattern is invalid.
    pub const fn try_new(pattern: &'src str) -> Option<Self> {
        let raw_pattern = pattern.as_bytes();
        if raw_pattern.is_empty() {
            return None;
        }

        let len = raw_pattern.len();

        // State machine:
        // - accept_reg: whether the next character can be a regular identifier character
        // - accept_dot: whether the next character can be a dot
        // - accept_star: whether the next character can be a star
        let mut accept_reg = true;
        let mut accept_dot = false;
        let mut accept_star = false;

        let mut idx = 0;
        while idx < len {
            accept_dot = accept_dot && idx != len - 1;

            match raw_pattern[idx] {
                b'.' => {
                    if !accept_dot {
                        return None;
                    }

                    accept_reg = true;
                    accept_dot = false;
                    accept_star = true;
                }
                b'*' => {
                    if !accept_star {
                        return None;
                    }

                    accept_reg = false;
                    accept_star = false;
                    accept_dot = true;
                }
                c if c.is_ascii_alphanumeric() || c == b'-' || c == b'_' => {
                    if !accept_reg {
                        return None;
                    }

                    accept_reg = true;
                    accept_dot = true;
                    accept_star = false;
                }
                _ => return None, // invalid character
            }

            idx += 1;
        }

        Some(Self(pattern))
    }

    fn compare_part(pattern: &str, part: &Expr<'src>) -> bool {
        if pattern == "*" {
            true
        } else {
            match part {
                Expr::Identifier(part) => pattern.eq_ignore_ascii_case(part.0),
                Expr::Index(part) => match &part.inner {
                    Expr::Literal(Literal::String(part)) => pattern.eq_ignore_ascii_case(part),
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

            match expr.inner {
                Expr::Context(ctx) => Ok(ctx),
                _ => Err(anyhow::anyhow!("expected context, found {:?}", expr)),
            }
        }
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
    fn test_single_tail() {
        for (case, expected) in &[
            // Valid cases.
            ("foo.bar", Some("bar")),
            ("foo['bar']", Some("bar")),
            ("inputs.test", Some("test")),
            // Invalid cases.
            ("foo.bar.baz", None),       // too many parts
            ("foo.bar.baz.qux", None),   // too many parts
            ("foo['bar']['baz']", None), // too many parts
            ("foo().bar", None),         // head is a call, not an identifier
        ] {
            let ctx = Context::try_from(*case).unwrap();
            assert_eq!(ctx.single_tail(), *expected);
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
            // Whitespace.
            ("foo . bar", Some("foo.bar")),
            ("foo . bar . baz", Some("foo.bar.baz")),
            ("foo . bar . baz_baz", Some("foo.bar.baz_baz")),
            ("foo . bar . baz-baz", Some("foo.bar.baz-baz")),
            ("foo .*", Some("foo.*")),
            ("foo . bar .*", Some("foo.bar.*")),
            ("foo .* . baz", Some("foo.*.baz")),
            ("foo .* .*", Some("foo.*.*")),
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
            ("*", None),
            ("**", None),
            (".**", None),
            (".foo", None),
            ("foo.", None),
            (".foo.", None),
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
            assert_eq!(ContextPattern::try_new(case).map(|p| p.0), *expected);
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
            let pattern = ContextPattern::try_new(pattern).unwrap();
            let ctx = Context::try_from(*ctx).unwrap();
            assert_eq!(pattern.parent_of(&ctx), *expected);
        }
    }

    #[test]
    fn test_context_pattern_matches() {
        for (pattern, ctx, expected) in &[
            // Normal matches.
            ("foo", "foo", true),
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
            let pattern = ContextPattern::try_new(pattern)
                .unwrap_or_else(|| panic!("invalid pattern: {pattern}"));
            let ctx = Context::try_from(*ctx).unwrap();
            assert_eq!(pattern.matches(&ctx), *expected);
        }
    }
}
