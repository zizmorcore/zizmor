//! Parsing and matching APIs for GitHub Actions expressions
//! contexts (e.g. `github.event.name`).

use super::Expr;

#[derive(Debug)]
pub(crate) struct Context<'src> {
    raw: &'src str,
    pub(crate) components: Vec<Expr<'src>>,
}

impl<'src> Context<'src> {
    pub(crate) fn new(raw: &'src str, components: impl Into<Vec<Expr<'src>>>) -> Self {
        Self {
            raw,
            components: components.into(),
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        self.raw
    }

    pub(crate) fn components(&self) -> &[Expr<'src>] {
        &self.components
    }

    pub(crate) fn child_of(&self, parent: impl TryInto<Context<'src>>) -> bool {
        let Ok(parent) = parent.try_into() else {
            return false;
        };

        let mut parent_components = parent.components().iter().peekable();
        let mut child_components = self.components().iter().peekable();

        while let (Some(parent), Some(child)) = (parent_components.peek(), child_components.peek())
        {
            match (parent, child) {
                (Expr::Identifier(parent), Expr::Identifier(child)) => {
                    if parent != child {
                        return false;
                    }
                }
                _ => return false,
            }

            parent_components.next();
            child_components.next();
        }

        // If we've exhausted the parent, then the child is a true child.
        parent_components.next().is_none()
    }

    /// Returns the tail of the context if the head matches the given string.
    pub(crate) fn pop_if(&self, head: &str) -> Option<&str> {
        match self.components().first()? {
            Expr::Identifier(ident) if ident == head => Some(self.raw.split_once('.')?.1),
            _ => None,
        }
    }
}

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
pub(crate) struct ContextPattern<'src>(
    // NOTE: Kept as a string as a potentially premature optimization;
    // re-parsing should be faster in terms of locality.
    // TODO: Vec instead?
    &'src str,
);

impl<'src> ContextPattern<'src> {
    pub(crate) fn new(pattern: &'src str) -> Option<Self> {
        let components = pattern.split('.');
        let mut count = 0;
        for component in components {
            if component.is_empty() {
                return None;
            }

            match component {
                "*" => {}
                _ if component
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
}

#[cfg(test)]
mod tests {
    use super::{Context, ContextPattern};

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
}
