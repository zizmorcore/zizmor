//! Literal values.

use std::borrow::Cow;

use crate::Evaluation;

/// Represents a literal value in a GitHub Actions expression.
#[derive(Debug, PartialEq)]
pub enum Literal<'src> {
    /// A number literal.
    Number(f64),
    /// A string literal.
    String(Cow<'src, str>),
    /// A boolean literal.
    Boolean(bool),
    /// The `null` literal.
    Null,
}

impl<'src> Literal<'src> {
    /// Returns a string representation of the literal.
    ///
    /// This is not guaranteed to be an exact equivalent of the literal
    /// as it appears in its source expression. For example, the string
    /// representation of a floating point literal is subject to normalization,
    /// and string literals are returned without surrounding quotes.
    pub fn as_str(&self) -> Cow<'src, str> {
        match self {
            Literal::String(s) => s.clone(),
            Literal::Number(n) => Cow::Owned(n.to_string()),
            Literal::Boolean(b) => Cow::Owned(b.to_string()),
            Literal::Null => Cow::Borrowed("null"),
        }
    }

    /// Returns the trivial constant evaluation of the literal.
    pub(crate) fn consteval(&self) -> Evaluation {
        match self {
            Literal::String(s) => Evaluation::String(s.to_string()),
            Literal::Number(n) => Evaluation::Number(*n),
            Literal::Boolean(b) => Evaluation::Boolean(*b),
            Literal::Null => Evaluation::Null,
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::Expr;

    #[test]
    fn test_evaluate_constant_literals() -> Result<()> {
        use crate::Evaluation;

        let test_cases = &[
            ("'hello'", Evaluation::String("hello".to_string())),
            ("'world'", Evaluation::String("world".to_string())),
            ("42", Evaluation::Number(42.0)),
            ("3.14", Evaluation::Number(3.14)),
            ("true", Evaluation::Boolean(true)),
            ("false", Evaluation::Boolean(false)),
            ("null", Evaluation::Null),
        ];

        for (expr_str, expected) in test_cases {
            let expr = Expr::parse(expr_str)?;
            let result = expr.consteval().unwrap();
            assert_eq!(result, *expected, "Failed for expression: {}", expr_str);
        }

        Ok(())
    }
}
