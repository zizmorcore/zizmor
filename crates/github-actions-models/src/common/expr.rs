//! GitHub Actions expression parsing and handling.

use serde::{Deserialize, Serialize};

/// An explicit GitHub Actions expression, fenced by `${{ <expr> }}`.
#[derive(Debug, PartialEq, Serialize)]
pub struct ExplicitExpr(String);

impl ExplicitExpr {
    /// Construct an `ExplicitExpr` from the given string, consuming it
    /// in the process.
    ///
    /// Returns `None` if the input is not a valid explicit expression.
    pub fn from_curly(expr: impl Into<String>) -> Option<Self> {
        // Invariant preservation: we store the full string, but
        // we expect it to be a well-formed expression.
        let expr = expr.into();
        let trimmed = expr.trim();
        if !trimmed.starts_with("${{") || !trimmed.ends_with("}}") {
            return None;
        }

        Some(ExplicitExpr(expr))
    }

    /// Return the original string underlying this expression, including
    /// its exact whitespace and curly delimiters.
    pub fn as_raw(&self) -> &str {
        &self.0
    }

    /// Return the "curly" form of this expression, with leading and trailing
    /// whitespace removed.
    ///
    /// Whitespace *within* the expression body is not removed or normalized.
    pub fn as_curly(&self) -> &str {
        self.as_raw().trim()
    }

    /// Return the "bare" form of this expression, i.e. the `body` within
    /// `${{ body }}`. Leading and trailing whitespace within
    /// the expression body is removed.
    pub fn as_bare(&self) -> &str {
        self.as_curly()
            .strip_prefix("${{")
            .and_then(|e| e.strip_suffix("}}"))
            .map(|e| e.trim())
            .expect("invariant violated: ExplicitExpr must be an expression")
    }
}

impl<'de> Deserialize<'de> for ExplicitExpr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;

        let Some(expr) = Self::from_curly(raw) else {
            return Err(serde::de::Error::custom(
                "invalid expression: expected '${{' and '}}' delimiters",
            ));
        };

        Ok(expr)
    }
}

/// A "literal or expr" type, for places in GitHub Actions where a
/// key can either have a literal value (array, object, etc.) or an
/// expression string.
#[derive(Deserialize, Serialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum LoE<T> {
    // Observe that `Expr` comes first, since `LoE<String>` should always
    // attempt to parse as an expression before falling back on a literal
    // string.
    Expr(ExplicitExpr),
    Literal(T),
}

impl<T> Default for LoE<T>
where
    T: Default,
{
    fn default() -> Self {
        Self::Literal(T::default())
    }
}

/// A convenience alias for a `bool` literal or an actions expression.
pub type BoE = LoE<bool>;

#[cfg(test)]
mod tests {
    use super::{ExplicitExpr, LoE};

    #[test]
    fn test_expr_invalid() {
        let cases = &[
            "not an expression",
            "${{ missing end ",
            "missing beginning }}",
        ];

        for case in cases {
            let case = format!("\"{case}\"");
            assert!(serde_yaml::from_str::<ExplicitExpr>(&case).is_err());
        }
    }

    #[test]
    fn test_expr() {
        let expr = "\"  ${{ foo }} \\t \"";
        let expr: ExplicitExpr = serde_yaml::from_str(expr).unwrap();
        assert_eq!(expr.as_bare(), "foo");
    }

    #[test]
    fn test_loe() {
        let lit = "\"normal string\"";
        assert_eq!(
            serde_yaml::from_str::<LoE<String>>(lit).unwrap(),
            LoE::Literal("normal string".to_string())
        );

        let expr = "\"${{ expr }}\"";
        assert!(matches!(
            serde_yaml::from_str::<LoE<String>>(expr).unwrap(),
            LoE::Expr(_)
        ));

        // Invalid expr deserializes as string.
        let invalid = "\"${{ invalid \"";
        assert_eq!(
            serde_yaml::from_str::<LoE<String>>(invalid).unwrap(),
            LoE::Literal("${{ invalid ".to_string())
        );
    }
}
