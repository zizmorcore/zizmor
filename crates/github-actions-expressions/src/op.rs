//! Unary and binary expressions and operators.

use crate::SpannedExpr;

/// Binary operations allowed in an expression.
#[derive(Debug, PartialEq)]
pub enum BinOp {
    /// `expr && expr`
    And,
    /// `expr || expr`
    Or,
    /// `expr == expr`
    Eq,
    /// `expr != expr`
    Neq,
    /// `expr > expr`
    Gt,
    /// `expr >= expr`
    Ge,
    /// `expr < expr`
    Lt,
    /// `expr <= expr`
    Le,
}

impl BinOp {
    /// Applies this operator to already evaluated operands.
    ///
    /// Callers must implement short circuiting before evaluating the right operand.
    pub fn evaluate(&self, lhs: crate::Evaluation, rhs: crate::Evaluation) -> crate::Evaluation {
        use crate::Evaluation::Boolean;

        match self {
            Self::And if lhs.as_boolean() => rhs,
            Self::Or if !lhs.as_boolean() => rhs,
            Self::And | Self::Or => lhs,
            Self::Eq => Boolean(lhs.sema() == rhs.sema()),
            Self::Neq => Boolean(lhs.sema() != rhs.sema()),
            Self::Lt => Boolean(lhs.sema() < rhs.sema()),
            Self::Le => Boolean(lhs.sema() <= rhs.sema()),
            Self::Gt => Boolean(lhs.sema() > rhs.sema()),
            Self::Ge => Boolean(lhs.sema() >= rhs.sema()),
        }
    }
}

/// Represents a binary expression.
///
/// Binary expressions can be either logical or arithmetic.
#[derive(Debug, PartialEq)]
pub struct BinExpr<'src> {
    /// The LHS of the expr.
    pub lhs: Box<SpannedExpr<'src>>,
    /// The binary operator.
    pub op: BinOp,
    /// The RHS of the expr.
    pub rhs: Box<SpannedExpr<'src>>,
}

/// Unary operations allowed in an expression.
#[derive(Debug, PartialEq)]
pub enum UnOp {
    /// `!expr`
    Not,
}

#[cfg(test)]
mod tests {
    use crate::{Error, Expr};

    #[test]
    fn test_evaluate_constant_binary_operations() -> Result<(), Error> {
        use crate::Evaluation;

        let test_cases = &[
            // Unreachable operands may be dynamic or invalid.
            ("true || fromJSON('invalid')", Evaluation::Boolean(true)),
            (
                "'' && fromJSON('invalid')",
                Evaluation::String(String::new()),
            ),
            // Boolean operations
            ("true && true", Evaluation::Boolean(true)),
            ("true && false", Evaluation::Boolean(false)),
            ("false && true", Evaluation::Boolean(false)),
            ("false && false", Evaluation::Boolean(false)),
            ("true || true", Evaluation::Boolean(true)),
            ("true || false", Evaluation::Boolean(true)),
            ("false || true", Evaluation::Boolean(true)),
            ("false || false", Evaluation::Boolean(false)),
            // Equality operations
            ("1 == 1", Evaluation::Boolean(true)),
            ("1 == 2", Evaluation::Boolean(false)),
            ("'hello' == 'hello'", Evaluation::Boolean(true)),
            ("'hello' == 'world'", Evaluation::Boolean(false)),
            ("true == true", Evaluation::Boolean(true)),
            ("true == false", Evaluation::Boolean(false)),
            ("1 != 2", Evaluation::Boolean(true)),
            ("1 != 1", Evaluation::Boolean(false)),
            // Comparison operations
            ("1 < 2", Evaluation::Boolean(true)),
            ("2 < 1", Evaluation::Boolean(false)),
            ("1 <= 1", Evaluation::Boolean(true)),
            ("1 <= 2", Evaluation::Boolean(true)),
            ("2 <= 1", Evaluation::Boolean(false)),
            ("2 > 1", Evaluation::Boolean(true)),
            ("1 > 2", Evaluation::Boolean(false)),
            ("1 >= 1", Evaluation::Boolean(true)),
            ("2 >= 1", Evaluation::Boolean(true)),
            ("1 >= 2", Evaluation::Boolean(false)),
        ];

        for (expr_str, expected) in test_cases {
            let expr = Expr::parse(expr_str)?;
            let result = expr.consteval().unwrap();
            assert_eq!(result, *expected, "Failed for expression: {}", expr_str);
        }

        Ok(())
    }

    #[test]
    fn test_cross_type_comparison_with_whitespace() -> Result<(), Error> {
        use crate::Evaluation;

        let test_cases = &[
            // Strings with whitespace should be trimmed before number coercion.
            ("'   1   ' == 1", Evaluation::Boolean(true)),
            ("' 42 ' == 42", Evaluation::Boolean(true)),
            ("'  0  ' == 0", Evaluation::Boolean(true)),
            ("'  3.14  ' == 3.14", Evaluation::Boolean(true)),
            ("'   1   ' != 1", Evaluation::Boolean(false)),
            ("' 2 ' < 3", Evaluation::Boolean(true)),
            ("' 5 ' > 3", Evaluation::Boolean(true)),
        ];

        for (expr_str, expected) in test_cases {
            let expr = Expr::parse(expr_str)?;
            let result = expr.consteval().unwrap();
            assert_eq!(result, *expected, "Failed for expression: {}", expr_str);
        }

        Ok(())
    }
}
