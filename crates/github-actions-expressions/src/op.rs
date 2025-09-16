//! Unary and binary operators.

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

/// Unary operations allowed in an expression.
#[derive(Debug, PartialEq)]
pub enum UnOp {
    /// `!expr`
    Not,
}

#[cfg(test)]
mod tests {
    use crate::Expr;
    use anyhow::Result;

    #[test]
    fn test_evaluate_constant_binary_operations() -> Result<()> {
        use crate::Evaluation;

        let test_cases = &[
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
}
