//! Expression parsing and analysis.

use anyhow::Result;
use pest::{
    iterators::Pair,
    pratt_parser::{Op, PrattParser},
    Parser,
};
use pest_derive::Parser;

/// A parser for GitHub Actions' expression language.
#[derive(Parser)]
#[grammar = "expr/expr.pest"]
struct ExprParser;

pub(crate) enum BinOp {
    And,
    Or,
    Eq,
    Neq,
    Gt,
    Ge,
    Lt,
    Le,
    Add,
    Sub,
    Mul,
    Div,
}

pub(crate) enum UnOp {
    Not,
    Neg,
}

pub(crate) enum Expr {
    Number(f64),
    String(String),
    Boolean(bool),
    Null,
    Call {
        func: String,
        args: Vec<Box<Expr>>,
    },
    ContextRef(String),
    BinOp {
        lhs: Box<Expr>,
        op: BinOp,
        rhs: Box<Expr>,
    },
    UnOp {
        op: UnOp,
        expr: Box<Expr>,
    },
}

fn parse(expr: &str) -> Result<()> {
    let expr = ExprParser::parse(Rule::expression, expr)?.next().unwrap();

    fn parse_inner(expr: Pair<'_, Rule>) -> Result<()> {
        todo!()
    }

    parse_inner(expr)
}

#[cfg(test)]
mod tests {
    use pest::Parser as _;

    use super::{ExprParser, Rule};

    #[test]
    fn test_parse_string() {
        let cases = &[
            ("''", ""),
            ("' '", " "),
            ("''''", "''"),
            ("'test'", "test"),
            ("'spaces are ok'", "spaces are ok"),
            ("'escaping '' works'", "escaping '' works"),
        ];

        for (case, expected) in cases {
            let s = ExprParser::parse(Rule::string, case)
                .unwrap()
                .next()
                .unwrap();

            assert_eq!(s.into_inner().next().unwrap().as_str(), *expected);
        }
    }

    #[test]
    fn test_parse_ident() {
        let cases = &[
            "foo.bar",
            "github.action_path",
            "inputs.foo-bar",
            "inputs.also--valid",
            "inputs.this__too",
            "inputs.this__too",
            "secrets.GH_TOKEN",
        ];

        for case in cases {
            assert_eq!(
                ExprParser::parse(Rule::context_reference, case)
                    .unwrap()
                    .next()
                    .unwrap()
                    .as_str(),
                *case
            );
        }
    }

    #[test]
    fn test_parse_call() {
        let cases = &[
            "foo()",
            "foo(bar)",
            // "foo(bar())",
            "foo(1.23)",
            "foo(1,2)",
            "foo(1, 2)",
            "foo(1, 2, secret.GH_TOKEN)",
            "foo(   )",
            "fromJSON(inputs.free-threading)",
        ];

        for case in cases {
            assert_eq!(
                ExprParser::parse(Rule::function_call, case)
                    .unwrap()
                    .next()
                    .unwrap()
                    .as_str(),
                *case
            );
        }
    }

    #[test]
    fn test_parse_expr() {
        let cases = &["fromJSON(inputs.free-threading) && '--disable-gil' || ''"];

        for case in cases {
            assert_eq!(
                ExprParser::parse(Rule::expression, case)
                    .unwrap()
                    .next()
                    .unwrap()
                    .as_str(),
                *case
            );
        }
    }
}
