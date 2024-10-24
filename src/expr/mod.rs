//! Expression parsing and analysis.

use anyhow::{Ok, Result};
use itertools::Itertools;
use pest::{iterators::Pair, Parser};
use pest_derive::Parser;

/// A parser for GitHub Actions' expression language.
#[derive(Parser)]
#[grammar = "expr/expr.pest"]
struct ExprParser;

#[derive(Debug, PartialEq)]
pub(crate) enum BinOp {
    And,
    Or,
    Eq,
    Neq,
    Gt,
    Ge,
    Lt,
    Le,
}

#[derive(Debug, PartialEq)]
pub(crate) enum UnOp {
    Not,
}

/// Represents a GitHub Actions expression.
#[derive(Debug, PartialEq)]
pub(crate) enum Expr {
    /// A number literal.
    Number(f64),
    /// A string literal.
    String(String),
    /// A boolean literal.
    Boolean(bool),
    /// The `null` literal.
    Null,
    /// An index operation.
    ///
    /// Three different kinds of expressions can be indexed:
    ///
    /// ```
    /// functionCall[expr]
    /// context.reference[expr]
    /// (<arbitrary expression>)[expr]
    /// ```
    Index { parent: Box<Expr>, index: Box<Expr> },
    /// A function call.
    Call { func: String, args: Vec<Box<Expr>> },
    /// A context reference.
    ContextRef(String),
    /// A binary operation, either logical or arithmetic.
    BinOp {
        lhs: Box<Expr>,
        op: BinOp,
        rhs: Box<Expr>,
    },
    /// A unary operation. Negation (`!`) is currently the only `UnOp`.
    UnOp { op: UnOp, expr: Box<Expr> },
}

impl Expr {
    pub(crate) fn parse(expr: &str) -> Result<Expr> {
        // Top level `expression` is a single `or_expr`.
        let or_expr = ExprParser::parse(Rule::expression, expr)?
            .next()
            .unwrap()
            .into_inner()
            .next()
            .unwrap();

        fn parse_inner(pair: Pair<'_, Rule>) -> Result<Expr> {
            // We're parsing a pest grammar, which isn't left-recursive.
            // As a result, we have constructions like
            // `or_expr = { and_expr ~ ("||" ~ and_expr)* }`, which
            // result in wonky ASTs like one or many (>2) headed ORs.
            // We turn these into sane looking ASTs by punching the single
            // pairs down to their primitive type and folding the
            // many-headed pairs appropriately.
            // For example, `or_expr` matches the `1` one but punches through
            // to `Number(1)`, and also matches `true || true || true` which
            // becomes `BinOp(BinOp(true, true), true)`.

            match pair.as_rule() {
                Rule::or_expr => {
                    let mut pairs = pair.into_inner();
                    let lhs = parse_inner(pairs.next().unwrap())?;
                    pairs.try_fold(lhs, |expr, next| {
                        Ok(Expr::BinOp {
                            lhs: expr.into(),
                            op: BinOp::Or,
                            rhs: parse_inner(next)?.into(),
                        })
                    })
                }
                Rule::and_expr => {
                    let mut pairs = pair.into_inner();
                    let lhs = parse_inner(pairs.next().unwrap())?;
                    pairs.try_fold(lhs, |expr, next| {
                        Ok(Expr::BinOp {
                            lhs: expr.into(),
                            op: BinOp::And,
                            rhs: parse_inner(next)?.into(),
                        })
                    })
                }
                Rule::eq_expr => {
                    // eq_expr matches both `==` and `!=` and captures
                    // them in the `eq_op` capture, so we fold with
                    // two-tuples of (eq_op, comp_expr).
                    let mut pairs = pair.into_inner();
                    let lhs = parse_inner(pairs.next().unwrap())?;

                    let pair_chunks = pairs.chunks(2);
                    pair_chunks.into_iter().try_fold(lhs, |expr, mut next| {
                        let eq_op = next.next().unwrap();
                        let comp_expr = next.next().unwrap();

                        let eq_op = match eq_op.as_str() {
                            "==" => BinOp::Eq,
                            "!=" => BinOp::Neq,
                            _ => unreachable!(),
                        };

                        Ok(Expr::BinOp {
                            lhs: expr.into(),
                            op: eq_op,
                            rhs: parse_inner(comp_expr)?.into(),
                        })
                    })
                }
                Rule::comp_expr => {
                    // Same as eq_expr, but with comparison operators.
                    let mut pairs = pair.into_inner();
                    let lhs = parse_inner(pairs.next().unwrap())?;

                    let pair_chunks = pairs.chunks(2);
                    pair_chunks.into_iter().try_fold(lhs, |expr, mut next| {
                        let comp_op = next.next().unwrap();
                        let unary_expr = next.next().unwrap();

                        let eq_op = match comp_op.as_str() {
                            ">" => BinOp::Gt,
                            ">=" => BinOp::Ge,
                            "<" => BinOp::Lt,
                            "<=" => BinOp::Le,
                            _ => unreachable!(),
                        };

                        Ok(Expr::BinOp {
                            lhs: expr.into(),
                            op: eq_op,
                            rhs: parse_inner(unary_expr)?.into(),
                        })
                    })
                }
                Rule::unary_expr => {
                    let mut pairs = pair.into_inner();
                    let pair = pairs.next().unwrap();

                    match pair.as_rule() {
                        Rule::unary_op => Ok(Expr::UnOp {
                            op: UnOp::Not,
                            expr: parse_inner(pairs.next().unwrap())?.into(),
                        }),
                        Rule::primary_expr => parse_inner(pair),
                        _ => unreachable!(),
                    }
                }
                Rule::primary_expr => {
                    // Punt back to the top level match to keep things simple.
                    parse_inner(pair.into_inner().next().unwrap())
                }
                Rule::number => Ok(Expr::Number(pair.as_str().parse().unwrap())),
                Rule::string => Ok(Expr::String(
                    // string -> string_inner
                    pair.into_inner()
                        .next()
                        .unwrap()
                        .as_str()
                        .replace("''", "'"),
                )),
                Rule::boolean => Ok(Expr::Boolean(pair.as_str().parse().unwrap())),
                Rule::null => Ok(Expr::Null),
                Rule::index => {
                    // (context | function (expr))[expr]
                    let mut pairs = pair.into_inner();

                    Ok(Expr::Index {
                        parent: parse_inner(pairs.next().unwrap())?.into(),
                        index: parse_inner(pairs.next().unwrap())?.into(),
                    })
                }
                Rule::function_call => {
                    let mut pairs = pair.into_inner();

                    let identifier = pairs.next().unwrap();
                    let args: Vec<Box<Expr>> = pairs
                        .map(|pair| parse_inner(pair).map(Box::new))
                        .collect::<Result<_, _>>()?;

                    Ok(Expr::Call {
                        func: identifier.as_str().into(),
                        args: args.into(),
                    })
                }
                Rule::context_reference => Ok(Expr::ContextRef(pair.as_str().into())),
                r => panic!("fuck: {r:?}"),
            }
        }

        parse_inner(or_expr)
    }
}

#[cfg(test)]
mod tests {
    use pest::Parser as _;

    use super::{BinOp, Expr, ExprParser, Rule, UnOp};

    #[test]
    fn test_parse_string_rule() {
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
    fn test_parse_ident_rule() {
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
    fn test_parse_call_rule() {
        let cases = &[
            "foo()",
            "foo(bar)",
            "foo(bar())",
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
    fn test_parse_expr_rule() {
        let cases = &[
            "fromJSON(inputs.free-threading) && '--disable-gil' || ''",
            "foo || bar || baz",
            "foo || bar && baz || foo && 1 && 2 && 3 || 4",
        ];

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

    #[test]
    fn test_parse() {
        let cases = &[
            (
                "!true || false || true",
                Expr::BinOp {
                    lhs: Expr::BinOp {
                        lhs: Expr::UnOp {
                            op: UnOp::Not,
                            expr: Expr::Boolean(true).into(),
                        }
                        .into(),
                        op: BinOp::Or,
                        rhs: Expr::Boolean(false).into(),
                    }
                    .into(),
                    op: BinOp::Or,
                    rhs: Expr::Boolean(true).into(),
                },
            ),
            ("'foo '' bar'", Expr::String("foo ' bar".into())),
            ("('foo '' bar')", Expr::String("foo ' bar".into())),
            ("((('foo '' bar')))", Expr::String("foo ' bar".into())),
            (
                "foo(1, 2, 3)",
                Expr::Call {
                    func: "foo".into(),
                    args: vec![
                        Expr::Number(1.0).into(),
                        Expr::Number(2.0).into(),
                        Expr::Number(3.0).into(),
                    ],
                },
            ),
            ("foo.bar.baz", Expr::ContextRef("foo.bar.baz".into())),
            (
                "foo.bar.baz[1]",
                Expr::Index {
                    parent: Expr::ContextRef("foo.bar.baz".into()).into(),
                    index: Expr::Number(1.0).into(),
                },
            ),
        ];

        for (case, expr) in cases {
            assert_eq!(Expr::parse(&case).unwrap(), *expr);
        }
    }
}
