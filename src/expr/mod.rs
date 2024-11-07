//! Expression parsing and analysis.

use anyhow::Result;
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
    /// The `*` literal within an index.
    Star,
    /// An index operation.
    ///
    /// Three different kinds of expressions can be indexed:
    ///
    /// ```
    /// functionCall[expr]
    /// context.reference[expr]
    /// (<arbitrary expression>)[expr]
    /// ```
    ///
    /// Arbitrarily many nestings of indices are allowed,
    /// e.g. `functionCall()[1][2][3]`.
    Index {
        parent: Box<Expr>,
        indices: Vec<Expr>,
    },
    /// A function call.
    Call { func: String, args: Vec<Expr> },
    /// A context reference.
    // TODO: This should probably be a vec of parts internally,
    // to expose the individual component/star parts.
    Context(String),
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
    /// Convenience API for making a boxed `Expr::String`.
    pub(crate) fn string(s: impl Into<String>) -> Box<Self> {
        Self::String(s.into()).into()
    }

    /// Returns all of the contexts used in this expression, regardless
    /// of dataflow.
    pub(crate) fn contexts(&self) -> Vec<&str> {
        let mut contexts = vec![];

        match self {
            Expr::Index { parent, indices } => {
                contexts.extend(parent.contexts());

                for index in indices {
                    contexts.extend(index.contexts());
                }
            }
            Expr::Call { func: _, args } => {
                for arg in args {
                    contexts.extend(arg.contexts());
                }
            }
            Expr::Context(ctx) => contexts.push(ctx.as_str()),
            Expr::BinOp { lhs, op: _, rhs } => {
                contexts.extend(lhs.contexts());
                contexts.extend(rhs.contexts());
            }
            Expr::UnOp { op: _, expr } => contexts.extend(expr.contexts()),
            Expr::Number(_) | Expr::String(_) | Expr::Boolean(_) | Expr::Null | Expr::Star => (),
        }

        contexts
    }

    pub(crate) fn parse(expr: &str) -> Result<Expr> {
        // Top level `expression` is a single `or_expr`.
        let or_expr = ExprParser::parse(Rule::expression, expr)?
            .next()
            .unwrap()
            .into_inner()
            .next()
            .unwrap();

        fn parse_pair(pair: Pair<'_, Rule>) -> Result<Box<Expr>> {
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
                    let lhs = parse_pair(pairs.next().unwrap())?;
                    pairs.try_fold(lhs, |expr, next| {
                        Ok(Expr::BinOp {
                            lhs: expr,
                            op: BinOp::Or,
                            rhs: parse_pair(next)?,
                        }
                        .into())
                    })
                }
                Rule::and_expr => {
                    let mut pairs = pair.into_inner();
                    let lhs = parse_pair(pairs.next().unwrap())?;
                    pairs.try_fold(lhs, |expr, next| {
                        Ok(Expr::BinOp {
                            lhs: expr,
                            op: BinOp::And,
                            rhs: parse_pair(next)?,
                        }
                        .into())
                    })
                }
                Rule::eq_expr => {
                    // eq_expr matches both `==` and `!=` and captures
                    // them in the `eq_op` capture, so we fold with
                    // two-tuples of (eq_op, comp_expr).
                    let mut pairs = pair.into_inner();
                    let lhs = parse_pair(pairs.next().unwrap())?;

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
                            lhs: expr,
                            op: eq_op,
                            rhs: parse_pair(comp_expr)?,
                        }
                        .into())
                    })
                }
                Rule::comp_expr => {
                    // Same as eq_expr, but with comparison operators.
                    let mut pairs = pair.into_inner();
                    let lhs = parse_pair(pairs.next().unwrap())?;

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
                            lhs: expr,
                            op: eq_op,
                            rhs: parse_pair(unary_expr)?,
                        }
                        .into())
                    })
                }
                Rule::unary_expr => {
                    let mut pairs = pair.into_inner();
                    let pair = pairs.next().unwrap();

                    match pair.as_rule() {
                        Rule::unary_op => Ok(Expr::UnOp {
                            op: UnOp::Not,
                            expr: parse_pair(pairs.next().unwrap())?,
                        }
                        .into()),
                        Rule::primary_expr => parse_pair(pair),
                        _ => unreachable!(),
                    }
                }
                Rule::primary_expr => {
                    // Punt back to the top level match to keep things simple.
                    parse_pair(pair.into_inner().next().unwrap())
                }
                Rule::number => Ok(Expr::Number(pair.as_str().parse().unwrap()).into()),
                Rule::string => Ok(Expr::string(
                    // string -> string_inner
                    pair.into_inner()
                        .next()
                        .unwrap()
                        .as_str()
                        .replace("''", "'"),
                )),
                Rule::boolean => Ok(Expr::Boolean(pair.as_str().parse().unwrap()).into()),
                Rule::null => Ok(Expr::Null.into()),
                Rule::star => Ok(Expr::Star.into()),
                Rule::index => {
                    // (context | function (expr))[expr]+
                    let mut pairs = pair.into_inner();

                    Ok(Expr::Index {
                        parent: parse_pair(pairs.next().unwrap())?,
                        indices: pairs
                            .map(|pair| parse_pair(pair).map(|e| *e))
                            .collect::<Result<_, _>>()?,
                    }
                    .into())
                }
                Rule::function_call => {
                    let mut pairs = pair.into_inner();

                    let identifier = pairs.next().unwrap();
                    let args = pairs
                        .map(|pair| parse_pair(pair).map(|e| *e))
                        .collect::<Result<_, _>>()?;

                    Ok(Expr::Call {
                        func: identifier.as_str().into(),
                        args,
                    }
                    .into())
                }
                Rule::context => Ok(Expr::Context(pair.as_str().into()).into()),
                r => panic!("fuck: {r:?}"),
            }
        }

        parse_pair(or_expr).map(|e| *e)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use pest::Parser as _;
    use pretty_assertions::assert_eq;

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
    fn test_parse_context_rule() {
        let cases = &[
            "foo.bar",
            "github.action_path",
            "inputs.foo-bar",
            "inputs.also--valid",
            "inputs.this__too",
            "inputs.this__too",
            "secrets.GH_TOKEN",
            "foo.*.bar",
            "github.event.issue.labels.*.name",
        ];

        for case in cases {
            assert_eq!(
                ExprParser::parse(Rule::context, case)
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
    fn test_parse_expr_rule() -> Result<()> {
        let cases = &[
            "fromJSON(inputs.free-threading) && '--disable-gil' || ''",
            "foo || bar || baz",
            "foo || bar && baz || foo && 1 && 2 && 3 || 4",
            "(github.actor != 'github-actions[bot]' && github.actor) || 'BrewTestBot'",
            "(true || false) == true",
            "!(!true || false)",
            "!(!true || false) == true",
            "(true == false) == true",
            "(true == (false || true && (true || false))) == true",
            "(github.actor != 'github-actions[bot]' && github.actor) == 'BrewTestBot'",
        ];

        for case in cases {
            assert_eq!(
                ExprParser::parse(Rule::expression, case)?
                    .next()
                    .unwrap()
                    .as_str(),
                *case
            );
        }

        Ok(())
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
            ("'foo '' bar'", *Expr::string("foo ' bar")),
            ("('foo '' bar')", *Expr::string("foo ' bar")),
            ("((('foo '' bar')))", *Expr::string("foo ' bar")),
            (
                "foo(1, 2, 3)",
                Expr::Call {
                    func: "foo".into(),
                    args: vec![Expr::Number(1.0), Expr::Number(2.0), Expr::Number(3.0)],
                },
            ),
            ("foo.bar.baz", Expr::Context("foo.bar.baz".into())),
            (
                "foo.bar.baz[1][2]",
                Expr::Index {
                    parent: Expr::Context("foo.bar.baz".into()).into(),
                    indices: vec![Expr::Number(1.0), Expr::Number(2.0)],
                },
            ),
            (
                "foo.bar.baz[*]",
                Expr::Index {
                    parent: Expr::Context("foo.bar.baz".into()).into(),
                    indices: vec![Expr::Star],
                },
            ),
            (
                "vegetables.*.ediblePortions",
                Expr::Context("vegetables.*.ediblePortions".into()),
            ),
            (
                // Sanity check for our associativity: the top level Expr here
                // should be `BinOp::Or`.
                "github.ref == 'refs/heads/main' && 'value_for_main_branch' || 'value_for_other_branches'",
                Expr::BinOp {
                    lhs: Expr::BinOp {
                        lhs: Expr::BinOp {
                            lhs: Expr::Context(
                                "github.ref".into(),
                            ).into(),
                            op: BinOp::Eq,
                            rhs: Expr::string("refs/heads/main"),
                        }.into(),
                        op: BinOp::And,
                        rhs: Expr::string("value_for_main_branch"),
                    }.into(),
                    op: BinOp::Or,
                    rhs: Expr::string("value_for_other_branches"),
                }
            ),
            (
                "(true || false) == true",
                Expr::BinOp {
                    lhs: Expr::BinOp {
                        lhs: Expr::Boolean(true).into(),
                        op: BinOp::Or,
                        rhs: Expr::Boolean(false).into()
                    }.into(),
                    op: BinOp::Eq,
                    rhs: Expr::Boolean(true).into()
                }
            ),
            (
                "!(!true || false)",
                Expr::UnOp {
                    op: UnOp::Not,
                    expr: Expr::BinOp {
                        lhs: Expr::UnOp {
                            op: UnOp::Not,
                            expr: Expr::Boolean(true).into()
                        }.into(),
                    op: BinOp::Or, rhs: Expr::Boolean(false).into()
                    }.into()
                }
            )
        ];

        for (case, expr) in cases {
            assert_eq!(Expr::parse(case).unwrap(), *expr);
        }
    }

    #[test]
    fn test_expr_contexts() {
        let expr = Expr::parse("foo.bar && abc && d.e.f").unwrap();

        assert_eq!(expr.contexts(), ["foo.bar", "abc", "d.e.f"]);
    }
}
