//! GitHub Actions expression parsing and analysis.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use crate::context::Context;

use self::parser::{ExprParser, Rule};
use anyhow::Result;
use itertools::Itertools;
use pest::{Parser, iterators::Pair};

pub mod context;

// Isolates the ExprParser, Rule and other generated types
// so that we can do `missing_docs` at the top-level.
// See: https://github.com/pest-parser/pest/issues/326
mod parser {
    use pest_derive::Parser;

    /// A parser for GitHub Actions' expression language.
    #[derive(Parser)]
    #[grammar = "expr.pest"]
    pub struct ExprParser;
}

/// Represents a function in a GitHub Actions expression.
///
/// Function names are case-insensitive.
#[derive(Debug)]
pub struct Function<'src>(pub(crate) &'src str);

impl PartialEq for Function<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(other.0)
    }
}
impl PartialEq<str> for Function<'_> {
    fn eq(&self, other: &str) -> bool {
        self.0.eq_ignore_ascii_case(other)
    }
}

/// Represents a single identifier in a GitHub Actions expression,
/// i.e. a single context component.
///
/// Identifiers are case-insensitive.
#[derive(Debug)]
pub struct Identifier<'src>(&'src str);

impl PartialEq for Identifier<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(other.0)
    }
}

impl PartialEq<str> for Identifier<'_> {
    fn eq(&self, other: &str) -> bool {
        self.0.eq_ignore_ascii_case(other)
    }
}

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

/// Represents a GitHub Actions expression.
#[derive(Debug, PartialEq)]
pub enum Expr<'src> {
    /// A number literal.
    Number(f64),
    /// A string literal.
    String(String),
    /// A boolean literal.
    Boolean(bool),
    /// The `null` literal.
    Null,
    /// The `*` literal within an index or context.
    Star,
    /// A function call.
    Call {
        /// The function name, e.g. `foo` in `foo()`.
        func: Function<'src>,
        /// The function's arguments.
        args: Vec<Expr<'src>>,
    },
    /// A context identifier component, e.g. `github` in `github.actor`.
    Identifier(Identifier<'src>),
    /// A context index component, e.g. `[0]` in `foo[0]`.
    Index(Box<Expr<'src>>),
    /// A full context reference.
    Context(Context<'src>),
    /// A binary operation, either logical or arithmetic.
    BinOp {
        /// The LHS of the binop.
        lhs: Box<Expr<'src>>,
        /// The binary operator.
        op: BinOp,
        /// The RHS of the binop.
        rhs: Box<Expr<'src>>,
    },
    /// A unary operation. Negation (`!`) is currently the only `UnOp`.
    UnOp {
        /// The unary operator.
        op: UnOp,
        /// The expression to apply the operator to.
        expr: Box<Expr<'src>>,
    },
}

impl<'src> Expr<'src> {
    /// Convenience API for making a boxed [`Expr::String`].
    fn string(s: impl Into<String>) -> Box<Self> {
        Self::String(s.into()).into()
    }

    /// Convenience API for making an [`Expr::Identifier`].
    fn ident(i: &'src str) -> Self {
        Self::Identifier(Identifier(i))
    }

    /// Convenience API for making an [`Expr::Context`].
    fn context(r: &'src str, components: impl Into<Vec<Expr<'src>>>) -> Self {
        Self::Context(Context::new(r, components))
    }

    /// Returns whether the expression is a literal.
    fn is_literal(&self) -> bool {
        matches!(
            self,
            Expr::Number(_) | Expr::String(_) | Expr::Boolean(_) | Expr::Null
        )
    }

    /// Returns whether the expression is constant reducible.
    ///
    /// "Constant reducible" is similar to "constant foldable" but with
    /// meta-evaluation semantics: the expression `5` would not be
    /// constant foldable in a normal program (because it's already
    /// an atom), but is "constant reducible" in a GitHub Actions expression
    /// because an expression containing it (e.g. `${{ 5 }}`) can be elided
    /// entirely and replaced with `5`.
    ///
    /// There are three kinds of reducible expressions:
    ///
    /// 1. Literals, which reduce to their literal value;
    /// 2. Binops/unops with reducible subexpressions, which reduce
    ///    to their evaluation;
    /// 3. Select function calls where the semantics of the function
    ///    mean that reducible arguments make the call itself reducible.
    ///
    /// NOTE: This implementation is sound but not complete.
    pub fn constant_reducible(&self) -> bool {
        match self {
            // Literals are always reducible.
            Expr::Number(_) | Expr::String(_) | Expr::Boolean(_) | Expr::Null => true,
            // Binops are reducible if their LHS and RHS are reducible.
            Expr::BinOp { lhs, op: _, rhs } => lhs.constant_reducible() && rhs.constant_reducible(),
            // Unops are reducible if their interior expression is reducible.
            Expr::UnOp { op: _, expr } => expr.constant_reducible(),
            Expr::Call { func, args } => {
                // These functions are reducible if their arguments are reducible.
                if func == "format"
                    || func == "contains"
                    || func == "startsWith"
                    || func == "endsWith"
                {
                    args.iter().all(Expr::constant_reducible)
                } else {
                    // TODO: fromJSON(toJSON(...)) and vice versa.
                    false
                }
            }
            // Everything else is presumed non-reducible.
            _ => false,
        }
    }

    /// Like [`Self::constant_reducible`], but for all subexpressions
    /// rather than the top-level expression.
    ///
    /// This has slightly different semantics than `constant_reducible`:
    /// it doesn't include "trivially" reducible expressions like literals,
    /// since flagging these as reducible within a larger expression
    /// would be misleading.
    pub fn has_constant_reducible_subexpr(&self) -> bool {
        if !self.is_literal() && self.constant_reducible() {
            return true;
        }

        match self {
            Expr::Call { func: _, args } => args.iter().any(|a| a.has_constant_reducible_subexpr()),
            Expr::Context(ctx) => {
                // contexts themselves are never reducible, but they might
                // contains reducible index subexpressions.
                ctx.parts.iter().any(|c| c.has_constant_reducible_subexpr())
            }
            Expr::BinOp { lhs, op: _, rhs } => {
                lhs.has_constant_reducible_subexpr() || rhs.has_constant_reducible_subexpr()
            }
            Expr::UnOp { op: _, expr } => expr.has_constant_reducible_subexpr(),

            Expr::Index(expr) => expr.has_constant_reducible_subexpr(),
            _ => false,
        }
    }

    /// Returns the contexts in this expression that directly flow into the
    /// expression's evaluation.
    ///
    /// For example `${{ foo.bar }}` returns `foo.bar` since the value
    /// of `foo.bar` flows into the evaluation. On the other hand,
    /// `${{ foo.bar == 'abc' }}` returns no expanded contexts,
    /// since the value of `foo.bar` flows into a boolean evaluation
    /// that gets expanded.
    pub fn dataflow_contexts(&self) -> Vec<&Context> {
        let mut contexts = vec![];

        match self {
            Expr::Call { func, args } => {
                // These functions, when evaluated, produce an evaluation
                // that includes some or all of the contexts listed in
                // their arguments.
                if func == "toJSON" || func == "format" || func == "join" {
                    for arg in args {
                        contexts.extend(arg.dataflow_contexts());
                    }
                }
            }
            // NOTE: We intentionally don't handle the `func(...).foo.bar`
            // case differently here, since a call followed by a
            // context access *can* flow into the evaluation.
            // For example, `${{ fromJSON(something) }}` evaluates to
            // `Object` but `${{ fromJSON(something).foo }}` evaluates
            // to the contents of `something.foo`.
            Expr::Context(ctx) => contexts.push(ctx),
            Expr::BinOp { lhs, op, rhs } => match op {
                // With && only the RHS can flow into the evaluation as a context
                // (rather than a boolean).
                BinOp::And => {
                    contexts.extend(rhs.dataflow_contexts());
                }
                // With || either the LHS or RHS can flow into the evaluation as a context.
                BinOp::Or => {
                    contexts.extend(lhs.dataflow_contexts());
                    contexts.extend(rhs.dataflow_contexts());
                }
                _ => (),
            },
            _ => (),
        }

        contexts
    }

    /// Parses the given string into an expression.
    pub fn parse(expr: &str) -> Result<Expr> {
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
                Rule::function_call => {
                    let mut pairs = pair.into_inner();

                    let identifier = pairs.next().unwrap();
                    let args = pairs
                        .map(|pair| parse_pair(pair).map(|e| *e))
                        .collect::<Result<_, _>>()?;

                    Ok(Expr::Call {
                        func: Function(identifier.as_str()),
                        args,
                    }
                    .into())
                }
                Rule::identifier => Ok(Expr::ident(pair.as_str()).into()),
                Rule::index => {
                    Ok(Expr::Index(parse_pair(pair.into_inner().next().unwrap())?).into())
                }
                Rule::context => {
                    let raw = pair.as_str();
                    let pairs = pair.into_inner();

                    let mut inner: Vec<Expr> = pairs
                        .map(|pair| parse_pair(pair).map(|e| *e))
                        .collect::<Result<_, _>>()?;

                    // NOTE(ww): Annoying specialization: the `context` rule
                    // wholly encloses the `function_call` rule, so we clean up
                    // the AST slightly to turn `Context { Call }` into just `Call`.
                    if inner.len() == 1 && matches!(inner[0], Expr::Call { .. }) {
                        Ok(inner.remove(0).into())
                    } else {
                        Ok(Expr::context(raw, inner).into())
                    }
                }
                r => panic!("unrecognized rule: {r:?}"),
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

    use super::{BinOp, Expr, ExprParser, Function, Rule, UnOp};

    #[test]
    fn test_function_eq() {
        let func = Function("foo");
        assert_eq!(&func, "foo");
        assert_eq!(&func, "FOO");
        assert_eq!(&func, "Foo");

        assert_eq!(func, Function("FOO"));
    }

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
        // Ensures that we parse multi-line expressions correctly.
        let multiline = "github.repository_owner == 'Homebrew' &&
        ((github.event_name == 'pull_request_review' && github.event.review.state == 'approved') ||
        (github.event_name == 'pull_request_target' &&
        (github.event.action == 'ready_for_review' || github.event.label.name == 'automerge-skip')))";

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
            "foo()[0]",
            "fromJson(steps.runs.outputs.data).workflow_runs[0].id",
            multiline,
            "'a' == 'b' && 'c' || 'd'",
            "github.event['a']",
            "github.event['a' == 'b']",
            "github.event['a' == 'b' && 'c' || 'd']",
            "github['event']['inputs']['dry-run']",
            "github[format('{0}', 'event')]",
            "github['event']['inputs'][github.event.inputs.magic]",
            "github['event']['inputs'].*",
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
                    func: Function("foo"),
                    args: vec![Expr::Number(1.0), Expr::Number(2.0), Expr::Number(3.0)],
                },
            ),
            (
                "foo.bar.baz",
                Expr::context(
                    "foo.bar.baz",
                    [Expr::ident("foo"), Expr::ident("bar"), Expr::ident("baz")],
                ),
            ),
            (
                "foo.bar.baz[1][2]",
                Expr::context(
                    "foo.bar.baz[1][2]",
                    [
                        Expr::ident("foo"),
                        Expr::ident("bar"),
                        Expr::ident("baz"),
                        Expr::Index(Expr::Number(1.0).into()),
                        Expr::Index(Expr::Number(2.0).into()),
                    ],
                ),
            ),
            (
                "foo.bar.baz[*]",
                Expr::context(
                    "foo.bar.baz[*]",
                    [
                        Expr::ident("foo"),
                        Expr::ident("bar"),
                        Expr::ident("baz"),
                        Expr::Index(Expr::Star.into()),
                    ],
                ),
            ),
            (
                "vegetables.*.ediblePortions",
                Expr::context(
                    "vegetables.*.ediblePortions",
                    vec![
                        Expr::ident("vegetables"),
                        Expr::Star,
                        Expr::ident("ediblePortions"),
                    ],
                ),
            ),
            (
                // Sanity check for our associativity: the top level Expr here
                // should be `BinOp::Or`.
                "github.ref == 'refs/heads/main' && 'value_for_main_branch' || 'value_for_other_branches'",
                Expr::BinOp {
                    lhs: Expr::BinOp {
                        lhs: Expr::BinOp {
                            lhs: Expr::context(
                                "github.ref",
                                [Expr::ident("github"), Expr::ident("ref")],
                            )
                            .into(),
                            op: BinOp::Eq,
                            rhs: Expr::string("refs/heads/main"),
                        }
                        .into(),
                        op: BinOp::And,
                        rhs: Expr::string("value_for_main_branch"),
                    }
                    .into(),
                    op: BinOp::Or,
                    rhs: Expr::string("value_for_other_branches"),
                },
            ),
            (
                "(true || false) == true",
                Expr::BinOp {
                    lhs: Expr::BinOp {
                        lhs: Expr::Boolean(true).into(),
                        op: BinOp::Or,
                        rhs: Expr::Boolean(false).into(),
                    }
                    .into(),
                    op: BinOp::Eq,
                    rhs: Expr::Boolean(true).into(),
                },
            ),
            (
                "!(!true || false)",
                Expr::UnOp {
                    op: UnOp::Not,
                    expr: Expr::BinOp {
                        lhs: Expr::UnOp {
                            op: UnOp::Not,
                            expr: Expr::Boolean(true).into(),
                        }
                        .into(),
                        op: BinOp::Or,
                        rhs: Expr::Boolean(false).into(),
                    }
                    .into(),
                },
            ),
            (
                "foobar[format('{0}', 'event')]",
                Expr::context(
                    "foobar[format('{0}', 'event')]",
                    [
                        Expr::ident("foobar"),
                        Expr::Index(
                            Expr::Call {
                                func: Function("format"),
                                args: vec![*Expr::string("{0}"), *Expr::string("event")],
                            }
                            .into(),
                        ),
                    ],
                ),
            ),
        ];

        for (case, expr) in cases {
            assert_eq!(Expr::parse(case).unwrap(), *expr);
        }
    }

    #[test]
    fn test_expr_constant_reducible() -> Result<()> {
        for (expr, reducible) in &[
            ("'foo'", true),
            ("1", true),
            ("true", true),
            ("null", true),
            // boolean and unary expressions of all literals are
            // always reducible.
            ("!true", true),
            ("!null", true),
            ("true && false", true),
            ("true || false", true),
            ("null && !null && true", true),
            // formats/contains/startsWith/endsWith are reducible
            // if all of their arguments are reducible.
            ("format('{0} {1}', 'foo', 'bar')", true),
            ("format('{0} {1}', 1, 2)", true),
            ("format('{0} {1}', 1, '2')", true),
            ("contains('foo', 'bar')", true),
            ("startsWith('foo', 'bar')", true),
            ("endsWith('foo', 'bar')", true),
            ("startsWith(some.context, 'bar')", false),
            ("endsWith(some.context, 'bar')", false),
            // Nesting works as long as the nested call is also reducible.
            ("format('{0} {1}', '1', format('{0}', null))", true),
            ("format('{0} {1}', '1', startsWith('foo', 'foo'))", true),
            ("format('{0} {1}', '1', startsWith(foo.bar, 'foo'))", false),
            ("foo", false),
            ("foo.bar", false),
            ("foo.bar[1]", false),
            ("foo.bar == 'bar'", false),
            ("foo.bar || bar || baz", false),
            ("foo.bar && bar && baz", false),
        ] {
            let expr = Expr::parse(expr)?;
            assert_eq!(expr.constant_reducible(), *reducible);
        }

        Ok(())
    }

    #[test]
    fn test_expr_has_constant_reducible_subexpr() -> Result<()> {
        for (expr, reducible) in &[
            // Literals are not considered reducible subexpressions.
            ("'foo'", false),
            ("1", false),
            ("true", false),
            ("null", false),
            // Non-reducible expressions with reducible subexpressions
            (
                "format('{0}, {1}', github.event.number, format('{0}', 'abc'))",
                true,
            ),
            ("foobar[format('{0}', 'event')]", true),
        ] {
            let expr = Expr::parse(expr)?;
            assert_eq!(expr.has_constant_reducible_subexpr(), *reducible);
        }
        Ok(())
    }

    #[test]
    fn test_expr_dataflow_contexts() -> Result<()> {
        // Trivial cases.
        let expr = Expr::parse("foo.bar")?;
        assert_eq!(expr.dataflow_contexts(), ["foo.bar"]);

        let expr = Expr::parse("foo.bar[1]")?;
        assert_eq!(expr.dataflow_contexts(), ["foo.bar[1]"]);

        // No dataflow due to a boolean expression.
        let expr = Expr::parse("foo.bar == 'bar'")?;
        assert!(expr.dataflow_contexts().is_empty());

        // ||: all contexts potentially expand into the evaluation.
        let expr = Expr::parse("foo.bar || abc || d.e.f")?;
        assert_eq!(expr.dataflow_contexts(), ["foo.bar", "abc", "d.e.f"]);

        // &&: only the RHS context(s) expand into the evaluation.
        let expr = Expr::parse("foo.bar && abc && d.e.f")?;
        assert_eq!(expr.dataflow_contexts(), ["d.e.f"]);

        let expr = Expr::parse("foo.bar == 'bar' && foo.bar || 'false'")?;
        assert_eq!(expr.dataflow_contexts(), ["foo.bar"]);

        let expr = Expr::parse("foo.bar == 'bar' && foo.bar || foo.baz")?;
        assert_eq!(expr.dataflow_contexts(), ["foo.bar", "foo.baz"]);

        let expr = Expr::parse("fromJson(steps.runs.outputs.data).workflow_runs[0].id")?;
        assert_eq!(
            expr.dataflow_contexts(),
            ["fromJson(steps.runs.outputs.data).workflow_runs[0].id"]
        );

        let expr = Expr::parse("format('{0} {1} {2}', foo.bar, tojson(github), toJSON(github))")?;
        assert_eq!(expr.dataflow_contexts(), ["foo.bar", "github", "github"]);

        Ok(())
    }
}
