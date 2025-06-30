//! GitHub Actions expression parsing and analysis.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::{borrow::Cow, ops::Deref};

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

impl Identifier<'_> {
    /// Returns the identifier as a string slice, as it appears in the
    /// expression.
    ///
    /// Important: identifiers are case-insensitive, so this should not
    /// be used for comparisons.
    pub fn as_str(&self) -> &str {
        self.0
    }
}

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
}

// TODO: Move this type to some kind of common crate? It's useful to have
// a single span type everywhere, instead of the current mash of span helpers
// and ranges we have throughout zizmor.
/// Represents a `[start, end)` byte span for a source expression.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Span {
    /// The start of the span, inclusive.
    pub start: usize,
    /// The end of the span, exclusive.
    pub end: usize,
}

impl Span {
    /// Adjust this span by the given bias.
    pub fn adjust(self, bias: usize) -> Self {
        Self {
            start: self.start + bias,
            end: self.end + bias,
        }
    }
}

impl From<pest::Span<'_>> for Span {
    fn from(span: pest::Span<'_>) -> Self {
        Self {
            start: span.start(),
            end: span.end(),
        }
    }
}

impl From<std::ops::Range<usize>> for Span {
    fn from(range: std::ops::Range<usize>) -> Self {
        Self {
            start: range.start,
            end: range.end,
        }
    }
}

impl From<Span> for std::ops::Range<usize> {
    fn from(span: Span) -> Self {
        span.start..span.end
    }
}

/// Represents the origin of an expression, including its source span
/// and unparsed form.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Origin<'src> {
    /// The expression's source span.
    pub span: Span,
    /// The expression's unparsed form, as it appears in the source.
    ///
    /// This is recorded exactly as it appears in the source, *except*
    /// that leading and trailing whitespace is stripped. This is stripped
    /// because it's (1) non-semantic, and (2) can cause all kinds of issues
    /// when attempting to map expressions back to YAML source features.
    pub raw: &'src str,
}

impl<'a> Origin<'a> {
    /// Create a new origin from the given span and raw form.
    pub fn new(span: impl Into<Span>, raw: &'a str) -> Self {
        Self {
            span: span.into(),
            raw: raw.trim(),
        }
    }
}

/// An expression along with its source origin (span and unparsed form).
///
/// Important: Because of how our parser works internally, an expression's
/// span is its *rule*'s span, which can be larger than the expression itself.
/// For example, `foo || bar || baz` is covered by a single rule, so each
/// decomposed `Expr::BinOp` within it will have the same span despite
/// logically having different sub-spans of the parent rule's span.
#[derive(Debug, PartialEq)]
pub struct SpannedExpr<'src> {
    /// The expression's source origin.
    pub origin: Origin<'src>,
    /// The expression itself.
    pub inner: Expr<'src>,
}

impl<'a> SpannedExpr<'a> {
    /// Creates a new `SpannedExpr` from an expression and its span.
    pub(crate) fn new(origin: Origin<'a>, inner: Expr<'a>) -> Self {
        Self { origin, inner }
    }

    /// Returns the contexts in this expression that directly flow into the
    /// expression's evaluation.
    ///
    /// For example `${{ foo.bar }}` returns `foo.bar` since the value
    /// of `foo.bar` flows into the evaluation. On the other hand,
    /// `${{ foo.bar == 'abc' }}` returns no expanded contexts,
    /// since the value of `foo.bar` flows into a boolean evaluation
    /// that gets expanded.
    pub fn dataflow_contexts(&self) -> Vec<(&Context<'a>, &Origin<'a>)> {
        let mut contexts = vec![];

        match self.deref() {
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
            Expr::Context(ctx) => contexts.push((ctx, &self.origin)),
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

    /// Returns any computed indices in this expression.
    ///
    /// A computed index is any index operation with a non-literal
    /// evaluation, e.g. `foo[a.b.c]`.
    pub fn computed_indices(&self) -> Vec<&SpannedExpr<'a>> {
        let mut index_exprs = vec![];

        match self.deref() {
            Expr::Call { func: _, args } => {
                for arg in args {
                    index_exprs.extend(arg.computed_indices());
                }
            }
            Expr::Index(spanned_expr) => {
                // NOTE: We consider any non-literal, non-star index computed.
                if !spanned_expr.is_literal() && !matches!(spanned_expr.inner, Expr::Star) {
                    index_exprs.push(self);
                }
            }
            Expr::Context(context) => {
                for part in &context.parts {
                    index_exprs.extend(part.computed_indices());
                }
            }
            Expr::BinOp { lhs, op: _, rhs } => {
                index_exprs.extend(lhs.computed_indices());
                index_exprs.extend(rhs.computed_indices());
            }
            Expr::UnOp { op: _, expr } => {
                index_exprs.extend(expr.computed_indices());
            }
            _ => {}
        }

        index_exprs
    }

    /// Like [`Expr::constant_reducible`], but for all subexpressions
    /// rather than the top-level expression.
    ///
    /// This has slightly different semantics than `constant_reducible`:
    /// it doesn't include "trivially" reducible expressions like literals,
    /// since flagging these as reducible within a larger expression
    /// would be misleading.
    pub fn constant_reducible_subexprs(&self) -> Vec<&SpannedExpr<'a>> {
        if !self.is_literal() && self.constant_reducible() {
            return vec![self];
        }

        let mut subexprs = vec![];

        match self.deref() {
            Expr::Call { func: _, args } => {
                for arg in args {
                    subexprs.extend(arg.constant_reducible_subexprs());
                }
            }
            Expr::Context(ctx) => {
                // contexts themselves are never reducible, but they might
                // contains reducible index subexpressions.
                for part in &ctx.parts {
                    subexprs.extend(part.constant_reducible_subexprs());
                }
            }
            Expr::BinOp { lhs, op: _, rhs } => {
                subexprs.extend(lhs.constant_reducible_subexprs());
                subexprs.extend(rhs.constant_reducible_subexprs());
            }
            Expr::UnOp { op: _, expr } => subexprs.extend(expr.constant_reducible_subexprs()),

            Expr::Index(expr) => subexprs.extend(expr.constant_reducible_subexprs()),
            _ => {}
        }

        subexprs
    }
}

impl<'a> Deref for SpannedExpr<'a> {
    type Target = Expr<'a>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Represents a GitHub Actions expression.
#[derive(Debug, PartialEq)]
pub enum Expr<'src> {
    /// A literal value.
    Literal(Literal<'src>),
    /// The `*` literal within an index or context.
    Star,
    /// A function call.
    Call {
        /// The function name, e.g. `foo` in `foo()`.
        func: Function<'src>,
        /// The function's arguments.
        args: Vec<SpannedExpr<'src>>,
    },
    /// A context identifier component, e.g. `github` in `github.actor`.
    Identifier(Identifier<'src>),
    /// A context index component, e.g. `[0]` in `foo[0]`.
    Index(Box<SpannedExpr<'src>>),
    /// A full context reference.
    Context(Context<'src>),
    /// A binary operation, either logical or arithmetic.
    BinOp {
        /// The LHS of the binop.
        lhs: Box<SpannedExpr<'src>>,
        /// The binary operator.
        op: BinOp,
        /// The RHS of the binop.
        rhs: Box<SpannedExpr<'src>>,
    },
    /// A unary operation. Negation (`!`) is currently the only `UnOp`.
    UnOp {
        /// The unary operator.
        op: UnOp,
        /// The expression to apply the operator to.
        expr: Box<SpannedExpr<'src>>,
    },
}

impl<'src> Expr<'src> {
    /// Convenience API for making an [`Expr::Identifier`].
    fn ident(i: &'src str) -> Self {
        Self::Identifier(Identifier(i))
    }

    /// Convenience API for making an [`Expr::Context`].
    fn context(components: impl Into<Vec<SpannedExpr<'src>>>) -> Self {
        Self::Context(Context::new(components))
    }

    /// Returns whether the expression is a literal.
    pub fn is_literal(&self) -> bool {
        matches!(self, Expr::Literal(_))
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
            Expr::Literal(_) => true,
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
                    args.iter().all(|e| e.constant_reducible())
                } else {
                    // TODO: fromJSON(toJSON(...)) and vice versa.
                    false
                }
            }
            // Everything else is presumed non-reducible.
            _ => false,
        }
    }

    /// Parses the given string into an expression.
    pub fn parse(expr: &'src str) -> Result<SpannedExpr<'src>> {
        // Top level `expression` is a single `or_expr`.
        let or_expr = ExprParser::parse(Rule::expression, expr)?
            .next()
            .unwrap()
            .into_inner()
            .next()
            .unwrap();

        fn parse_pair(pair: Pair<'_, Rule>) -> Result<Box<SpannedExpr>> {
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
                    let (span, raw) = (pair.as_span(), pair.as_str());
                    let mut pairs = pair.into_inner();
                    let lhs = parse_pair(pairs.next().unwrap())?;
                    pairs.try_fold(lhs, |expr, next| {
                        Ok(SpannedExpr::new(
                            Origin::new(span, raw),
                            Expr::BinOp {
                                lhs: expr,
                                op: BinOp::Or,
                                rhs: parse_pair(next)?,
                            },
                        )
                        .into())
                    })
                }
                Rule::and_expr => {
                    let (span, raw) = (pair.as_span(), pair.as_str());
                    let mut pairs = pair.into_inner();
                    let lhs = parse_pair(pairs.next().unwrap())?;
                    pairs.try_fold(lhs, |expr, next| {
                        Ok(SpannedExpr::new(
                            Origin::new(span, raw),
                            Expr::BinOp {
                                lhs: expr,
                                op: BinOp::And,
                                rhs: parse_pair(next)?,
                            },
                        )
                        .into())
                    })
                }
                Rule::eq_expr => {
                    // eq_expr matches both `==` and `!=` and captures
                    // them in the `eq_op` capture, so we fold with
                    // two-tuples of (eq_op, comp_expr).
                    let (span, raw) = (pair.as_span(), pair.as_str());
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

                        Ok(SpannedExpr::new(
                            Origin::new(span, raw),
                            Expr::BinOp {
                                lhs: expr,
                                op: eq_op,
                                rhs: parse_pair(comp_expr)?,
                            },
                        )
                        .into())
                    })
                }
                Rule::comp_expr => {
                    // Same as eq_expr, but with comparison operators.
                    let (span, raw) = (pair.as_span(), pair.as_str());
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

                        Ok(SpannedExpr::new(
                            Origin::new(span, raw),
                            Expr::BinOp {
                                lhs: expr,
                                op: eq_op,
                                rhs: parse_pair(unary_expr)?,
                            },
                        )
                        .into())
                    })
                }
                Rule::unary_expr => {
                    let (span, raw) = (pair.as_span(), pair.as_str());
                    let mut pairs = pair.into_inner();
                    let inner_pair = pairs.next().unwrap();

                    match inner_pair.as_rule() {
                        Rule::unary_op => Ok(SpannedExpr::new(
                            Origin::new(span, raw),
                            Expr::UnOp {
                                op: UnOp::Not,
                                expr: parse_pair(pairs.next().unwrap())?,
                            },
                        )
                        .into()),
                        Rule::primary_expr => parse_pair(inner_pair),
                        _ => unreachable!(),
                    }
                }
                Rule::primary_expr => {
                    // Punt back to the top level match to keep things simple.
                    parse_pair(pair.into_inner().next().unwrap())
                }
                Rule::number => Ok(SpannedExpr::new(
                    Origin::new(pair.as_span(), pair.as_str()),
                    pair.as_str().parse::<f64>().unwrap().into(),
                )
                .into()),
                Rule::string => {
                    let (span, raw) = (pair.as_span(), pair.as_str());
                    // string -> string_inner
                    let string_inner = pair.into_inner().next().unwrap().as_str();

                    // Optimization: if our string literal doesn't have any
                    // escaped quotes in it, we can save ourselves a clone.
                    if !string_inner.contains('\'') {
                        Ok(SpannedExpr::new(Origin::new(span, raw), string_inner.into()).into())
                    } else {
                        Ok(SpannedExpr::new(
                            Origin::new(span, raw),
                            string_inner.replace("''", "'").into(),
                        )
                        .into())
                    }
                }
                Rule::boolean => Ok(SpannedExpr::new(
                    Origin::new(pair.as_span(), pair.as_str()),
                    pair.as_str().parse::<bool>().unwrap().into(),
                )
                .into()),
                Rule::null => Ok(SpannedExpr::new(
                    Origin::new(pair.as_span(), pair.as_str()),
                    Expr::Literal(Literal::Null),
                )
                .into()),
                Rule::star => Ok(SpannedExpr::new(
                    Origin::new(pair.as_span(), pair.as_str()),
                    Expr::Star,
                )
                .into()),
                Rule::function_call => {
                    let (span, raw) = (pair.as_span(), pair.as_str());
                    let mut pairs = pair.into_inner();

                    let identifier = pairs.next().unwrap();
                    let args = pairs
                        .map(|pair| parse_pair(pair).map(|e| *e))
                        .collect::<Result<_, _>>()?;

                    Ok(SpannedExpr::new(
                        Origin::new(span, raw),
                        Expr::Call {
                            func: Function(identifier.as_str()),
                            args,
                        },
                    )
                    .into())
                }
                Rule::identifier => Ok(SpannedExpr::new(
                    Origin::new(pair.as_span(), pair.as_str()),
                    Expr::ident(pair.as_str()),
                )
                .into()),
                Rule::index => Ok(SpannedExpr::new(
                    Origin::new(pair.as_span(), pair.as_str()),
                    Expr::Index(parse_pair(pair.into_inner().next().unwrap())?),
                )
                .into()),
                Rule::context => {
                    let (span, raw) = (pair.as_span(), pair.as_str());
                    let pairs = pair.into_inner();

                    let mut inner: Vec<SpannedExpr> = pairs
                        .map(|pair| parse_pair(pair).map(|e| *e))
                        .collect::<Result<_, _>>()?;

                    // NOTE(ww): Annoying specialization: the `context` rule
                    // wholly encloses the `function_call` rule, so we clean up
                    // the AST slightly to turn `Context { Call }` into just `Call`.
                    if inner.len() == 1 && matches!(inner[0].inner, Expr::Call { .. }) {
                        Ok(inner.remove(0).into())
                    } else {
                        Ok(SpannedExpr::new(Origin::new(span, raw), Expr::context(inner)).into())
                    }
                }
                r => panic!("unrecognized rule: {r:?}"),
            }
        }

        parse_pair(or_expr).map(|e| *e)
    }
}

impl<'src> From<&'src str> for Expr<'src> {
    fn from(s: &'src str) -> Self {
        Expr::Literal(Literal::String(s.into()))
    }
}

impl From<String> for Expr<'_> {
    fn from(s: String) -> Self {
        Expr::Literal(Literal::String(s.into()))
    }
}

impl From<f64> for Expr<'_> {
    fn from(n: f64) -> Self {
        Expr::Literal(Literal::Number(n))
    }
}

impl From<bool> for Expr<'_> {
    fn from(b: bool) -> Self {
        Expr::Literal(Literal::Boolean(b))
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use anyhow::Result;
    use pest::Parser as _;
    use pretty_assertions::assert_eq;

    use crate::{Literal, Origin, SpannedExpr};

    use super::{BinOp, Expr, ExprParser, Function, Rule, UnOp};

    #[test]
    fn test_literal_string_borrows() {
        let cases = &[
            ("'foo'", true),
            ("'foo bar'", true),
            ("'foo '' bar'", false),
            ("'foo''bar'", false),
            ("'foo''''bar'", false),
        ];

        for (expr, borrows) in cases {
            let Expr::Literal(Literal::String(s)) = &*Expr::parse(expr).unwrap() else {
                panic!("expected a literal string expression for {expr}");
            };

            assert!(matches!(
                (s, borrows),
                (Cow::Borrowed(_), true) | (Cow::Owned(_), false)
            ));
        }
    }

    #[test]
    fn test_literal_as_str() {
        let cases = &[
            ("'foo'", "foo"),
            ("'foo '' bar'", "foo ' bar"),
            ("123", "123"),
            ("123.000", "123"),
            ("0.0", "0"),
            ("0.1", "0.1"),
            ("0.12345", "0.12345"),
            ("true", "true"),
            ("false", "false"),
            ("null", "null"),
        ];

        for (expr, expected) in cases {
            let Expr::Literal(expr) = &*Expr::parse(expr).unwrap() else {
                panic!("expected a literal expression for {expr}");
            };

            assert_eq!(expr.as_str(), *expected);
        }
    }

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

        let multiline2 = "foo.bar.baz[
        0
        ]";

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
            "1 == 1",
            "1 > 1",
            "1 >= 1",
            "matrix.node_version >= 20",
            "true||false",
            multiline2,
            "fromJSON( github.event.inputs.hmm ) [ 0 ]",
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
                SpannedExpr::new(
                    Origin::new(0..22, "!true || false || true"),
                    Expr::BinOp {
                        lhs: SpannedExpr::new(
                            Origin::new(0..22, "!true || false || true"),
                            Expr::BinOp {
                                lhs: SpannedExpr::new(
                                    Origin::new(0..5, "!true"),
                                    Expr::UnOp {
                                        op: UnOp::Not,
                                        expr: SpannedExpr::new(
                                            Origin::new(1..5, "true"),
                                            true.into(),
                                        )
                                        .into(),
                                    },
                                )
                                .into(),
                                op: BinOp::Or,
                                rhs: SpannedExpr::new(Origin::new(9..14, "false"), false.into())
                                    .into(),
                            },
                        )
                        .into(),
                        op: BinOp::Or,
                        rhs: SpannedExpr::new(Origin::new(18..22, "true"), true.into()).into(),
                    },
                ),
            ),
            (
                "'foo '' bar'",
                SpannedExpr::new(
                    Origin::new(0..12, "'foo '' bar'"),
                    Expr::Literal(Literal::String("foo ' bar".into())),
                ),
            ),
            (
                "('foo '' bar')",
                SpannedExpr::new(
                    Origin::new(1..13, "'foo '' bar'"),
                    Expr::Literal(Literal::String("foo ' bar".into())),
                ),
            ),
            (
                "((('foo '' bar')))",
                SpannedExpr::new(
                    Origin::new(3..15, "'foo '' bar'"),
                    Expr::Literal(Literal::String("foo ' bar".into())),
                ),
            ),
            (
                "foo(1, 2, 3)",
                SpannedExpr::new(
                    Origin::new(0..12, "foo(1, 2, 3)"),
                    Expr::Call {
                        func: Function("foo"),
                        args: vec![
                            SpannedExpr::new(Origin::new(4..5, "1"), 1.0.into()),
                            SpannedExpr::new(Origin::new(7..8, "2"), 2.0.into()),
                            SpannedExpr::new(Origin::new(10..11, "3"), 3.0.into()),
                        ],
                    },
                ),
            ),
            (
                "foo.bar.baz",
                SpannedExpr::new(
                    Origin::new(0..11, "foo.bar.baz"),
                    Expr::context(vec![
                        SpannedExpr::new(Origin::new(0..3, "foo"), Expr::ident("foo")),
                        SpannedExpr::new(Origin::new(4..7, "bar"), Expr::ident("bar")),
                        SpannedExpr::new(Origin::new(8..11, "baz"), Expr::ident("baz")),
                    ]),
                ),
            ),
            (
                "foo.bar.baz[1][2]",
                SpannedExpr::new(
                    Origin::new(0..17, "foo.bar.baz[1][2]"),
                    Expr::context(vec![
                        SpannedExpr::new(Origin::new(0..3, "foo"), Expr::ident("foo")),
                        SpannedExpr::new(Origin::new(4..7, "bar"), Expr::ident("bar")),
                        SpannedExpr::new(Origin::new(8..11, "baz"), Expr::ident("baz")),
                        SpannedExpr::new(
                            Origin::new(11..14, "[1]"),
                            Expr::Index(Box::new(SpannedExpr::new(
                                Origin::new(12..13, "1"),
                                1.0.into(),
                            ))),
                        ),
                        SpannedExpr::new(
                            Origin::new(14..17, "[2]"),
                            Expr::Index(Box::new(SpannedExpr::new(
                                Origin::new(15..16, "2"),
                                2.0.into(),
                            ))),
                        ),
                    ]),
                ),
            ),
            (
                "foo.bar.baz[*]",
                SpannedExpr::new(
                    Origin::new(0..14, "foo.bar.baz[*]"),
                    Expr::context([
                        SpannedExpr::new(Origin::new(0..3, "foo"), Expr::ident("foo")),
                        SpannedExpr::new(Origin::new(4..7, "bar"), Expr::ident("bar")),
                        SpannedExpr::new(Origin::new(8..11, "baz"), Expr::ident("baz")),
                        SpannedExpr::new(
                            Origin::new(11..14, "[*]"),
                            Expr::Index(Box::new(SpannedExpr::new(
                                Origin::new(12..13, "*"),
                                Expr::Star,
                            ))),
                        ),
                    ]),
                ),
            ),
            (
                "vegetables.*.ediblePortions",
                SpannedExpr::new(
                    Origin::new(0..27, "vegetables.*.ediblePortions"),
                    Expr::context(vec![
                        SpannedExpr::new(
                            Origin::new(0..10, "vegetables"),
                            Expr::ident("vegetables"),
                        ),
                        SpannedExpr::new(Origin::new(11..12, "*"), Expr::Star),
                        SpannedExpr::new(
                            Origin::new(13..27, "ediblePortions"),
                            Expr::ident("ediblePortions"),
                        ),
                    ]),
                ),
            ),
            (
                // Sanity check for our associativity: the top level Expr here
                // should be `BinOp::Or`.
                "github.ref == 'refs/heads/main' && 'value_for_main_branch' || 'value_for_other_branches'",
                SpannedExpr::new(
                    Origin::new(
                        0..88,
                        "github.ref == 'refs/heads/main' && 'value_for_main_branch' || 'value_for_other_branches'",
                    ),
                    Expr::BinOp {
                        lhs: Box::new(SpannedExpr::new(
                            Origin::new(
                                0..59,
                                "github.ref == 'refs/heads/main' && 'value_for_main_branch'",
                            ),
                            Expr::BinOp {
                                lhs: Box::new(SpannedExpr::new(
                                    Origin::new(0..32, "github.ref == 'refs/heads/main'"),
                                    Expr::BinOp {
                                        lhs: Box::new(SpannedExpr::new(
                                            Origin::new(0..10, "github.ref"),
                                            Expr::context(vec![
                                                SpannedExpr::new(
                                                    Origin::new(0..6, "github"),
                                                    Expr::ident("github"),
                                                ),
                                                SpannedExpr::new(
                                                    Origin::new(7..10, "ref"),
                                                    Expr::ident("ref"),
                                                ),
                                            ]),
                                        )),
                                        op: BinOp::Eq,
                                        rhs: Box::new(SpannedExpr::new(
                                            Origin::new(14..31, "'refs/heads/main'"),
                                            Expr::Literal(Literal::String(
                                                "refs/heads/main".into(),
                                            )),
                                        )),
                                    },
                                )),
                                op: BinOp::And,
                                rhs: Box::new(SpannedExpr::new(
                                    Origin::new(35..58, "'value_for_main_branch'"),
                                    Expr::Literal(Literal::String("value_for_main_branch".into())),
                                )),
                            },
                        )),
                        op: BinOp::Or,
                        rhs: Box::new(SpannedExpr::new(
                            Origin::new(62..88, "'value_for_other_branches'"),
                            Expr::Literal(Literal::String("value_for_other_branches".into())),
                        )),
                    },
                ),
            ),
            (
                "(true || false) == true",
                SpannedExpr::new(
                    Origin::new(0..23, "(true || false) == true"),
                    Expr::BinOp {
                        lhs: Box::new(SpannedExpr::new(
                            Origin::new(1..14, "true || false"),
                            Expr::BinOp {
                                lhs: Box::new(SpannedExpr::new(
                                    Origin::new(1..5, "true"),
                                    true.into(),
                                )),
                                op: BinOp::Or,
                                rhs: Box::new(SpannedExpr::new(
                                    Origin::new(9..14, "false"),
                                    false.into(),
                                )),
                            },
                        )),
                        op: BinOp::Eq,
                        rhs: Box::new(SpannedExpr::new(Origin::new(19..23, "true"), true.into())),
                    },
                ),
            ),
            (
                "!(!true || false)",
                SpannedExpr::new(
                    Origin::new(0..17, "!(!true || false)"),
                    Expr::UnOp {
                        op: UnOp::Not,
                        expr: Box::new(SpannedExpr::new(
                            Origin::new(2..16, "!true || false"),
                            Expr::BinOp {
                                lhs: Box::new(SpannedExpr::new(
                                    Origin::new(2..7, "!true"),
                                    Expr::UnOp {
                                        op: UnOp::Not,
                                        expr: Box::new(SpannedExpr::new(
                                            Origin::new(3..7, "true"),
                                            true.into(),
                                        )),
                                    },
                                )),
                                op: BinOp::Or,
                                rhs: Box::new(SpannedExpr::new(
                                    Origin::new(11..16, "false"),
                                    false.into(),
                                )),
                            },
                        )),
                    },
                ),
            ),
            (
                "foobar[format('{0}', 'event')]",
                SpannedExpr::new(
                    Origin::new(0..30, "foobar[format('{0}', 'event')]"),
                    Expr::context([
                        SpannedExpr::new(Origin::new(0..6, "foobar"), Expr::ident("foobar")),
                        SpannedExpr::new(
                            Origin::new(6..30, "[format('{0}', 'event')]"),
                            Expr::Index(Box::new(SpannedExpr::new(
                                Origin::new(7..29, "format('{0}', 'event')"),
                                Expr::Call {
                                    func: Function("format"),
                                    args: vec![
                                        SpannedExpr::new(
                                            Origin::new(14..19, "'{0}'"),
                                            Expr::from("{0}"),
                                        ),
                                        SpannedExpr::new(
                                            Origin::new(21..28, "'event'"),
                                            Expr::from("event"),
                                        ),
                                    ],
                                },
                            ))),
                        ),
                    ]),
                ),
            ),
            (
                "github.actor_id == '49699333'",
                SpannedExpr::new(
                    Origin::new(0..29, "github.actor_id == '49699333'"),
                    Expr::BinOp {
                        lhs: SpannedExpr::new(
                            Origin::new(0..15, "github.actor_id"),
                            Expr::context(vec![
                                SpannedExpr::new(
                                    Origin::new(0..6, "github"),
                                    Expr::ident("github"),
                                ),
                                SpannedExpr::new(
                                    Origin::new(7..15, "actor_id"),
                                    Expr::ident("actor_id"),
                                ),
                            ]),
                        )
                        .into(),
                        op: BinOp::Eq,
                        rhs: Box::new(SpannedExpr::new(
                            Origin::new(19..29, "'49699333'"),
                            Expr::from("49699333"),
                        )),
                    },
                ),
            ),
        ];

        for (case, expr) in cases {
            assert_eq!(*expr, Expr::parse(case).unwrap());
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
            assert_eq!(!expr.constant_reducible_subexprs().is_empty(), *reducible);
        }
        Ok(())
    }

    #[test]
    fn test_expr_dataflow_contexts() -> Result<()> {
        // Trivial cases.
        let expr = Expr::parse("foo.bar")?;
        assert_eq!(
            expr.dataflow_contexts()
                .iter()
                .map(|t| t.1.raw)
                .collect::<Vec<_>>(),
            ["foo.bar"]
        );

        let expr = Expr::parse("foo.bar[1]")?;
        assert_eq!(
            expr.dataflow_contexts()
                .iter()
                .map(|t| t.1.raw)
                .collect::<Vec<_>>(),
            ["foo.bar[1]"]
        );

        // No dataflow due to a boolean expression.
        let expr = Expr::parse("foo.bar == 'bar'")?;
        assert!(expr.dataflow_contexts().is_empty());

        // ||: all contexts potentially expand into the evaluation.
        let expr = Expr::parse("foo.bar || abc || d.e.f")?;
        assert_eq!(
            expr.dataflow_contexts()
                .iter()
                .map(|t| t.1.raw)
                .collect::<Vec<_>>(),
            ["foo.bar", "abc", "d.e.f"]
        );

        // &&: only the RHS context(s) expand into the evaluation.
        let expr = Expr::parse("foo.bar && abc && d.e.f")?;
        assert_eq!(
            expr.dataflow_contexts()
                .iter()
                .map(|t| t.1.raw)
                .collect::<Vec<_>>(),
            ["d.e.f"]
        );

        let expr = Expr::parse("foo.bar == 'bar' && foo.bar || 'false'")?;
        assert_eq!(
            expr.dataflow_contexts()
                .iter()
                .map(|t| t.1.raw)
                .collect::<Vec<_>>(),
            ["foo.bar"]
        );

        let expr = Expr::parse("foo.bar == 'bar' && foo.bar || foo.baz")?;
        assert_eq!(
            expr.dataflow_contexts()
                .iter()
                .map(|t| t.1.raw)
                .collect::<Vec<_>>(),
            ["foo.bar", "foo.baz"]
        );

        let expr = Expr::parse("fromJson(steps.runs.outputs.data).workflow_runs[0].id")?;
        assert_eq!(
            expr.dataflow_contexts()
                .iter()
                .map(|t| t.1.raw)
                .collect::<Vec<_>>(),
            ["fromJson(steps.runs.outputs.data).workflow_runs[0].id"]
        );

        let expr = Expr::parse("format('{0} {1} {2}', foo.bar, tojson(github), toJSON(github))")?;
        assert_eq!(
            expr.dataflow_contexts()
                .iter()
                .map(|t| t.1.raw)
                .collect::<Vec<_>>(),
            ["foo.bar", "github", "github"]
        );

        Ok(())
    }

    #[test]
    fn test_spannedexpr_computed_indices() -> Result<()> {
        for (expr, computed_indices) in &[
            ("foo.bar", vec![]),
            ("foo.bar[1]", vec![]),
            ("foo.bar[*]", vec![]),
            ("foo.bar[abc]", vec!["[abc]"]),
            (
                "foo.bar[format('{0}', 'foo')]",
                vec!["[format('{0}', 'foo')]"],
            ),
            ("foo.bar[abc].def[efg]", vec!["[abc]", "[efg]"]),
        ] {
            let expr = Expr::parse(expr)?;

            assert_eq!(
                expr.computed_indices()
                    .iter()
                    .map(|e| e.origin.raw)
                    .collect::<Vec<_>>(),
                *computed_indices
            );
        }

        Ok(())
    }
}
