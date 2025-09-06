//! GitHub Actions expression parsing and analysis.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::{borrow::Cow, ops::Deref, slice};

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

/// Represents a function call in a GitHub Actions expression.
#[derive(Debug, PartialEq)]
pub struct Call<'src> {
    /// The function name, e.g. `foo` in `foo()`.
    pub func: Function<'src>,
    /// The function's arguments.
    pub args: Vec<SpannedExpr<'src>>,
}

impl<'src> Call<'src> {
    /// Performs constant evaluation of a GitHub Actions expression
    /// function call.
    fn consteval(&self) -> Option<Evaluation> {
        let args = self
            .args
            .iter()
            .map(|arg| arg.consteval())
            .collect::<Option<Vec<Evaluation>>>()?;

        match &self.func {
            f if f == "format" => Self::consteval_format(&args),
            f if f == "contains" => Self::consteval_contains(&args),
            f if f == "startsWith" => Self::consteval_startswith(&args),
            f if f == "endsWith" => Self::consteval_endswith(&args),
            f if f == "toJSON" => Self::consteval_tojson(&args),
            f if f == "fromJSON" => Self::consteval_fromjson(&args),
            f if f == "join" => Self::consteval_join(&args),
            _ => None,
        }
    }

    /// Constant-evaluates a `format(fmtspec, args...)` call.
    ///
    /// See: <https://github.com/actions/languageservices/blob/1f3436c3cacc0f99d5d79e7120a5a9270cf13a72/expressions/src/funcs/format.ts>
    fn consteval_format(args: &[Evaluation]) -> Option<Evaluation> {
        if args.is_empty() {
            return None;
        }

        let template = args[0].to_string();
        let mut result = String::new();
        let mut index = 0;

        while index < template.len() {
            let lbrace = template[index..].find('{').map(|pos| index + pos);
            let rbrace = template[index..].find('}').map(|pos| index + pos);

            // Left brace
            if let Some(lbrace_pos) = lbrace {
                if rbrace.is_none() || rbrace.unwrap() > lbrace_pos {
                    // Escaped left brace
                    if template.as_bytes().get(lbrace_pos + 1) == Some(&b'{') {
                        result.push_str(&template[index..=lbrace_pos]);
                        index = lbrace_pos + 2;
                        continue;
                    }

                    // Left brace, number, optional format specifiers, right brace
                    if let Some(rbrace_pos) = rbrace {
                        if rbrace_pos > lbrace_pos + 1 {
                            if let Some(arg_index) = Self::read_arg_index(&template, lbrace_pos + 1)
                            {
                                // Check parameter count
                                if 1 + arg_index > args.len() - 1 {
                                    // Invalid format string - too few arguments
                                    return None;
                                }

                                // Append the portion before the left brace
                                if lbrace_pos > index {
                                    result.push_str(&template[index..lbrace_pos]);
                                }

                                // Append the arg
                                result.push_str(&args[1 + arg_index].to_string());
                                index = rbrace_pos + 1;
                                continue;
                            }
                        }
                    }

                    // Invalid format string
                    return None;
                }
            }

            // Right brace
            if let Some(rbrace_pos) = rbrace {
                if lbrace.is_none() || lbrace.unwrap() > rbrace_pos {
                    // Escaped right brace
                    if template.as_bytes().get(rbrace_pos + 1) == Some(&b'}') {
                        result.push_str(&template[index..=rbrace_pos]);
                        index = rbrace_pos + 2;
                    } else {
                        // Invalid format string
                        return None;
                    }
                }
            } else {
                // Last segment
                result.push_str(&template[index..]);
                break;
            }
        }

        Some(Evaluation::String(result))
    }

    /// Helper function to read argument index from format string.
    fn read_arg_index(string: &str, start_index: usize) -> Option<usize> {
        let mut length = 0;
        let chars: Vec<char> = string.chars().collect();

        // Count the number of digits
        while start_index + length < chars.len() {
            let next_char = chars[start_index + length];
            if next_char.is_ascii_digit() {
                length += 1;
            } else {
                break;
            }
        }

        // Validate at least one digit
        if length < 1 {
            return None;
        }

        // Parse the number
        let number_str: String = chars[start_index..start_index + length].iter().collect();
        number_str.parse::<usize>().ok()
    }

    /// Constant-evaluates a `contains(haystack, needle)` call.
    ///
    /// See: <https://github.com/actions/languageservices/blob/1f3436c3cacc0f99d5d79e7120a5a9270cf13a72/expressions/src/funcs/contains.ts>
    fn consteval_contains(args: &[Evaluation]) -> Option<Evaluation> {
        if args.len() != 2 {
            return None;
        }

        let search = &args[0];
        let item = &args[1];

        match search {
            // For primitive types (strings, numbers, booleans, null), do case-insensitive string search
            Evaluation::String(_)
            | Evaluation::Number(_)
            | Evaluation::Boolean(_)
            | Evaluation::Null => {
                let search_str = search.to_string().to_lowercase();
                let item_str = item.to_string().to_lowercase();
                Some(Evaluation::Boolean(search_str.contains(&item_str)))
            }
            // For arrays, check if any element equals the item
            Evaluation::Array(arr) => arr
                .iter()
                .any(|element| Expr::values_equal(item, element))
                .then_some(Some(Evaluation::Boolean(true)))
                .unwrap_or(Some(Evaluation::Boolean(false))),
            // For dictionaries, return false (not supported in reference implementation)
            Evaluation::Dictionary(_) => Some(Evaluation::Boolean(false)),
        }
    }

    /// Constant-evaluates a `startsWith(string, prefix)` call.
    ///
    /// See: <https://github.com/actions/languageservices/blob/1f3436c3cacc0f99d5d79e7120a5a9270cf13a72/expressions/src/funcs/startswith.ts>
    fn consteval_startswith(args: &[Evaluation]) -> Option<Evaluation> {
        if args.len() != 2 {
            return None;
        }

        let search_string = &args[0];
        let search_value = &args[1];

        // Both arguments must be primitive types (not arrays or dictionaries)
        match (search_string, search_value) {
            (
                Evaluation::String(_)
                | Evaluation::Number(_)
                | Evaluation::Boolean(_)
                | Evaluation::Null,
                Evaluation::String(_)
                | Evaluation::Number(_)
                | Evaluation::Boolean(_)
                | Evaluation::Null,
            ) => {
                // Case-insensitive comparison
                let string_str = search_string.to_string().to_lowercase();
                let prefix_str = search_value.to_string().to_lowercase();
                Some(Evaluation::Boolean(string_str.starts_with(&prefix_str)))
            }
            // If either argument is not primitive (array or dictionary), return false
            _ => Some(Evaluation::Boolean(false)),
        }
    }

    /// Constant-evaluates an `endsWith(string, suffix)` call.
    ///
    /// See: <https://github.com/actions/languageservices/blob/1f3436c3cacc0f99d5d79e7120a5a9270cf13a72/expressions/src/funcs/endswith.ts>
    fn consteval_endswith(args: &[Evaluation]) -> Option<Evaluation> {
        if args.len() != 2 {
            return None;
        }

        let search_string = &args[0];
        let search_value = &args[1];

        // Both arguments must be primitive types (not arrays or dictionaries)
        match (search_string, search_value) {
            (
                Evaluation::String(_)
                | Evaluation::Number(_)
                | Evaluation::Boolean(_)
                | Evaluation::Null,
                Evaluation::String(_)
                | Evaluation::Number(_)
                | Evaluation::Boolean(_)
                | Evaluation::Null,
            ) => {
                // Case-insensitive comparison
                let string_str = search_string.to_string().to_lowercase();
                let suffix_str = search_value.to_string().to_lowercase();
                Some(Evaluation::Boolean(string_str.ends_with(&suffix_str)))
            }
            // If either argument is not primitive (array or dictionary), return false
            _ => Some(Evaluation::Boolean(false)),
        }
    }

    /// Constant-evaluates a `toJSON(value)` call.
    ///
    /// See: <https://github.com/actions/languageservices/blob/1f3436c3cacc0f99d5d79e7120a5a9270cf13a72/expressions/src/funcs/tojson.ts>
    fn consteval_tojson(args: &[Evaluation]) -> Option<Evaluation> {
        if args.len() != 1 {
            return None;
        }

        let value = &args[0];

        let json_str = match value {
            Evaluation::String(s) => {
                format!("\"{}\"", s.replace('\\', "\\\\").replace('\"', "\\\""))
            }
            Evaluation::Number(n) => n.to_string(),
            Evaluation::Boolean(b) => b.to_string(),
            Evaluation::Null => "null".to_string(),
            Evaluation::Array(arr) => {
                // Convert array to JSON string
                let elements: Vec<String> = arr
                    .iter()
                    .map(|elem| match Self::consteval_tojson(slice::from_ref(elem)) {
                        Some(Evaluation::String(json)) => json,
                        _ => "null".to_string(), // Fallback for unconvertible elements
                    })
                    .collect();
                format!("[{}]", elements.join(","))
            }
            Evaluation::Dictionary(dict) => {
                // Convert dictionary to JSON string
                let mut pairs: Vec<String> = dict
                    .iter()
                    .map(|(key, value)| {
                        let key_json =
                            format!("\"{}\"", key.replace('\\', "\\\\").replace('\"', "\\\""));
                        let value_json = match Self::consteval_tojson(slice::from_ref(value)) {
                            Some(Evaluation::String(json)) => json,
                            _ => "null".to_string(), // Fallback for unconvertible values
                        };
                        format!("{}:{}", key_json, value_json)
                    })
                    .collect();
                pairs.sort(); // Ensure consistent ordering
                format!("{{{}}}", pairs.join(","))
            }
        };

        Some(Evaluation::String(json_str))
    }

    /// Constant-evaluates a `fromJSON(json_string)` call.
    ///
    /// See: <https://github.com/actions/languageservices/blob/1f3436c3cacc0f99d5d79e7120a5a9270cf13a72/expressions/src/funcs/fromjson.ts>
    fn consteval_fromjson(args: &[Evaluation]) -> Option<Evaluation> {
        if args.len() != 1 {
            return None;
        }

        let json_str = args[0].to_string();
        let trimmed = json_str.trim();

        // Match reference implementation: error on empty input
        if trimmed.is_empty() {
            return None;
        }

        // Parse with full JSON parser to handle arrays and objects
        match serde_json::from_str::<serde_json::Value>(trimmed) {
            Ok(value) => Some(Self::json_value_to_evaluation(value)),
            Err(_) => None,
        }
    }

    /// Converts a serde_json::Value to an Evaluation, matching GitHub Actions semantics.
    fn json_value_to_evaluation(value: serde_json::Value) -> Evaluation {
        match value {
            serde_json::Value::Null => Evaluation::Null,
            serde_json::Value::Bool(b) => Evaluation::Boolean(b),
            serde_json::Value::Number(n) => {
                if let Some(f) = n.as_f64() {
                    Evaluation::Number(f)
                } else {
                    // Fallback for very large integers that don't fit in f64
                    Evaluation::Number(0.0)
                }
            }
            serde_json::Value::String(s) => Evaluation::String(s),
            serde_json::Value::Array(arr) => {
                let elements = arr
                    .into_iter()
                    .map(Self::json_value_to_evaluation)
                    .collect();
                Evaluation::Array(elements)
            }
            serde_json::Value::Object(obj) => {
                let mut map = std::collections::HashMap::new();
                for (key, value) in obj {
                    map.insert(key, Self::json_value_to_evaluation(value));
                }
                Evaluation::Dictionary(map)
            }
        }
    }

    /// Constant-evaluates a `join(array, optionalSeparator)` call.
    ///
    /// See: <https://github.com/actions/languageservices/blob/1f3436c3cacc0f99d5d79e7120a5a9270cf13a72/expressions/src/funcs/join.ts>
    fn consteval_join(args: &[Evaluation]) -> Option<Evaluation> {
        if args.is_empty() || args.len() > 2 {
            return None;
        }

        let array_or_string = &args[0];

        // Get separator (default is comma)
        let separator = if args.len() > 1 {
            args[1].to_string()
        } else {
            ",".to_string()
        };

        match array_or_string {
            // For primitive types (strings, numbers, booleans, null), return as string
            Evaluation::String(_)
            | Evaluation::Number(_)
            | Evaluation::Boolean(_)
            | Evaluation::Null => Some(Evaluation::String(array_or_string.to_string())),
            // For arrays, join elements with separator
            Evaluation::Array(arr) => {
                let joined = arr
                    .iter()
                    .map(|item| item.to_string())
                    .collect::<Vec<String>>()
                    .join(&separator);
                Some(Evaluation::String(joined))
            }
            // For dictionaries, return empty string (not supported in reference)
            Evaluation::Dictionary(_) => Some(Evaluation::String("".to_string())),
        }
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

    /// Returns the trivial constant evaluation of the literal.
    fn consteval(&self) -> Evaluation {
        match self {
            Literal::String(s) => Evaluation::String(s.to_string()),
            Literal::Number(n) => Evaluation::Number(*n),
            Literal::Boolean(b) => Evaluation::Boolean(*b),
            Literal::Null => Evaluation::Null,
        }
    }
}

/// Represents the origin of an expression, including its source span
/// and unparsed form.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Origin<'src> {
    /// The expression's source span.
    pub span: subfeature::Span,
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
    pub fn new(span: impl Into<subfeature::Span>, raw: &'a str) -> Self {
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
            Expr::Call(Call { func, args }) => {
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
            Expr::Call(Call { func: _, args }) => {
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
            Expr::Call(Call { func: _, args }) => {
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

impl<'doc> From<&SpannedExpr<'doc>> for subfeature::Fragment<'doc> {
    fn from(expr: &SpannedExpr<'doc>) -> Self {
        Self::new(expr.origin.raw)
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
    Call(Call<'src>),
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
            Expr::Call(Call { func, args }) => {
                // These functions are reducible if their arguments are reducible.
                if func == "format"
                    || func == "contains"
                    || func == "startsWith"
                    || func == "endsWith"
                    || func == "toJSON"
                    || func == "fromJSON"
                    || func == "join"
                {
                    args.iter().all(|e| e.constant_reducible())
                } else {
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

        fn parse_pair(pair: Pair<'_, Rule>) -> Result<Box<SpannedExpr<'_>>> {
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
                            Origin::new(span.start()..span.end(), raw),
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
                            Origin::new(span.start()..span.end(), raw),
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
                            Origin::new(span.start()..span.end(), raw),
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
                            Origin::new(span.start()..span.end(), raw),
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
                            Origin::new(span.start()..span.end(), raw),
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
                    Origin::new(pair.as_span().start()..pair.as_span().end(), pair.as_str()),
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
                        Ok(SpannedExpr::new(
                            Origin::new(span.start()..span.end(), raw),
                            string_inner.into(),
                        )
                        .into())
                    } else {
                        Ok(SpannedExpr::new(
                            Origin::new(span.start()..span.end(), raw),
                            string_inner.replace("''", "'").into(),
                        )
                        .into())
                    }
                }
                Rule::boolean => Ok(SpannedExpr::new(
                    Origin::new(pair.as_span().start()..pair.as_span().end(), pair.as_str()),
                    pair.as_str().parse::<bool>().unwrap().into(),
                )
                .into()),
                Rule::null => Ok(SpannedExpr::new(
                    Origin::new(pair.as_span().start()..pair.as_span().end(), pair.as_str()),
                    Expr::Literal(Literal::Null),
                )
                .into()),
                Rule::star => Ok(SpannedExpr::new(
                    Origin::new(pair.as_span().start()..pair.as_span().end(), pair.as_str()),
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
                        Origin::new(span.start()..span.end(), raw),
                        Expr::Call(Call {
                            func: Function(identifier.as_str()),
                            args,
                        }),
                    )
                    .into())
                }
                Rule::identifier => Ok(SpannedExpr::new(
                    Origin::new(pair.as_span().start()..pair.as_span().end(), pair.as_str()),
                    Expr::ident(pair.as_str()),
                )
                .into()),
                Rule::index => Ok(SpannedExpr::new(
                    Origin::new(pair.as_span().start()..pair.as_span().end(), pair.as_str()),
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
                        Ok(SpannedExpr::new(
                            Origin::new(span.start()..span.end(), raw),
                            Expr::context(inner),
                        )
                        .into())
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

/// The result of evaluating a GitHub Actions expression.
///
/// This type represents the possible values that can result from evaluating
/// GitHub Actions expressions.
#[derive(Debug, Clone, PartialEq)]
pub enum Evaluation {
    /// A string value (includes both string literals and stringified other types)
    String(String),
    /// A numeric value
    Number(f64),
    /// A boolean value
    Boolean(bool),
    /// The null value
    Null,
    /// An array value (from fromJSON parsing)
    Array(Vec<Evaluation>),
    /// A dictionary/object value (from fromJSON parsing)
    Dictionary(std::collections::HashMap<String, Evaluation>),
}

impl PartialOrd for Evaluation {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match (self, other) {
            // Numbers can be compared directly
            (Evaluation::Number(a), Evaluation::Number(b)) => a.partial_cmp(b),

            // String comparison
            (Evaluation::String(a), Evaluation::String(b)) => Some(a.cmp(b)),

            // Arrays and dictionaries cannot be compared with other types
            (Evaluation::Array(_), _) | (_, Evaluation::Array(_)) => None,
            (Evaluation::Dictionary(_), _) | (_, Evaluation::Dictionary(_)) => None,

            // Try to convert both to numbers first, then fall back to string comparison
            (a, b) => {
                if let (Ok(a_num), Ok(b_num)) =
                    (a.to_string().parse::<f64>(), b.to_string().parse::<f64>())
                {
                    a_num.partial_cmp(&b_num)
                } else {
                    Some(a.to_string().cmp(&b.to_string()))
                }
            }
        }
    }
}

impl Evaluation {
    /// Convert to a boolean following GitHub Actions truthiness rules.
    ///
    /// GitHub Actions truthiness:
    /// - false and null are falsy
    /// - Numbers: 0 is falsy, everything else is truthy
    /// - Strings: empty string is falsy, everything else is truthy
    /// - Arrays and dictionaries are always truthy (non-empty objects)
    pub fn as_boolean(&self) -> bool {
        match self {
            Evaluation::Boolean(b) => *b,
            Evaluation::Null => false,
            Evaluation::Number(n) => *n != 0.0,
            Evaluation::String(s) => !s.is_empty(),
            Evaluation::Array(_) => true,
            Evaluation::Dictionary(_) => true,
        }
    }
}

impl std::fmt::Display for Evaluation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Evaluation::String(s) => write!(f, "{}", s),
            Evaluation::Number(n) => {
                // Format numbers like GitHub Actions does
                if n.fract() == 0.0 {
                    write!(f, "{}", *n as i64)
                } else {
                    write!(f, "{}", n)
                }
            }
            Evaluation::Boolean(b) => write!(f, "{}", b),
            Evaluation::Null => write!(f, ""),
            Evaluation::Array(_) => write!(f, "Array"),
            Evaluation::Dictionary(_) => write!(f, "Object"),
        }
    }
}

impl<'src> Expr<'src> {
    /// Evaluates a constant-reducible expression to its literal value.
    ///
    /// Returns `Some(Evaluation)` if the expression can be constant-evaluated,
    /// or `None` if the expression contains non-constant elements (like contexts or
    /// non-reducible function calls).
    ///
    /// This implementation follows GitHub Actions' evaluation semantics as documented at:
    /// https://docs.github.com/en/actions/reference/workflows-and-actions/expressions
    ///
    /// # Examples
    ///
    /// ```
    /// use github_actions_expressions::{Expr, Evaluation};
    ///
    /// let expr = Expr::parse("'hello'").unwrap();
    /// let result = expr.consteval().unwrap();
    /// assert_eq!(result.to_string(), "hello");
    ///
    /// let expr = Expr::parse("true && false").unwrap();
    /// let result = expr.consteval().unwrap();
    /// assert_eq!(result, Evaluation::Boolean(false));
    /// ```
    pub fn consteval(&self) -> Option<Evaluation> {
        match self {
            Expr::Literal(literal) => Some(literal.consteval()),

            Expr::BinOp { lhs, op, rhs } => {
                let lhs_val = lhs.consteval()?;
                let rhs_val = rhs.consteval()?;

                match op {
                    BinOp::And => {
                        // GitHub Actions && semantics: if LHS is falsy, return LHS, else return RHS
                        if lhs_val.as_boolean() {
                            Some(rhs_val)
                        } else {
                            Some(lhs_val)
                        }
                    }
                    BinOp::Or => {
                        // GitHub Actions || semantics: if LHS is truthy, return LHS, else return RHS
                        if lhs_val.as_boolean() {
                            Some(lhs_val)
                        } else {
                            Some(rhs_val)
                        }
                    }
                    BinOp::Eq => Some(Evaluation::Boolean(Self::values_equal(&lhs_val, &rhs_val))),
                    BinOp::Neq => {
                        Some(Evaluation::Boolean(!Self::values_equal(&lhs_val, &rhs_val)))
                    }
                    BinOp::Lt => lhs_val
                        .partial_cmp(&rhs_val)
                        .map(|ord| Evaluation::Boolean(matches!(ord, std::cmp::Ordering::Less))),
                    BinOp::Le => lhs_val.partial_cmp(&rhs_val).map(|ord| {
                        Evaluation::Boolean(matches!(
                            ord,
                            std::cmp::Ordering::Less | std::cmp::Ordering::Equal
                        ))
                    }),
                    BinOp::Gt => lhs_val
                        .partial_cmp(&rhs_val)
                        .map(|ord| Evaluation::Boolean(matches!(ord, std::cmp::Ordering::Greater))),
                    BinOp::Ge => lhs_val.partial_cmp(&rhs_val).map(|ord| {
                        Evaluation::Boolean(matches!(
                            ord,
                            std::cmp::Ordering::Greater | std::cmp::Ordering::Equal
                        ))
                    }),
                }
            }

            Expr::UnOp { op, expr } => {
                let val = expr.consteval()?;
                match op {
                    UnOp::Not => Some(Evaluation::Boolean(!val.as_boolean())),
                }
            }

            Expr::Call(call) => call.consteval(),

            // Non-constant expressions
            _ => None,
        }
    }

    /// Compares two evaluation results following GitHub Actions comparison semantics.
    fn values_equal(lhs: &Evaluation, rhs: &Evaluation) -> bool {
        match (lhs, rhs) {
            (Evaluation::Null, Evaluation::Null) => true,
            (Evaluation::Boolean(a), Evaluation::Boolean(b)) => a == b,
            (Evaluation::Number(a), Evaluation::Number(b)) => a == b,
            (Evaluation::String(a), Evaluation::String(b)) => a == b,
            (Evaluation::Array(a), Evaluation::Array(b)) => a == b,
            (Evaluation::Dictionary(a), Evaluation::Dictionary(b)) => a == b,

            // Type coercion rules - convert to string and compare
            (a, b) => a.to_string() == b.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use anyhow::Result;
    use pest::Parser as _;
    use pretty_assertions::assert_eq;

    use crate::{Call, Literal, Origin, SpannedExpr};

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
            "true",
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
                    Expr::Call(Call {
                        func: Function("foo"),
                        args: vec![
                            SpannedExpr::new(Origin::new(4..5, "1"), 1.0.into()),
                            SpannedExpr::new(Origin::new(7..8, "2"), 2.0.into()),
                            SpannedExpr::new(Origin::new(10..11, "3"), 3.0.into()),
                        ],
                    }),
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
                                Expr::Call(Call {
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
                                }),
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

    #[test]
    fn test_evaluate_constant_functions() -> Result<()> {
        use crate::Evaluation;

        let test_cases = &[
            // format function
            (
                "format('{0}', 'hello')",
                Evaluation::String("hello".to_string()),
            ),
            (
                "format('{0} {1}', 'hello', 'world')",
                Evaluation::String("hello world".to_string()),
            ),
            (
                "format('Value: {0}', 42)",
                Evaluation::String("Value: 42".to_string()),
            ),
            // contains function
            (
                "contains('hello world', 'world')",
                Evaluation::Boolean(true),
            ),
            ("contains('hello world', 'foo')", Evaluation::Boolean(false)),
            ("contains('test', '')", Evaluation::Boolean(true)),
            // startsWith function
            (
                "startsWith('hello world', 'hello')",
                Evaluation::Boolean(true),
            ),
            (
                "startsWith('hello world', 'world')",
                Evaluation::Boolean(false),
            ),
            ("startsWith('test', '')", Evaluation::Boolean(true)),
            // endsWith function
            (
                "endsWith('hello world', 'world')",
                Evaluation::Boolean(true),
            ),
            (
                "endsWith('hello world', 'hello')",
                Evaluation::Boolean(false),
            ),
            ("endsWith('test', '')", Evaluation::Boolean(true)),
            // toJSON function
            (
                "toJSON('hello')",
                Evaluation::String("\"hello\"".to_string()),
            ),
            ("toJSON(42)", Evaluation::String("42".to_string())),
            ("toJSON(true)", Evaluation::String("true".to_string())),
            ("toJSON(null)", Evaluation::String("null".to_string())),
            // fromJSON function - primitives
            (
                "fromJSON('\"hello\"')",
                Evaluation::String("hello".to_string()),
            ),
            ("fromJSON('42')", Evaluation::Number(42.0)),
            ("fromJSON('true')", Evaluation::Boolean(true)),
            ("fromJSON('null')", Evaluation::Null),
            // fromJSON function - arrays and objects
            (
                "fromJSON('[1, 2, 3]')",
                Evaluation::Array(vec![
                    Evaluation::Number(1.0),
                    Evaluation::Number(2.0),
                    Evaluation::Number(3.0),
                ]),
            ),
            (
                "fromJSON('{\"key\": \"value\"}')",
                Evaluation::Dictionary({
                    let mut map = std::collections::HashMap::new();
                    map.insert("key".to_string(), Evaluation::String("value".to_string()));
                    map
                }),
            ),
        ];

        for (expr_str, expected) in test_cases {
            let expr = Expr::parse(expr_str)?;
            let result = expr.consteval().unwrap();
            assert_eq!(result, *expected, "Failed for expression: {}", expr_str);
        }

        Ok(())
    }

    #[test]
    fn test_evaluate_constant_complex_expressions() -> Result<()> {
        use crate::Evaluation;

        let test_cases = &[
            // Nested operations
            ("!false", Evaluation::Boolean(true)),
            ("!true", Evaluation::Boolean(false)),
            ("!(true && false)", Evaluation::Boolean(true)),
            // Complex boolean logic
            ("true && (false || true)", Evaluation::Boolean(true)),
            ("false || (true && false)", Evaluation::Boolean(false)),
            // Mixed function calls
            (
                "contains(format('{0} {1}', 'hello', 'world'), 'world')",
                Evaluation::Boolean(true),
            ),
            (
                "startsWith(format('prefix_{0}', 'test'), 'prefix')",
                Evaluation::Boolean(true),
            ),
        ];

        for (expr_str, expected) in test_cases {
            let expr = Expr::parse(expr_str)?;
            let result = expr.consteval().unwrap();
            assert_eq!(result, *expected, "Failed for expression: {}", expr_str);
        }

        Ok(())
    }

    #[test]
    fn test_evaluation_result_display() {
        use crate::Evaluation;

        let test_cases = &[
            (Evaluation::String("hello".to_string()), "hello"),
            (Evaluation::Number(42.0), "42"),
            (Evaluation::Number(3.14), "3.14"),
            (Evaluation::Boolean(true), "true"),
            (Evaluation::Boolean(false), "false"),
            (Evaluation::Null, ""),
        ];

        for (result, expected) in test_cases {
            assert_eq!(result.to_string(), *expected);
        }
    }

    #[test]
    fn test_evaluation_result_to_boolean() {
        use crate::Evaluation;

        let test_cases = &[
            (Evaluation::Boolean(true), true),
            (Evaluation::Boolean(false), false),
            (Evaluation::Null, false),
            (Evaluation::Number(0.0), false),
            (Evaluation::Number(1.0), true),
            (Evaluation::Number(-1.0), true),
            (Evaluation::String("".to_string()), false),
            (Evaluation::String("hello".to_string()), true),
            (Evaluation::Array(vec![]), true), // Arrays are always truthy
            (
                Evaluation::Dictionary(std::collections::HashMap::new()),
                true,
            ), // Dictionaries are always truthy
        ];

        for (result, expected) in test_cases {
            assert_eq!(result.as_boolean(), *expected);
        }
    }

    #[test]
    fn test_github_actions_logical_semantics() -> Result<()> {
        use crate::Evaluation;

        // Test GitHub Actions-specific && and || semantics
        let test_cases = &[
            // && returns the first falsy value, or the last value if all are truthy
            ("false && 'hello'", Evaluation::Boolean(false)),
            ("null && 'hello'", Evaluation::Null),
            ("'' && 'hello'", Evaluation::String("".to_string())),
            (
                "'hello' && 'world'",
                Evaluation::String("world".to_string()),
            ),
            ("true && 42", Evaluation::Number(42.0)),
            // || returns the first truthy value, or the last value if all are falsy
            ("true || 'hello'", Evaluation::Boolean(true)),
            (
                "'hello' || 'world'",
                Evaluation::String("hello".to_string()),
            ),
            ("false || 'hello'", Evaluation::String("hello".to_string())),
            ("null || false", Evaluation::Boolean(false)),
            ("'' || null", Evaluation::Null),
        ];

        for (expr_str, expected) in test_cases {
            let expr = Expr::parse(expr_str)?;
            let result = expr.consteval().unwrap();
            assert_eq!(result, *expected, "Failed for expression: {}", expr_str);
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

    #[test]
    fn test_fragment_from_expr() {
        for (expr, expected) in &[
            ("foo==bar", "foo==bar"),
            ("foo    ==   bar", "foo    ==   bar"),
            ("foo == bar", r"foo == bar"),
            ("foo(bar)", "foo(bar)"),
            ("foo(bar, baz)", "foo(bar, baz)"),
            ("foo (bar, baz)", "foo (bar, baz)"),
            ("a . b . c . d", "a . b . c . d"),
            ("true \n && \n false", r"true\s+\&\&\s+false"),
        ] {
            let expr = Expr::parse(expr).unwrap();
            match subfeature::Fragment::from(&expr) {
                subfeature::Fragment::Raw(actual) => assert_eq!(actual, *expected),
                subfeature::Fragment::Regex(actual) => assert_eq!(actual.as_str(), *expected),
            };
        }
    }

    #[test]
    fn test_fromjson_comprehensive() -> Result<()> {
        use crate::Evaluation;

        let test_cases = &[
            // Basic primitives
            ("fromJSON('null')", Evaluation::Null),
            ("fromJSON('true')", Evaluation::Boolean(true)),
            ("fromJSON('false')", Evaluation::Boolean(false)),
            ("fromJSON('42')", Evaluation::Number(42.0)),
            ("fromJSON('3.14')", Evaluation::Number(3.14)),
            (
                "fromJSON('\"hello\"')",
                Evaluation::String("hello".to_string()),
            ),
            ("fromJSON('\"\"')", Evaluation::String("".to_string())),
            // Arrays
            ("fromJSON('[]')", Evaluation::Array(vec![])),
            (
                "fromJSON('[1, 2, 3]')",
                Evaluation::Array(vec![
                    Evaluation::Number(1.0),
                    Evaluation::Number(2.0),
                    Evaluation::Number(3.0),
                ]),
            ),
            (
                "fromJSON('[\"a\", \"b\", null, true, 123]')",
                Evaluation::Array(vec![
                    Evaluation::String("a".to_string()),
                    Evaluation::String("b".to_string()),
                    Evaluation::Null,
                    Evaluation::Boolean(true),
                    Evaluation::Number(123.0),
                ]),
            ),
            // Objects
            (
                "fromJSON('{}')",
                Evaluation::Dictionary(std::collections::HashMap::new()),
            ),
            (
                "fromJSON('{\"key\": \"value\"}')",
                Evaluation::Dictionary({
                    let mut map = std::collections::HashMap::new();
                    map.insert("key".to_string(), Evaluation::String("value".to_string()));
                    map
                }),
            ),
            (
                "fromJSON('{\"num\": 42, \"bool\": true, \"null\": null}')",
                Evaluation::Dictionary({
                    let mut map = std::collections::HashMap::new();
                    map.insert("num".to_string(), Evaluation::Number(42.0));
                    map.insert("bool".to_string(), Evaluation::Boolean(true));
                    map.insert("null".to_string(), Evaluation::Null);
                    map
                }),
            ),
            // Nested structures
            (
                "fromJSON('{\"array\": [1, 2], \"object\": {\"nested\": true}}')",
                Evaluation::Dictionary({
                    let mut map = std::collections::HashMap::new();
                    map.insert(
                        "array".to_string(),
                        Evaluation::Array(vec![Evaluation::Number(1.0), Evaluation::Number(2.0)]),
                    );
                    let mut nested_map = std::collections::HashMap::new();
                    nested_map.insert("nested".to_string(), Evaluation::Boolean(true));
                    map.insert("object".to_string(), Evaluation::Dictionary(nested_map));
                    map
                }),
            ),
        ];

        for (expr_str, expected) in test_cases {
            let expr = Expr::parse(expr_str)?;
            let result = expr.consteval().unwrap();
            assert_eq!(result, *expected, "Failed for expression: {}", expr_str);
        }

        Ok(())
    }

    #[test]
    fn test_fromjson_error_cases() -> Result<()> {
        let error_cases = &[
            "fromJSON('')",          // Empty string
            "fromJSON('   ')",       // Whitespace only
            "fromJSON('invalid')",   // Invalid JSON
            "fromJSON('{invalid}')", // Invalid JSON syntax
            "fromJSON('[1, 2,]')",   // Trailing comma (invalid in strict JSON)
        ];

        for expr_str in error_cases {
            let expr = Expr::parse(expr_str)?;
            let result = expr.consteval();
            assert!(
                result.is_none(),
                "Expected None for invalid JSON: {}",
                expr_str
            );
        }

        Ok(())
    }

    #[test]
    fn test_fromjson_display_format() -> Result<()> {
        use crate::Evaluation;

        let test_cases = &[
            (Evaluation::Array(vec![Evaluation::Number(1.0)]), "Array"),
            (
                Evaluation::Dictionary(std::collections::HashMap::new()),
                "Object",
            ),
        ];

        for (result, expected) in test_cases {
            assert_eq!(result.to_string(), *expected);
        }

        Ok(())
    }

    #[test]
    fn test_tojson_fromjson_roundtrip() -> Result<()> {
        use crate::Evaluation;

        // Test round-trip conversion for complex structures
        let test_cases = &[
            // Simple array
            "[1, 2, 3]",
            // Simple object
            r#"{"key": "value"}"#,
            // Mixed array
            r#"[1, "hello", true, null]"#,
            // Nested structure
            r#"{"array": [1, 2], "object": {"nested": true}}"#,
        ];

        for json_str in test_cases {
            // Parse with fromJSON
            let from_expr_str = format!("fromJSON('{}')", json_str);
            let from_expr = Expr::parse(&from_expr_str)?;
            let parsed = from_expr.consteval().unwrap();

            // Convert back with toJSON (using a dummy toJSON call structure)
            let to_result = Call::consteval_tojson(&[parsed.clone()]).unwrap();

            // Parse the result again to compare structure
            let reparsed_expr_str = format!("fromJSON('{}')", to_result.to_string());
            let reparsed_expr = Expr::parse(&reparsed_expr_str)?;
            let reparsed = reparsed_expr.consteval().unwrap();

            // The structure should be preserved (though ordering might differ for objects)
            match (&parsed, &reparsed) {
                (Evaluation::Array(a), Evaluation::Array(b)) => assert_eq!(a, b),
                (Evaluation::Dictionary(_), Evaluation::Dictionary(_)) => {
                    // For dictionaries, we just check that both are dictionaries
                    // since ordering might differ
                    assert!(matches!(parsed, Evaluation::Dictionary(_)));
                    assert!(matches!(reparsed, Evaluation::Dictionary(_)));
                }
                (a, b) => assert_eq!(a, b),
            }
        }

        Ok(())
    }

    #[test]
    fn test_format_function() -> Result<()> {
        use crate::Evaluation;

        let test_cases = &[
            // Basic formatting
            (
                "format('Hello {0}', 'world')",
                Evaluation::String("Hello world".to_string()),
            ),
            (
                "format('{0} {1}', 'Hello', 'world')",
                Evaluation::String("Hello world".to_string()),
            ),
            (
                "format('Value: {0}', 42)",
                Evaluation::String("Value: 42".to_string()),
            ),
            // Escaped braces
            (
                "format('{{0}}', 'test')",
                Evaluation::String("{0}".to_string()),
            ),
            (
                "format('{{Hello}} {0}', 'world')",
                Evaluation::String("{Hello} world".to_string()),
            ),
            (
                "format('{0} {{1}}', 'Hello')",
                Evaluation::String("Hello {1}".to_string()),
            ),
            (
                "format('}}{{', 'test')",
                Evaluation::String("}{".to_string()),
            ),
            (
                "format('{{{{}}}}', 'test')",
                Evaluation::String("{{}}".to_string()),
            ),
            // Multiple arguments
            (
                "format('{0} {1} {2}', 'a', 'b', 'c')",
                Evaluation::String("a b c".to_string()),
            ),
            (
                "format('{2} {1} {0}', 'a', 'b', 'c')",
                Evaluation::String("c b a".to_string()),
            ),
            // Repeated arguments
            (
                "format('{0} {0} {0}', 'test')",
                Evaluation::String("test test test".to_string()),
            ),
            // No arguments to replace
            (
                "format('Hello world')",
                Evaluation::String("Hello world".to_string()),
            ),
            // Trailing fragments
            ("format('abc {{')", Evaluation::String("abc {".to_string())),
            ("format('abc }}')", Evaluation::String("abc }".to_string())),
            (
                "format('abc {{}}')",
                Evaluation::String("abc {}".to_string()),
            ),
        ];

        for (expr_str, expected) in test_cases {
            let expr = Expr::parse(expr_str)?;
            let result = expr.consteval().unwrap();
            assert_eq!(result, *expected, "Failed for expression: {}", expr_str);
        }

        Ok(())
    }

    #[test]
    fn test_format_function_error_cases() -> Result<()> {
        let error_cases = &[
            // Invalid format strings
            "format('{0', 'test')",        // Missing closing brace
            "format('0}', 'test')",        // Missing opening brace
            "format('{a}', 'test')",       // Non-numeric placeholder
            "format('{1}', 'test')",       // Argument index out of bounds
            "format('{0} {2}', 'a', 'b')", // Argument index out of bounds
            "format('{}', 'test')",        // Empty braces
            "format('{-1}', 'test')",      // Negative index (invalid)
        ];

        for expr_str in error_cases {
            let expr = Expr::parse(expr_str)?;
            let result = expr.consteval();
            assert!(
                result.is_none(),
                "Expected None for invalid format string: {}",
                expr_str
            );
        }

        Ok(())
    }

    #[test]
    fn test_contains_function() -> Result<()> {
        use crate::Evaluation;

        let test_cases = &[
            // Basic string contains (case-insensitive)
            (
                "contains('hello world', 'world')",
                Evaluation::Boolean(true),
            ),
            (
                "contains('hello world', 'WORLD')",
                Evaluation::Boolean(true),
            ),
            (
                "contains('HELLO WORLD', 'world')",
                Evaluation::Boolean(true),
            ),
            ("contains('hello world', 'foo')", Evaluation::Boolean(false)),
            ("contains('test', '')", Evaluation::Boolean(true)),
            // Number to string conversion
            ("contains('123', '2')", Evaluation::Boolean(true)),
            ("contains(123, '2')", Evaluation::Boolean(true)),
            ("contains('hello123', 123)", Evaluation::Boolean(true)),
            // Boolean to string conversion
            ("contains('true', true)", Evaluation::Boolean(true)),
            ("contains('false', false)", Evaluation::Boolean(true)),
            // Null handling
            ("contains('null', null)", Evaluation::Boolean(true)),
            ("contains(null, '')", Evaluation::Boolean(true)),
            // Array contains - exact matches
            (
                "contains(fromJSON('[1, 2, 3]'), 2)",
                Evaluation::Boolean(true),
            ),
            (
                "contains(fromJSON('[1, 2, 3]'), 4)",
                Evaluation::Boolean(false),
            ),
            (
                "contains(fromJSON('[\"a\", \"b\", \"c\"]'), 'b')",
                Evaluation::Boolean(true),
            ),
            (
                "contains(fromJSON('[\"a\", \"b\", \"c\"]'), 'B')",
                Evaluation::Boolean(false), // Array search is exact match, not case-insensitive
            ),
            (
                "contains(fromJSON('[true, false, null]'), true)",
                Evaluation::Boolean(true),
            ),
            (
                "contains(fromJSON('[true, false, null]'), null)",
                Evaluation::Boolean(true),
            ),
            // Empty array
            (
                "contains(fromJSON('[]'), 'anything')",
                Evaluation::Boolean(false),
            ),
            // Mixed type array
            (
                "contains(fromJSON('[1, \"hello\", true, null]'), 'hello')",
                Evaluation::Boolean(true),
            ),
            (
                "contains(fromJSON('[1, \"hello\", true, null]'), 1)",
                Evaluation::Boolean(true),
            ),
        ];

        for (expr_str, expected) in test_cases {
            let expr = Expr::parse(expr_str)?;
            let result = expr.consteval().unwrap();
            assert_eq!(result, *expected, "Failed for expression: {}", expr_str);
        }

        Ok(())
    }

    #[test]
    fn test_join_function() -> Result<()> {
        use crate::Evaluation;

        let test_cases = &[
            // Basic array joining with default separator
            (
                "join(fromJSON('[\"a\", \"b\", \"c\"]'))",
                Evaluation::String("a,b,c".to_string()),
            ),
            (
                "join(fromJSON('[1, 2, 3]'))",
                Evaluation::String("1,2,3".to_string()),
            ),
            (
                "join(fromJSON('[true, false, null]'))",
                Evaluation::String("true,false,".to_string()),
            ),
            // Array joining with custom separator
            (
                "join(fromJSON('[\"a\", \"b\", \"c\"]'), ' ')",
                Evaluation::String("a b c".to_string()),
            ),
            (
                "join(fromJSON('[1, 2, 3]'), '-')",
                Evaluation::String("1-2-3".to_string()),
            ),
            (
                "join(fromJSON('[\"hello\", \"world\"]'), ' | ')",
                Evaluation::String("hello | world".to_string()),
            ),
            (
                "join(fromJSON('[\"a\", \"b\", \"c\"]'), '')",
                Evaluation::String("abc".to_string()),
            ),
            // Empty array
            ("join(fromJSON('[]'))", Evaluation::String("".to_string())),
            (
                "join(fromJSON('[]'), '-')",
                Evaluation::String("".to_string()),
            ),
            // Single element array
            (
                "join(fromJSON('[\"single\"]'))",
                Evaluation::String("single".to_string()),
            ),
            (
                "join(fromJSON('[\"single\"]'), '-')",
                Evaluation::String("single".to_string()),
            ),
            // Primitive values (should return the value as string)
            ("join('hello')", Evaluation::String("hello".to_string())),
            (
                "join('hello', '-')",
                Evaluation::String("hello".to_string()),
            ),
            ("join(123)", Evaluation::String("123".to_string())),
            ("join(true)", Evaluation::String("true".to_string())),
            ("join(null)", Evaluation::String("".to_string())),
            // Mixed type array
            (
                "join(fromJSON('[1, \"hello\", true, null]'))",
                Evaluation::String("1,hello,true,".to_string()),
            ),
            (
                "join(fromJSON('[1, \"hello\", true, null]'), ' | ')",
                Evaluation::String("1 | hello | true | ".to_string()),
            ),
            // Special separator values
            (
                "join(fromJSON('[\"a\", \"b\", \"c\"]'), 123)",
                Evaluation::String("a123b123c".to_string()),
            ),
            (
                "join(fromJSON('[\"a\", \"b\", \"c\"]'), true)",
                Evaluation::String("atruebtruec".to_string()),
            ),
        ];

        for (expr_str, expected) in test_cases {
            let expr = Expr::parse(expr_str)?;
            let result = expr.consteval().unwrap();
            assert_eq!(result, *expected, "Failed for expression: {}", expr_str);
        }

        Ok(())
    }

    #[test]
    fn test_endswith_function() -> Result<()> {
        use crate::Evaluation;

        let test_cases = &[
            // Basic case-insensitive string endsWith
            (
                "endsWith('hello world', 'world')",
                Evaluation::Boolean(true),
            ),
            (
                "endsWith('hello world', 'WORLD')",
                Evaluation::Boolean(true),
            ),
            (
                "endsWith('HELLO WORLD', 'world')",
                Evaluation::Boolean(true),
            ),
            (
                "endsWith('hello world', 'hello')",
                Evaluation::Boolean(false),
            ),
            ("endsWith('hello world', 'foo')", Evaluation::Boolean(false)),
            // Empty string cases
            ("endsWith('test', '')", Evaluation::Boolean(true)),
            ("endsWith('', '')", Evaluation::Boolean(true)),
            ("endsWith('', 'test')", Evaluation::Boolean(false)),
            // Number to string conversion
            ("endsWith('123', '3')", Evaluation::Boolean(true)),
            ("endsWith(123, '3')", Evaluation::Boolean(true)),
            ("endsWith('hello123', 123)", Evaluation::Boolean(true)),
            ("endsWith(12345, 345)", Evaluation::Boolean(true)),
            // Boolean to string conversion
            ("endsWith('test true', true)", Evaluation::Boolean(true)),
            ("endsWith('test false', false)", Evaluation::Boolean(true)),
            ("endsWith(true, 'ue')", Evaluation::Boolean(true)),
            // Null handling
            ("endsWith('test null', null)", Evaluation::Boolean(true)),
            ("endsWith(null, '')", Evaluation::Boolean(true)),
            ("endsWith('something', null)", Evaluation::Boolean(true)), // null converts to empty string
            // Non-primitive types should return false
            (
                "endsWith(fromJSON('[1, 2, 3]'), '3')",
                Evaluation::Boolean(false),
            ),
            (
                "endsWith('test', fromJSON('[1, 2, 3]'))",
                Evaluation::Boolean(false),
            ),
            (
                "endsWith(fromJSON('{\"key\": \"value\"}'), 'value')",
                Evaluation::Boolean(false),
            ),
            (
                "endsWith('test', fromJSON('{\"key\": \"value\"}'))",
                Evaluation::Boolean(false),
            ),
            // Mixed case scenarios
            (
                "endsWith('TestString', 'STRING')",
                Evaluation::Boolean(true),
            ),
            ("endsWith('CamelCase', 'case')", Evaluation::Boolean(true)),
            // Exact match
            ("endsWith('exact', 'exact')", Evaluation::Boolean(true)),
            // Longer suffix than string
            (
                "endsWith('short', 'very long suffix')",
                Evaluation::Boolean(false),
            ),
        ];

        for (expr_str, expected) in test_cases {
            let expr = Expr::parse(expr_str)?;
            let result = expr.consteval().unwrap();
            assert_eq!(result, *expected, "Failed for expression: {}", expr_str);
        }

        Ok(())
    }

    #[test]
    fn test_startswith_function() -> Result<()> {
        use crate::Evaluation;

        let test_cases = &[
            // Basic case-insensitive string startsWith
            (
                "startsWith('hello world', 'hello')",
                Evaluation::Boolean(true),
            ),
            (
                "startsWith('hello world', 'HELLO')",
                Evaluation::Boolean(true),
            ),
            (
                "startsWith('HELLO WORLD', 'hello')",
                Evaluation::Boolean(true),
            ),
            (
                "startsWith('hello world', 'world')",
                Evaluation::Boolean(false),
            ),
            (
                "startsWith('hello world', 'foo')",
                Evaluation::Boolean(false),
            ),
            // Empty string cases
            ("startsWith('test', '')", Evaluation::Boolean(true)),
            ("startsWith('', '')", Evaluation::Boolean(true)),
            ("startsWith('', 'test')", Evaluation::Boolean(false)),
            // Number to string conversion
            ("startsWith('123', '1')", Evaluation::Boolean(true)),
            ("startsWith(123, '1')", Evaluation::Boolean(true)),
            ("startsWith('123hello', 123)", Evaluation::Boolean(true)),
            ("startsWith(12345, 123)", Evaluation::Boolean(true)),
            // Boolean to string conversion
            ("startsWith('true test', true)", Evaluation::Boolean(true)),
            ("startsWith('false test', false)", Evaluation::Boolean(true)),
            ("startsWith(true, 'tr')", Evaluation::Boolean(true)),
            // Null handling
            ("startsWith('null test', null)", Evaluation::Boolean(true)),
            ("startsWith(null, '')", Evaluation::Boolean(true)),
            (
                "startsWith('something', null)",
                Evaluation::Boolean(true), // null converts to empty string
            ),
            // Non-primitive types should return false
            (
                "startsWith(fromJSON('[1, 2, 3]'), '1')",
                Evaluation::Boolean(false),
            ),
            (
                "startsWith('test', fromJSON('[1, 2, 3]'))",
                Evaluation::Boolean(false),
            ),
            (
                "startsWith(fromJSON('{\"key\": \"value\"}'), 'key')",
                Evaluation::Boolean(false),
            ),
            (
                "startsWith('test', fromJSON('{\"key\": \"value\"}'))",
                Evaluation::Boolean(false),
            ),
            // Mixed case scenarios
            (
                "startsWith('TestString', 'TEST')",
                Evaluation::Boolean(true),
            ),
            (
                "startsWith('CamelCase', 'camel')",
                Evaluation::Boolean(true),
            ),
            // Exact match
            ("startsWith('exact', 'exact')", Evaluation::Boolean(true)),
            // Longer prefix than string
            (
                "startsWith('short', 'very long prefix')",
                Evaluation::Boolean(false),
            ),
            // Partial matches
            (
                "startsWith('prefix_suffix', 'prefix')",
                Evaluation::Boolean(true),
            ),
            (
                "startsWith('prefix_suffix', 'suffix')",
                Evaluation::Boolean(false),
            ),
        ];

        for (expr_str, expected) in test_cases {
            let expr = Expr::parse(expr_str)?;
            let result = expr.consteval().unwrap();
            assert_eq!(result, *expected, "Failed for expression: {}", expr_str);
        }

        Ok(())
    }
}
