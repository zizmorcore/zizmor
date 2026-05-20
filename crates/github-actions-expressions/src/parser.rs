//! A hand-written, dependency-free recursive descent parser for
//! GitHub Actions expressions.
//!
//! This parser deliberately mirrors the structure -- and, crucially, the
//! exact span semantics -- of the `pest` grammar it replaced. A few of
//! those span semantics are quirky (see the notes on individual rules),
//! but they're preserved verbatim so that downstream consumers and the
//! test suite continue to see identical byte ranges.

use std::borrow::Cow;

use crate::{
    Error, Expr, Origin, SpannedExpr, SyntaxError,
    call::Call,
    literal::Literal,
    op::{BinOp, UnOp},
    parse_number,
};

/// The result of parsing a single grammar production.
type PResult<'src> = Result<SpannedExpr<'src>, Error>;

/// Parse a complete GitHub Actions expression.
///
/// The entire input must be consumed (modulo leading and trailing
/// whitespace); otherwise a [`SyntaxError`] is returned.
pub(crate) fn parse(src: &str) -> Result<SpannedExpr<'_>, Error> {
    let mut parser = Parser::new(src);
    parser.skip_ws();
    let expr = parser.parse_or()?;
    parser.skip_ws();
    if parser.pos != src.len() {
        return Err(syntax_error("unexpected trailing input", parser.pos));
    }
    Ok(expr)
}

/// Build an [`Error`] for a syntax error at the given byte offset.
fn syntax_error(message: &'static str, offset: usize) -> Error {
    Error::Syntax(SyntaxError { message, offset })
}

/// Returns whether `byte` can begin an identifier.
fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

/// Returns whether `byte` can continue an identifier.
fn is_identifier_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

/// A recursive descent parser over a single expression string.
struct Parser<'src> {
    src: &'src str,
    /// The current byte offset into `src`.
    pos: usize,
}

impl<'src> Parser<'src> {
    fn new(src: &'src str) -> Self {
        Self { src, pos: 0 }
    }

    // --- low-level cursor helpers ------------------------------------------

    fn bytes(&self) -> &'src [u8] {
        self.src.as_bytes()
    }

    /// The byte at the cursor, if any.
    fn peek(&self) -> Option<u8> {
        self.bytes().get(self.pos).copied()
    }

    /// The yet-unconsumed input.
    fn rest(&self) -> &'src str {
        &self.src[self.pos..]
    }

    /// Skip expression whitespace: spaces, line feeds, and carriage
    /// returns. Note that tabs are deliberately *not* whitespace here,
    /// matching the original grammar.
    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    /// Consume `literal` if it appears at the cursor, reporting success.
    fn eat(&mut self, literal: &str) -> bool {
        if self.rest().starts_with(literal) {
            self.pos += literal.len();
            true
        } else {
            false
        }
    }

    /// Consume a single `byte` if it appears at the cursor.
    fn eat_byte(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// Build an [`Origin`] spanning `[start, self.pos)`.
    fn origin_from(&self, start: usize) -> Origin<'src> {
        Origin::new(start..self.pos, &self.src[start..self.pos])
    }

    // --- binary operator precedence levels ---------------------------------

    /// Parse a left-associative chain of binary operators.
    ///
    /// `operand` parses a single operand at the next-higher precedence
    /// level; `operator` consumes a binary operator if one is present.
    ///
    /// This mirrors `pest`'s span behavior: when the chain contains at
    /// least one operator, *every* resulting [`Expr::BinOp`] node shares
    /// the span of the whole chain (which also includes any whitespace
    /// trailing the final operand).
    fn parse_binop_chain(
        &mut self,
        operand: fn(&mut Self) -> PResult<'src>,
        operator: fn(&mut Self) -> Option<BinOp>,
    ) -> PResult<'src> {
        let start = self.pos;
        let first = operand(self)?;
        self.skip_ws();

        let mut rest = Vec::new();
        while let Some(op) = operator(self) {
            self.skip_ws();
            let rhs = operand(self)?;
            self.skip_ws();
            rest.push((op, rhs));
        }

        // A chain with no operators punches through to its single operand,
        // discarding this level's span entirely.
        if rest.is_empty() {
            return Ok(first);
        }

        let origin = self.origin_from(start);
        Ok(rest.into_iter().fold(first, |lhs, (op, rhs)| {
            SpannedExpr::new(
                origin,
                Expr::BinOp {
                    lhs: Box::new(lhs),
                    op,
                    rhs: Box::new(rhs),
                },
            )
        }))
    }

    /// Parse a logical-or chain (`||`).
    fn parse_or(&mut self) -> PResult<'src> {
        self.parse_binop_chain(Self::parse_and, Self::eat_or_op)
    }

    fn eat_or_op(&mut self) -> Option<BinOp> {
        self.eat("||").then_some(BinOp::Or)
    }

    /// Parse a logical-and chain (`&&`).
    fn parse_and(&mut self) -> PResult<'src> {
        self.parse_binop_chain(Self::parse_eq, Self::eat_and_op)
    }

    fn eat_and_op(&mut self) -> Option<BinOp> {
        self.eat("&&").then_some(BinOp::And)
    }

    /// Parse an equality chain (`==`, `!=`).
    fn parse_eq(&mut self) -> PResult<'src> {
        self.parse_binop_chain(Self::parse_comp, Self::eat_eq_op)
    }

    fn eat_eq_op(&mut self) -> Option<BinOp> {
        if self.eat("==") {
            Some(BinOp::Eq)
        } else if self.eat("!=") {
            Some(BinOp::Neq)
        } else {
            None
        }
    }

    /// Parse a comparison chain (`>`, `>=`, `<`, `<=`).
    fn parse_comp(&mut self) -> PResult<'src> {
        self.parse_binop_chain(Self::parse_unary, Self::eat_comp_op)
    }

    fn eat_comp_op(&mut self) -> Option<BinOp> {
        // Longer operators must be tried before their prefixes.
        if self.eat(">=") {
            Some(BinOp::Ge)
        } else if self.eat(">") {
            Some(BinOp::Gt)
        } else if self.eat("<=") {
            Some(BinOp::Le)
        } else if self.eat("<") {
            Some(BinOp::Lt)
        } else {
            None
        }
    }

    // --- unary, primary, and contexts --------------------------------------

    /// Parse a unary expression: an optional `!` applied to a primary
    /// expression.
    ///
    /// When a `!` is *not* followed by a primary expression, it instead
    /// applies to a full nested expression. This is what allows `!!x` (and
    /// chains like `!!x || y`) to parse, preserving a quirk of the original
    /// grammar's `unary_op ~ or_expr` fallback.
    fn parse_unary(&mut self) -> PResult<'src> {
        if self.peek() != Some(b'!') {
            return self.parse_primary();
        }

        let start = self.pos;
        self.pos += 1; // consume '!'
        self.skip_ws();

        let checkpoint = self.pos;
        let inner = match self.parse_primary() {
            Ok(inner) => inner,
            Err(_) => {
                self.pos = checkpoint;
                self.parse_or()?
            }
        };

        Ok(SpannedExpr::new(
            self.origin_from(start),
            Expr::UnOp {
                op: UnOp::Not,
                expr: Box::new(inner),
            },
        ))
    }

    /// Parse a primary expression: a number, string, boolean, `null`, or
    /// context reference, tried in that order.
    fn parse_primary(&mut self) -> PResult<'src> {
        if let Some(expr) = self.try_number() {
            return Ok(expr);
        }
        if let Some(expr) = self.try_string()? {
            return Ok(expr);
        }
        if let Some(expr) = self.try_keyword_literal() {
            return Ok(expr);
        }
        self.parse_context()
    }

    /// Try to parse a numeric literal. Returns `None` (leaving the cursor
    /// untouched) if no number is present.
    fn try_number(&mut self) -> Option<SpannedExpr<'src>> {
        let start = self.pos;
        let end = self.scan_number()?;
        self.pos = end;
        let value = parse_number(&self.src[start..end]);
        Some(SpannedExpr::new(
            self.origin_from(start),
            Expr::from(value),
        ))
    }

    /// Scan a numeric literal starting at the cursor, returning the byte
    /// offset just past it. Does not move the cursor.
    ///
    /// Supports hexadecimal (`0x`), octal (`0o`), `NaN`, optionally-signed
    /// `Infinity`, and optionally-signed decimals with optional fraction
    /// and exponent.
    fn scan_number(&self) -> Option<usize> {
        let bytes = self.bytes();
        let len = bytes.len();
        let start = self.pos;

        // Hexadecimal: `0x` followed by one or more hex digits.
        if self.rest().starts_with("0x") {
            let mut i = start + 2;
            while i < len && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            if i > start + 2 {
                return Some(i);
            }
        }

        // Octal: `0o` followed by one or more octal digits.
        if self.rest().starts_with("0o") {
            let mut i = start + 2;
            while i < len && (b'0'..=b'7').contains(&bytes[i]) {
                i += 1;
            }
            if i > start + 2 {
                return Some(i);
            }
        }

        // `NaN`.
        if self.rest().starts_with("NaN") {
            return Some(start + 3);
        }

        // Optionally-signed `Infinity`.
        {
            let mut i = start;
            if matches!(bytes.get(i), Some(b'+' | b'-')) {
                i += 1;
            }
            if self.src[i..].starts_with("Infinity") {
                return Some(i + "Infinity".len());
            }
        }

        // Optionally-signed decimal.
        let mut i = start;
        if matches!(bytes.get(i), Some(b'+' | b'-')) {
            i += 1;
        }

        let int_start = i;
        while i < len && bytes[i].is_ascii_digit() {
            i += 1;
        }
        let has_int = i > int_start;

        let mantissa_ok = if has_int {
            // Optional `.` followed by zero or more digits.
            if bytes.get(i) == Some(&b'.') {
                i += 1;
                while i < len && bytes[i].is_ascii_digit() {
                    i += 1;
                }
            }
            true
        } else if bytes.get(i) == Some(&b'.') {
            // `.` followed by one or more digits.
            i += 1;
            let frac_start = i;
            while i < len && bytes[i].is_ascii_digit() {
                i += 1;
            }
            i > frac_start
        } else {
            false
        };

        if !mantissa_ok {
            return None;
        }

        // Optional exponent: `[eE] [+-]? digit+`. If the exponent is
        // malformed, the number ends just before the `e`/`E`.
        if matches!(bytes.get(i), Some(b'e' | b'E')) {
            let mut j = i + 1;
            if matches!(bytes.get(j), Some(b'+' | b'-')) {
                j += 1;
            }
            let exp_start = j;
            while j < len && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j > exp_start {
                i = j;
            }
        }

        Some(i)
    }

    /// Try to parse a single-quoted string literal. Within a string, a
    /// doubled quote (`''`) is an escaped literal quote.
    ///
    /// Returns `Ok(None)` if there is no string at the cursor, and an
    /// error only if a string is started but never terminated.
    fn try_string(&mut self) -> Result<Option<SpannedExpr<'src>>, Error> {
        if self.peek() != Some(b'\'') {
            return Ok(None);
        }

        let start = self.pos;
        let bytes = self.bytes();
        let inner_start = start + 1;
        let mut i = inner_start;

        loop {
            match bytes.get(i) {
                None => return Err(syntax_error("unterminated string literal", start)),
                Some(b'\'') => {
                    if bytes.get(i + 1) == Some(&b'\'') {
                        // An escaped quote; consume both bytes and continue.
                        i += 2;
                    } else {
                        // The closing quote.
                        let inner = &self.src[inner_start..i];
                        self.pos = i + 1;
                        // Borrow the source directly unless the literal
                        // contains an escaped quote that must be unescaped.
                        let value = if inner.contains('\'') {
                            Cow::Owned(inner.replace("''", "'"))
                        } else {
                            Cow::Borrowed(inner)
                        };
                        return Ok(Some(SpannedExpr::new(
                            self.origin_from(start),
                            Expr::Literal(Literal::String(value)),
                        )));
                    }
                }
                // Any other byte is string content. UTF-8 continuation
                // bytes are always >= 0x80, so stepping byte-by-byte never
                // misreads a multi-byte character as a quote.
                Some(_) => i += 1,
            }
        }
    }

    /// Try to parse a `true`, `false`, or `null` keyword literal.
    ///
    /// Like the original grammar, these keywords are matched greedily and
    /// without a trailing word boundary, so e.g. `trueish` is *not* a valid
    /// identifier.
    fn try_keyword_literal(&mut self) -> Option<SpannedExpr<'src>> {
        let start = self.pos;
        let literal = if self.eat("true") {
            Literal::Boolean(true)
        } else if self.eat("false") {
            Literal::Boolean(false)
        } else if self.eat("null") {
            Literal::Null
        } else {
            return None;
        };

        Some(SpannedExpr::new(
            self.origin_from(start),
            Expr::Literal(literal),
        ))
    }

    /// Parse a context reference: a head (identifier, function call, or
    /// parenthesized expression) followed by zero or more `.member`,
    /// `.*`, or `[index]` accesses.
    fn parse_context(&mut self) -> PResult<'src> {
        let start = self.pos;
        let head = self.parse_context_head()?;
        // Whitespace after the head is always part of the context's span.
        self.skip_ws();

        let mut parts = vec![head];
        loop {
            if self.eat_byte(b'.') {
                self.skip_ws();
                parts.push(self.parse_member()?);
            } else if self.peek() == Some(b'[') {
                parts.push(self.parse_index()?);
            } else {
                break;
            }

            // Look ahead past whitespace for another access. Unlike the
            // whitespace after the head, whitespace trailing the *final*
            // access is not part of the context's span, so we only commit
            // to skipping it once we know another access follows.
            let checkpoint = self.pos;
            self.skip_ws();
            if !matches!(self.peek(), Some(b'.' | b'[')) {
                self.pos = checkpoint;
                break;
            }
        }

        // A context wrapping a single non-identifier expression (a bare
        // function call or parenthesized expression) is unwrapped, so that
        // e.g. `format(...)` and `(a || b)` don't gain pointless `Context`
        // nesting. Bare identifiers stay wrapped, since they are genuine
        // single-component context references (e.g. `github`).
        if parts.len() == 1 && !matches!(parts[0].inner, Expr::Identifier(_)) {
            return Ok(parts.remove(0));
        }

        Ok(SpannedExpr::new(
            self.origin_from(start),
            Expr::context(parts),
        ))
    }

    /// Parse the head of a context: a function call, a bare identifier, or
    /// a parenthesized expression.
    fn parse_context_head(&mut self) -> PResult<'src> {
        match self.peek() {
            Some(b'(') => {
                self.pos += 1; // consume '('
                self.skip_ws();
                let inner = self.parse_or()?;
                self.skip_ws();
                if !self.eat_byte(b')') {
                    return Err(syntax_error("expected `)`", self.pos));
                }
                Ok(inner)
            }
            Some(byte) if is_identifier_start(byte) => {
                let start = self.pos;
                let name = self.consume_identifier();
                let ident_end = self.pos;

                // A `(` here -- possibly after whitespace -- makes this a
                // function call rather than a bare identifier.
                self.skip_ws();
                if self.peek() == Some(b'(') {
                    self.parse_call(start, name)
                } else {
                    Ok(SpannedExpr::new(
                        Origin::new(start..ident_end, &self.src[start..ident_end]),
                        Expr::ident(name),
                    ))
                }
            }
            _ => Err(syntax_error("expected an expression", self.pos)),
        }
    }

    /// Parse a function call. `start` is the byte offset of the function
    /// name and `name` is the already-consumed name; the cursor is at the
    /// opening `(`.
    fn parse_call(&mut self, start: usize, name: &'src str) -> PResult<'src> {
        self.pos += 1; // consume '('
        self.skip_ws();

        let mut args = Vec::new();
        if self.peek() != Some(b')') {
            loop {
                // `parse_or` consumes any whitespace trailing the argument.
                args.push(self.parse_or()?);
                if self.eat_byte(b',') {
                    self.skip_ws();
                } else {
                    break;
                }
            }
        }

        if !self.eat_byte(b')') {
            return Err(syntax_error("expected `,` or `)`", self.pos));
        }

        let origin = self.origin_from(start);
        let call = Call::new(name, args)?;
        Ok(SpannedExpr::new(origin, Expr::Call(call)))
    }

    /// Parse a `.member` access component: an identifier or a `*` wildcard.
    fn parse_member(&mut self) -> PResult<'src> {
        match self.peek() {
            Some(b'*') => Ok(self.parse_star()),
            Some(byte) if is_identifier_start(byte) => {
                let start = self.pos;
                let name = self.consume_identifier();
                Ok(SpannedExpr::new(self.origin_from(start), Expr::ident(name)))
            }
            _ => Err(syntax_error("expected an identifier or `*`", self.pos)),
        }
    }

    /// Parse a `[index]` access component. The index is either a full
    /// expression or a bare `*` wildcard.
    fn parse_index(&mut self) -> PResult<'src> {
        let start = self.pos;
        self.pos += 1; // consume '['
        self.skip_ws();

        // No expression can begin with `*`, so a leading `*` here is
        // unambiguously the wildcard alternative.
        let inner = if self.peek() == Some(b'*') {
            self.parse_star()
        } else {
            self.parse_or()?
        };

        self.skip_ws();
        if !self.eat_byte(b']') {
            return Err(syntax_error("expected `]`", self.pos));
        }

        Ok(SpannedExpr::new(
            self.origin_from(start),
            Expr::Index(Box::new(inner)),
        ))
    }

    /// Parse a `*` wildcard at the cursor.
    fn parse_star(&mut self) -> SpannedExpr<'src> {
        let start = self.pos;
        self.pos += 1; // consume '*'
        SpannedExpr::new(self.origin_from(start), Expr::Star)
    }

    /// Consume an identifier at the cursor. The caller must have already
    /// confirmed that the byte at the cursor is a valid identifier start.
    fn consume_identifier(&mut self) -> &'src str {
        let start = self.pos;
        self.pos += 1; // the (already-validated) start byte
        while self.peek().is_some_and(is_identifier_continue) {
            self.pos += 1;
        }
        &self.src[start..self.pos]
    }
}
