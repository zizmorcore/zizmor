//! A hand-written, dependency-free parser for GitHub Actions expressions.
//!
//! Parsing happens in two phases:
//!
//! 1. The [`Lexer`] turns the source string into a flat list of [`Token`]s,
//!    discarding whitespace. Every token carries a precise byte range.
//! 2. The [`Parser`] is a recursive descent parser over those tokens. Because
//!    it works on tokens rather than raw characters, every AST node's span is
//!    simply the range from its first token to its last token -- tight, and
//!    free of the whitespace artifacts a character-level parser would incur.
//!
//! The structure is loosely modeled on GitHub's reference implementation in
//! `actions/languageservices`, but builds zizmor's own AST and is deliberately
//! permissive about unknown context names.

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
/// The entire input must be consumed (modulo whitespace); otherwise a
/// [`SyntaxError`] is returned.
pub(crate) fn parse(src: &str) -> Result<SpannedExpr<'_>, Error> {
    let tokens = Lexer::new(src).lex()?;
    let mut parser = Parser {
        src,
        tokens,
        pos: 0,
    };

    if parser.peek().is_none() {
        return Err(syntax_error("empty expression", 0));
    }

    let expr = parser.parse_or()?;

    if let Some(token) = parser.peek() {
        return Err(syntax_error("unexpected trailing input", token.start));
    }

    Ok(expr)
}

/// Build an [`Error`] for a syntax error at the given byte offset.
fn syntax_error(message: &'static str, offset: usize) -> Error {
    Error::Syntax(SyntaxError { message, offset })
}

// --- lexer -----------------------------------------------------------------

/// A lexical token.
#[derive(Clone, Copy)]
enum Tok<'src> {
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Dot,
    Star,
    Bang,
    BangEqual,
    EqualEqual,
    Greater,
    GreaterEqual,
    Less,
    LessEqual,
    And,
    Or,
    /// A numeric literal; the parsed value is carried inline.
    Number(f64),
    /// A string literal; its value is derived from the token's byte range.
    Str,
    /// An identifier; its name is the slice between `start` and `end`.
    Ident(&'src str),
    True,
    False,
    Null,
}

/// A token along with its byte range `[start, end)` in the source.
#[derive(Clone, Copy)]
struct Token<'src> {
    tok: Tok<'src>,
    start: usize,
    end: usize,
}

/// Returns whether `byte` terminates an identifier or number lexeme.
///
/// Note that `.` is a boundary here, but numbers treat it specially (a number
/// may contain `.`), so callers scanning numbers handle it themselves.
fn is_boundary(byte: u8) -> bool {
    byte.is_ascii_whitespace()
        || matches!(
            byte,
            b'(' | b')' | b'[' | b']' | b',' | b'.' | b'!' | b'<' | b'>' | b'=' | b'&' | b'|'
        )
}

/// Returns whether `byte` can begin an identifier.
fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

/// Returns whether `lexeme` is a well-formed identifier.
fn is_legal_identifier(lexeme: &str) -> bool {
    let mut bytes = lexeme.bytes();
    match bytes.next() {
        Some(first) if is_identifier_start(first) => {}
        _ => return false,
    }
    bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Turns a source string into a flat list of [`Token`]s.
struct Lexer<'src> {
    src: &'src str,
    pos: usize,
    tokens: Vec<Token<'src>>,
}

impl<'src> Lexer<'src> {
    fn new(src: &'src str) -> Self {
        Self {
            src,
            pos: 0,
            tokens: Vec::new(),
        }
    }

    fn bytes(&self) -> &'src [u8] {
        self.src.as_bytes()
    }

    fn lex(mut self) -> Result<Vec<Token<'src>>, Error> {
        let bytes = self.bytes();

        loop {
            // Skip whitespace between tokens.
            while self.pos < bytes.len() && bytes[self.pos].is_ascii_whitespace() {
                self.pos += 1;
            }
            if self.pos >= bytes.len() {
                break;
            }

            let start = self.pos;
            let byte = bytes[start];
            let next = bytes.get(start + 1).copied();

            match byte {
                b'(' => self.push(Tok::LParen, start, start + 1),
                b')' => self.push(Tok::RParen, start, start + 1),
                b'[' => self.push(Tok::LBracket, start, start + 1),
                b']' => self.push(Tok::RBracket, start, start + 1),
                b',' => self.push(Tok::Comma, start, start + 1),
                b'*' => self.push(Tok::Star, start, start + 1),
                b'!' if next == Some(b'=') => self.push(Tok::BangEqual, start, start + 2),
                b'!' => self.push(Tok::Bang, start, start + 1),
                b'<' if next == Some(b'=') => self.push(Tok::LessEqual, start, start + 2),
                b'<' => self.push(Tok::Less, start, start + 1),
                b'>' if next == Some(b'=') => self.push(Tok::GreaterEqual, start, start + 2),
                b'>' => self.push(Tok::Greater, start, start + 1),
                b'=' if next == Some(b'=') => self.push(Tok::EqualEqual, start, start + 2),
                b'=' => return Err(syntax_error("expected `==`", start)),
                b'&' if next == Some(b'&') => self.push(Tok::And, start, start + 2),
                b'&' => return Err(syntax_error("expected `&&`", start)),
                b'|' if next == Some(b'|') => self.push(Tok::Or, start, start + 2),
                b'|' => return Err(syntax_error("expected `||`", start)),
                b'\'' => self.lex_string()?,
                // A `.` begins a number unless it follows something a member
                // access can attach to, in which case it's a `.` accessor.
                b'.' if self.prev_allows_dot() => self.push(Tok::Dot, start, start + 1),
                b'.' | b'+' | b'-' | b'0'..=b'9' => self.lex_number()?,
                _ => self.lex_identifier()?,
            }
        }

        Ok(self.tokens)
    }

    fn push(&mut self, tok: Tok<'src>, start: usize, end: usize) {
        self.tokens.push(Token { tok, start, end });
        self.pos = end;
    }

    /// Whether the previous token is one a `.` member access can follow.
    fn prev_allows_dot(&self) -> bool {
        matches!(
            self.tokens.last().map(|t| t.tok),
            Some(Tok::Ident(_) | Tok::RBracket | Tok::RParen | Tok::Star)
        )
    }

    /// Lex a single-quoted string literal. A doubled quote (`''`) is an
    /// escaped literal quote.
    fn lex_string(&mut self) -> Result<(), Error> {
        let bytes = self.bytes();
        let start = self.pos;
        let mut i = start + 1;

        loop {
            match bytes.get(i) {
                None => return Err(syntax_error("unterminated string literal", start)),
                Some(b'\'') if bytes.get(i + 1) == Some(&b'\'') => i += 2,
                Some(b'\'') => break,
                // Any other byte is content; UTF-8 continuation bytes are
                // always >= 0x80, so a quote is never misread.
                Some(_) => i += 1,
            }
        }

        self.push(Tok::Str, start, i + 1);
        Ok(())
    }

    /// Lex a numeric literal. The lexeme runs to the next boundary (with `.`
    /// allowed within), and must parse to a finite, non-`NaN` value.
    fn lex_number(&mut self) -> Result<(), Error> {
        let bytes = self.bytes();
        let start = self.pos;
        let mut i = start;
        while i < bytes.len() && (!is_boundary(bytes[i]) || bytes[i] == b'.') {
            i += 1;
        }

        let value = parse_number(&self.src[start..i]);
        if value.is_nan() {
            return Err(syntax_error("invalid numeric literal", start));
        }

        self.push(Tok::Number(value), start, i);
        Ok(())
    }

    /// Lex an identifier or a keyword (`true`, `false`, `null`, `NaN`,
    /// `Infinity`). Keywords are only recognized when not immediately
    /// following a `.`, so e.g. `foo.true` accesses a member named `true`.
    fn lex_identifier(&mut self) -> Result<(), Error> {
        let bytes = self.bytes();
        let start = self.pos;
        let mut i = start;
        while i < bytes.len() && !is_boundary(bytes[i]) {
            i += 1;
        }

        let lexeme = &self.src[start..i];
        if !is_legal_identifier(lexeme) {
            return Err(syntax_error("unexpected symbol", start));
        }

        let after_dot = matches!(self.tokens.last().map(|t| t.tok), Some(Tok::Dot));
        let tok = match lexeme {
            "true" if !after_dot => Tok::True,
            "false" if !after_dot => Tok::False,
            "null" if !after_dot => Tok::Null,
            "NaN" if !after_dot => Tok::Number(f64::NAN),
            "Infinity" if !after_dot => Tok::Number(f64::INFINITY),
            _ => Tok::Ident(lexeme),
        };

        self.push(tok, start, i);
        Ok(())
    }
}

// --- parser ----------------------------------------------------------------

/// A recursive descent parser over a lexed token stream.
struct Parser<'src> {
    src: &'src str,
    tokens: Vec<Token<'src>>,
    pos: usize,
}

impl<'src> Parser<'src> {
    /// The token at the cursor, if any.
    fn peek(&self) -> Option<Token<'src>> {
        self.tokens.get(self.pos).copied()
    }

    /// The kind of the token at the cursor, if any.
    fn peek_tok(&self) -> Option<Tok<'src>> {
        self.peek().map(|t| t.tok)
    }

    /// Build an [`Origin`] spanning `[start, end)`.
    fn origin(&self, start: usize, end: usize) -> Origin<'src> {
        Origin::new(start..end, &self.src[start..end])
    }

    /// The byte offset to blame for an "unexpected end of input" error.
    fn end_offset(&self) -> usize {
        self.tokens.last().map_or(0, |t| t.end)
    }

    // --- binary operator precedence levels ---------------------------------

    /// Parse a left-associative chain of binary operators. `operand` parses
    /// the next-higher precedence level; `match_op` recognizes an operator.
    fn parse_binop(
        &mut self,
        operand: fn(&mut Self) -> PResult<'src>,
        match_op: fn(Tok<'src>) -> Option<BinOp>,
    ) -> PResult<'src> {
        let mut lhs = operand(self)?;

        while let Some(op) = self.peek_tok().and_then(match_op) {
            self.pos += 1;
            let rhs = operand(self)?;
            let (start, end) = (lhs.origin.span.start, rhs.origin.span.end);
            lhs = SpannedExpr::new(
                self.origin(start, end),
                Expr::BinOp {
                    lhs: Box::new(lhs),
                    op,
                    rhs: Box::new(rhs),
                },
            );
        }

        Ok(lhs)
    }

    /// Parse a logical-or chain (`||`), the lowest precedence level.
    fn parse_or(&mut self) -> PResult<'src> {
        self.parse_binop(Self::parse_and, |t| {
            matches!(t, Tok::Or).then_some(BinOp::Or)
        })
    }

    /// Parse a logical-and chain (`&&`).
    fn parse_and(&mut self) -> PResult<'src> {
        self.parse_binop(Self::parse_equality, |t| {
            matches!(t, Tok::And).then_some(BinOp::And)
        })
    }

    /// Parse an equality chain (`==`, `!=`).
    fn parse_equality(&mut self) -> PResult<'src> {
        self.parse_binop(Self::parse_comparison, |t| match t {
            Tok::EqualEqual => Some(BinOp::Eq),
            Tok::BangEqual => Some(BinOp::Neq),
            _ => None,
        })
    }

    /// Parse a comparison chain (`>`, `>=`, `<`, `<=`).
    fn parse_comparison(&mut self) -> PResult<'src> {
        self.parse_binop(Self::parse_unary, |t| match t {
            Tok::Greater => Some(BinOp::Gt),
            Tok::GreaterEqual => Some(BinOp::Ge),
            Tok::Less => Some(BinOp::Lt),
            Tok::LessEqual => Some(BinOp::Le),
            _ => None,
        })
    }

    // --- unary, postfix, and primary ---------------------------------------

    /// Parse a unary expression: zero or more `!` applied to a postfix
    /// expression. Each `!` binds tightly to the expression that follows it,
    /// so `!!x` is `!(!x)` and `!!x || y` is `(!!x) || y`.
    fn parse_unary(&mut self) -> PResult<'src> {
        let Some(token) = self.peek() else {
            return Err(syntax_error(
                "unexpected end of expression",
                self.end_offset(),
            ));
        };

        if matches!(token.tok, Tok::Bang) {
            self.pos += 1;
            let inner = self.parse_unary()?;
            let end = inner.origin.span.end;
            return Ok(SpannedExpr::new(
                self.origin(token.start, end),
                Expr::UnOp {
                    op: UnOp::Not,
                    expr: Box::new(inner),
                },
            ));
        }

        self.parse_postfix()
    }

    /// Parse a primary expression followed by zero or more `.member`, `.*`,
    /// or `[index]` accesses, assembling them into a [`Expr::Context`].
    fn parse_postfix(&mut self) -> PResult<'src> {
        let (head, accessible) = self.parse_primary()?;

        // Literals can't take member or index accesses.
        if !accessible {
            return Ok(head);
        }

        let head_is_identifier = matches!(head.inner, Expr::Identifier(_));
        let start = head.origin.span.start;
        let mut parts = vec![head];

        loop {
            match self.peek_tok() {
                Some(Tok::Dot) => {
                    self.pos += 1;
                    parts.push(self.parse_member()?);
                }
                Some(Tok::LBracket) => parts.push(self.parse_index()?),
                _ => break,
            }
        }

        // A context wrapping a single non-identifier expression (a bare
        // function call or parenthesized expression) is unwrapped, to avoid
        // pointless `Context` nesting. Bare identifiers stay wrapped, since
        // they are genuine single-component contexts (e.g. `github`).
        if parts.len() == 1 && !head_is_identifier {
            return Ok(parts.remove(0));
        }

        let end = parts.last().expect("at least the head").origin.span.end;
        Ok(SpannedExpr::new(
            self.origin(start, end),
            Expr::context(parts),
        ))
    }

    /// Parse a `.member` access: an identifier or a `*` wildcard.
    fn parse_member(&mut self) -> PResult<'src> {
        match self.peek() {
            Some(Token {
                tok: Tok::Ident(name),
                start,
                end,
            }) => {
                self.pos += 1;
                Ok(SpannedExpr::new(self.origin(start, end), Expr::ident(name)))
            }
            Some(Token {
                tok: Tok::Star,
                start,
                end,
            }) => {
                self.pos += 1;
                Ok(SpannedExpr::new(self.origin(start, end), Expr::Star))
            }
            Some(token) => Err(syntax_error("expected an identifier or `*`", token.start)),
            None => Err(syntax_error(
                "expected an identifier or `*`",
                self.end_offset(),
            )),
        }
    }

    /// Parse a `[index]` access: either a full expression or a bare `*`.
    fn parse_index(&mut self) -> PResult<'src> {
        let open = self.peek().expect("caller checked for `[`");
        self.pos += 1; // consume '['

        let inner = match self.peek() {
            Some(Token {
                tok: Tok::Star,
                start,
                end,
            }) => {
                self.pos += 1;
                SpannedExpr::new(self.origin(start, end), Expr::Star)
            }
            _ => self.parse_or()?,
        };

        let close = self.expect(|t| matches!(t, Tok::RBracket), "expected `]`")?;

        Ok(SpannedExpr::new(
            self.origin(open.start, close.end),
            Expr::Index(Box::new(inner)),
        ))
    }

    /// Parse a primary expression: a literal, a parenthesized expression, an
    /// identifier, or a function call.
    ///
    /// Returns the parsed expression plus whether it can take a trailing
    /// member or index access (true for identifiers, calls, and groupings).
    fn parse_primary(&mut self) -> Result<(SpannedExpr<'src>, bool), Error> {
        let Some(token) = self.peek() else {
            return Err(syntax_error(
                "unexpected end of expression",
                self.end_offset(),
            ));
        };

        let literal = |kind| {
            Ok((
                SpannedExpr::new(
                    Origin::new(token.start..token.end, &self.src[token.start..token.end]),
                    Expr::Literal(kind),
                ),
                false,
            ))
        };

        match token.tok {
            Tok::Number(value) => {
                self.pos += 1;
                literal(Literal::Number(value))
            }
            Tok::True => {
                self.pos += 1;
                literal(Literal::Boolean(true))
            }
            Tok::False => {
                self.pos += 1;
                literal(Literal::Boolean(false))
            }
            Tok::Null => {
                self.pos += 1;
                literal(Literal::Null)
            }
            Tok::Str => {
                self.pos += 1;
                // The lexeme includes the surrounding quotes; trim them and
                // unescape any doubled quotes, borrowing when possible.
                let inner = &self.src[token.start + 1..token.end - 1];
                let value = if inner.contains('\'') {
                    Cow::Owned(inner.replace("''", "'"))
                } else {
                    Cow::Borrowed(inner)
                };
                literal(Literal::String(value))
            }
            Tok::LParen => {
                self.pos += 1;
                let inner = self.parse_or()?;
                let close = self.expect(|t| matches!(t, Tok::RParen), "expected `)`")?;
                // The grouping has no AST node of its own; re-span the inner
                // expression to cover the parentheses so every span remains a
                // balanced, self-contained slice of the source.
                Ok((
                    SpannedExpr::new(self.origin(token.start, close.end), inner.inner),
                    true,
                ))
            }
            Tok::Ident(name) => {
                self.pos += 1;
                if matches!(self.peek_tok(), Some(Tok::LParen)) {
                    Ok((self.parse_call(token.start, name)?, true))
                } else {
                    Ok((
                        SpannedExpr::new(self.origin(token.start, token.end), Expr::ident(name)),
                        true,
                    ))
                }
            }
            _ => Err(syntax_error("expected an expression", token.start)),
        }
    }

    /// Parse a function call. `start` is the offset of the function name and
    /// `name` is the name; the cursor is at the opening `(`.
    fn parse_call(&mut self, start: usize, name: &'src str) -> PResult<'src> {
        self.pos += 1; // consume '('

        let mut args = Vec::new();
        let close = loop {
            if let Some(close) = self.peek().filter(|t| matches!(t.tok, Tok::RParen)) {
                self.pos += 1;
                break close;
            }

            args.push(self.parse_or()?);

            match self.peek() {
                Some(token) if matches!(token.tok, Tok::RParen) => {
                    self.pos += 1;
                    break token;
                }
                Some(token) if matches!(token.tok, Tok::Comma) => self.pos += 1,
                Some(token) => return Err(syntax_error("expected `,` or `)`", token.start)),
                None => {
                    return Err(syntax_error("expected `,` or `)`", self.end_offset()));
                }
            }
        };

        let call = Call::new(name, args)?;
        Ok(SpannedExpr::new(
            self.origin(start, close.end),
            Expr::Call(call),
        ))
    }

    /// Consume the token at the cursor if `predicate` accepts it, otherwise
    /// fail with `message`.
    fn expect(
        &mut self,
        predicate: fn(Tok<'src>) -> bool,
        message: &'static str,
    ) -> Result<Token<'src>, Error> {
        match self.peek() {
            Some(token) if predicate(token.tok) => {
                self.pos += 1;
                Ok(token)
            }
            Some(token) => Err(syntax_error(message, token.start)),
            None => Err(syntax_error(message, self.end_offset())),
        }
    }
}
