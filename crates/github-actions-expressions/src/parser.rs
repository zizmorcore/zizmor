//! Recursive descent parser for GitHub Actions expressions.
//!
//! The grammar follows GitHub's `actions/languageservices` reference, but is
//! deliberately permissive about unknown context names.

use std::borrow::Cow;

use crate::{
    Error, Expr, Origin, SpannedExpr,
    call::Call,
    lexer::{self, Tok, Token, syntax_error},
    literal::Literal,
    op::{BinOp, UnOp},
};

/// The result of parsing a single grammar production.
type PResult<'src> = Result<SpannedExpr<'src>, Error>;

/// Parse a complete GitHub Actions expression. The whole input must be
/// consumed (modulo whitespace).
pub(crate) fn parse(src: &str) -> Result<SpannedExpr<'_>, Error> {
    let mut parser = Parser {
        src,
        tokens: lexer::lex(src)?,
        pos: 0,
    };

    if parser.peek().is_none() {
        return Err(parser.error_here("empty expression"));
    }

    let expr = parser.parse_expr(0)?;

    if parser.peek().is_some() {
        return Err(parser.error_here("unexpected trailing input"));
    }

    Ok(expr)
}

/// A recursive descent parser over a lexed token stream.
struct Parser<'src> {
    src: &'src str,
    tokens: Vec<Token<'src>>,
    pos: usize,
}

/// Map an operator token to its [`BinOp`] and binding power (higher binds
/// tighter), or `None` for any non-operator token.
fn binop(tok: Tok<'_>) -> Option<(BinOp, u8)> {
    Some(match tok {
        Tok::Or => (BinOp::Or, 1),
        Tok::And => (BinOp::And, 2),
        Tok::EqualEqual => (BinOp::Eq, 3),
        Tok::BangEqual => (BinOp::Neq, 3),
        Tok::Greater => (BinOp::Gt, 4),
        Tok::GreaterEqual => (BinOp::Ge, 4),
        Tok::Less => (BinOp::Lt, 4),
        Tok::LessEqual => (BinOp::Le, 4),
        _ => return None,
    })
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

    /// Advance past and return the current token. The caller must have already
    /// confirmed, via [`Parser::peek`], that a token is present.
    fn bump(&mut self) -> Token<'src> {
        let token = self.tokens[self.pos];
        self.pos += 1;
        token
    }

    /// Consume and return the current token if `predicate` accepts its kind.
    fn eat(&mut self, predicate: fn(Tok<'src>) -> bool) -> Option<Token<'src>> {
        let token = self.peek().filter(|t| predicate(t.tok))?;
        self.pos += 1;
        Some(token)
    }

    /// Like [`Parser::eat`], but fails with `message` when nothing matches.
    fn expect(
        &mut self,
        predicate: fn(Tok<'src>) -> bool,
        message: &'static str,
    ) -> Result<Token<'src>, Error> {
        self.eat(predicate).ok_or_else(|| self.error_here(message))
    }

    /// A syntax error blaming the current token, or end of input.
    fn error_here(&self, message: &'static str) -> Error {
        let offset = self
            .peek()
            .map_or_else(|| self.tokens.last().map_or(0, |t| t.end), |t| t.start);
        syntax_error(message, offset)
    }

    /// Build a [`SpannedExpr`] spanning `[start, end)`.
    fn spanned(&self, start: usize, end: usize, expr: Expr<'src>) -> SpannedExpr<'src> {
        SpannedExpr::new(Origin::new(start..end, &self.src[start..end]), expr)
    }

    /// Parse an expression via precedence climbing, consuming binary
    /// operators whose binding power is at least `min_bp`. All operators are
    /// left-associative; the precedences are (loosest to tightest) `||`,
    /// `&&`, `==`/`!=`, then `>`/`>=`/`<`/`<=`.
    fn parse_expr(&mut self, min_bp: u8) -> PResult<'src> {
        let mut lhs = self.parse_unary()?;

        while let Some((op, bp)) = self.peek_tok().and_then(binop) {
            if bp < min_bp {
                break;
            }
            self.pos += 1;
            let rhs = self.parse_expr(bp + 1)?;
            lhs = self.spanned(
                lhs.origin.span.start,
                rhs.origin.span.end,
                Expr::BinOp {
                    lhs: Box::new(lhs),
                    op,
                    rhs: Box::new(rhs),
                },
            );
        }

        Ok(lhs)
    }

    /// Parse a unary expression. Each `!` binds tightly to what follows it, so
    /// `!!x` is `!(!x)` and `!!x || y` is `(!!x) || y`.
    fn parse_unary(&mut self) -> PResult<'src> {
        let Some(bang) = self.eat(|t| matches!(t, Tok::Bang)) else {
            return self.parse_postfix();
        };

        let inner = self.parse_unary()?;
        Ok(self.spanned(
            bang.start,
            inner.origin.span.end,
            Expr::UnOp {
                op: UnOp::Not,
                expr: Box::new(inner),
            },
        ))
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

        // A lone non-identifier head (a bare call or parenthesized expression)
        // is unwrapped; a lone identifier stays a genuine `Context` (`github`).
        if parts.len() == 1 && !head_is_identifier {
            return Ok(parts.remove(0));
        }

        let end = parts.last().expect("at least the head").origin.span.end;
        Ok(self.spanned(start, end, Expr::context(parts)))
    }

    /// Parse a `.member` access: an identifier or a `*` wildcard.
    fn parse_member(&mut self) -> PResult<'src> {
        match self.peek_tok() {
            Some(Tok::Ident(name)) => {
                let token = self.bump();
                Ok(self.spanned(token.start, token.end, Expr::ident(name)))
            }
            Some(Tok::Star) => Ok(self.parse_star()),
            _ => Err(self.error_here("expected an identifier or `*`")),
        }
    }

    /// Parse a `[index]` access: either a full expression or a bare `*`.
    fn parse_index(&mut self) -> PResult<'src> {
        let open = self.bump(); // '['

        let inner = if matches!(self.peek_tok(), Some(Tok::Star)) {
            self.parse_star()
        } else {
            self.parse_expr(0)?
        };

        let close = self.expect(|t| matches!(t, Tok::RBracket), "expected `]`")?;
        Ok(self.spanned(open.start, close.end, Expr::Index(Box::new(inner))))
    }

    /// Parse a `*` wildcard. The caller must have confirmed the current token
    /// is a [`Tok::Star`].
    fn parse_star(&mut self) -> SpannedExpr<'src> {
        let token = self.bump();
        self.spanned(token.start, token.end, Expr::Star)
    }

    /// Parse a primary expression: a literal, parenthesized expression,
    /// identifier, or function call. The returned flag is whether it can take
    /// a trailing `.member`/`[index]` access (identifiers, calls, groupings).
    fn parse_primary(&mut self) -> Result<(SpannedExpr<'src>, bool), Error> {
        let Some(token) = self.peek() else {
            return Err(self.error_here("unexpected end of expression"));
        };

        // `(...)`, identifiers, and calls are accessible heads, returned
        // inline; every other primary is a one-token literal handled below.
        let literal = match token.tok {
            Tok::Number(value) => Literal::Number(value),
            Tok::True => Literal::Boolean(true),
            Tok::False => Literal::Boolean(false),
            Tok::Null => Literal::Null,
            Tok::Str => Literal::String(self.string_value(token)),
            Tok::LParen => {
                self.pos += 1;
                let inner = self.parse_expr(0)?;
                let close = self.expect(|t| matches!(t, Tok::RParen), "expected `)`")?;
                // A grouping has no AST node; re-span the inner expression over
                // the parens so every span stays a balanced slice of the source.
                return Ok((self.spanned(token.start, close.end, inner.inner), true));
            }
            Tok::Ident(name) => {
                self.pos += 1;
                let expr = if matches!(self.peek_tok(), Some(Tok::LParen)) {
                    self.parse_call(token.start, name)?
                } else {
                    self.spanned(token.start, token.end, Expr::ident(name))
                };
                return Ok((expr, true));
            }
            _ => return Err(self.error_here("expected an expression")),
        };

        self.pos += 1;
        Ok((
            self.spanned(token.start, token.end, Expr::Literal(literal)),
            false,
        ))
    }

    /// Parse a function call. `start` is the offset of the function name and
    /// `name` is the name; the cursor is at the opening `(`.
    fn parse_call(&mut self, start: usize, name: &'src str) -> PResult<'src> {
        self.pos += 1; // consume '('

        let mut args = Vec::new();
        let close = loop {
            // A `)` ends the argument list, whether it's empty or trailing.
            if let Some(close) = self.eat(|t| matches!(t, Tok::RParen)) {
                break close;
            }

            args.push(self.parse_expr(0)?);

            if let Some(close) = self.eat(|t| matches!(t, Tok::RParen)) {
                break close;
            }
            if self.eat(|t| matches!(t, Tok::Comma)).is_none() {
                return Err(self.error_here("expected `,` or `)`"));
            }
        };

        Ok(self.spanned(start, close.end, Expr::Call(Call::new(name, args)?)))
    }

    /// The unescaped value of a [`Tok::Str`] token: quotes trimmed and `''`
    /// collapsed to `'`, borrowing from the source unless unescaping is needed.
    fn string_value(&self, token: Token<'src>) -> Cow<'src, str> {
        let inner = &self.src[token.start + 1..token.end - 1];
        if inner.contains('\'') {
            Cow::Owned(inner.replace("''", "'"))
        } else {
            Cow::Borrowed(inner)
        }
    }
}
