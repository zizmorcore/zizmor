//! Lexer for GitHub Actions expressions: turns a string into a flat list of
//! [`Token`]s, discarding whitespace. Each token carries a precise byte range.

use crate::{Error, SyntaxError, parse_number};

/// Build an [`Error`] for a syntax error at the given byte offset.
pub(crate) fn syntax_error(message: &'static str, offset: usize) -> Error {
    Error::Syntax(SyntaxError { message, offset })
}

/// A lexical token kind, carrying any associated value.
#[derive(Clone, Copy)]
pub(crate) enum Tok<'src> {
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
    /// A numeric literal.
    Number(f64),
    /// A string literal; its value is derived from the token's byte range.
    Str,
    /// An identifier.
    Ident(&'src str),
    True,
    False,
    Null,
}

/// A token along with its byte range `[start, end)` in the source.
#[derive(Clone, Copy)]
pub(crate) struct Token<'src> {
    pub(crate) tok: Tok<'src>,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

/// Returns whether `byte` terminates an identifier or number lexeme.
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

/// Tokenize `src` into a flat list of [`Token`]s.
pub(crate) fn lex(src: &str) -> Result<Vec<Token<'_>>, Error> {
    Lexer {
        src,
        pos: 0,
        tokens: Vec::new(),
    }
    .run()
}

struct Lexer<'src> {
    src: &'src str,
    pos: usize,
    tokens: Vec<Token<'src>>,
}

impl<'src> Lexer<'src> {
    fn bytes(&self) -> &'src [u8] {
        self.src.as_bytes()
    }

    fn run(mut self) -> Result<Vec<Token<'src>>, Error> {
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
                // A `.` is a member accessor after a value, else it starts a number.
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

    /// Lex a single-quoted string literal (`''` is an escaped quote).
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

    /// Lex a numeric literal; it must parse to a finite, non-`NaN` value.
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

    /// Lex an identifier, or a keyword (`true`/`false`/`null`/`NaN`/`Infinity`)
    /// when not following a `.` (so `foo.true` accesses a member named `true`).
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
