//! Lexer, parsers and canonical printer (§4.2, §4.7 of the design note).
//!
//! There is one parser, which accepts any CEL spelling of a condition in the
//! subset. Strict parsing is that parser plus one rule: the text must equal
//! the canonical print of what it parsed to. The limits are enforced here,
//! before any schema is read.

use std::fmt::{self, Write as _};

use crate::{
    ast::{Condition, Field, Literal, MAX_SEGMENTS, Operand, Path, RESERVED, Relop, Variable, is_escaped_char, is_ident},
    time::{Duration, Timestamp},
};

/// At most this many bytes of text.
pub const MAX_TEXT_BYTES: usize = 4096;
/// At most this many terms in one `&&` or `||` run, after flattening.
pub const MAX_TERMS: usize = 32;
/// At most this many elements in an `in` list.
pub const MAX_LIST_ELEMENTS: usize = 32;
/// At most this many nested parentheses or `!`.
pub const MAX_NESTING: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Strict,
    Lenient,
}

/// A refusal from the parser, with the byte offset it refers to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    pub kind: ParseErrorKind,
    pub offset: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseErrorKind {
    /// Not a condition in the subset.
    Syntax(String),
    /// A string, number, timestamp or duration literal that does not parse.
    Literal(String),
    /// Over one of the limits.
    Limit(Limit),
    /// Strict parsing: the text parses, but is not the canonical spelling.
    NotCanonical { canonical: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit {
    TextBytes,
    Terms,
    ListElements,
    Nesting,
    Segments,
}

impl ParseError {
    /// A stable name for the kind of error: `syntax`, `literal`, `limit` or
    /// `not-canonical`. The conformance corpus uses these names.
    pub fn code(&self) -> &'static str {
        match self.kind {
            ParseErrorKind::Syntax(_) => "syntax",
            ParseErrorKind::Literal(_) => "literal",
            ParseErrorKind::Limit(_) => "limit",
            ParseErrorKind::NotCanonical { .. } => "not-canonical",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ParseErrorKind::Syntax(message) | ParseErrorKind::Literal(message) => write!(f, "{message} at byte {}", self.offset),
            ParseErrorKind::Limit(limit) => {
                let what = match limit {
                    Limit::TextBytes => format!("more than {MAX_TEXT_BYTES} bytes of text"),
                    Limit::Terms => format!("more than {MAX_TERMS} terms in one && or || run"),
                    Limit::ListElements => format!("more than {MAX_LIST_ELEMENTS} list elements"),
                    Limit::Nesting => format!("more than {MAX_NESTING} nested parentheses or !"),
                    Limit::Segments => format!("more than {MAX_SEGMENTS} segments in a name"),
                };
                write!(f, "{what} at byte {}", self.offset)
            }
            ParseErrorKind::NotCanonical { canonical } => write!(f, "not canonical text; the canonical spelling is {canonical}"),
        }
    }
}

impl std::error::Error for ParseError {}

// ---------------------------------------------------------------- lexer

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Ident(String),
    Escaped(String),
    Str(String),
    /// The magnitude of an integer literal; a leading `-` is its own token.
    Int(u64),
    Float(f64),
    LParen,
    RParen,
    LBracket,
    RBracket,
    Dot,
    Comma,
    Bang,
    AndAnd,
    OrOr,
    Rel(Relop),
    Minus,
    In,
    True,
    False,
    Null,
    End,
}

struct Lexer<'a> {
    text: &'a str,
    at: usize,
}

fn syntax(offset: usize, message: impl Into<String>) -> ParseError {
    ParseError { kind: ParseErrorKind::Syntax(message.into()), offset }
}

fn literal(offset: usize, message: impl Into<String>) -> ParseError {
    ParseError { kind: ParseErrorKind::Literal(message.into()), offset }
}

impl<'a> Lexer<'a> {
    fn rest(&self) -> &'a str {
        &self.text[self.at..]
    }

    fn skip_space(&mut self) {
        loop {
            let rest = self.rest();
            let trimmed = rest.trim_start_matches(['\t', '\n', '\x0c', '\r', ' ']);
            self.at += rest.len() - trimmed.len();
            if self.rest().starts_with("//") {
                self.at += self.rest().find('\n').unwrap_or(self.rest().len());
            } else {
                return;
            }
        }
    }

    fn next(&mut self) -> Result<(Tok, usize), ParseError> {
        self.skip_space();
        let start = self.at;
        let rest = self.rest();
        let Some(c) = rest.chars().next() else { return Ok((Tok::End, start)) };
        let two = rest.get(..2).unwrap_or("");
        let (tok, len) = match two {
            "&&" => (Tok::AndAnd, 2),
            "||" => (Tok::OrOr, 2),
            "==" => (Tok::Rel(Relop::Eq), 2),
            "!=" => (Tok::Rel(Relop::Ne), 2),
            "<=" => (Tok::Rel(Relop::Le), 2),
            ">=" => (Tok::Rel(Relop::Ge), 2),
            _ => match c {
                '(' => (Tok::LParen, 1),
                ')' => (Tok::RParen, 1),
                '[' => (Tok::LBracket, 1),
                ']' => (Tok::RBracket, 1),
                ',' => (Tok::Comma, 1),
                '!' => (Tok::Bang, 1),
                '<' => (Tok::Rel(Relop::Lt), 1),
                '>' => (Tok::Rel(Relop::Gt), 1),
                '-' => (Tok::Minus, 1),
                '.' if rest[1..].starts_with(|d: char| d.is_ascii_digit()) => return self.number(start),
                '.' => (Tok::Dot, 1),
                '`' => return self.escaped(start),
                '"' | '\'' => return self.string(start, false),
                c if c.is_ascii_digit() => return self.number(start),
                c if c == '_' || c.is_ascii_alphabetic() => return self.word(start),
                '?' | ':' => return Err(syntax(start, "the conditional operator ?: is not in the subset")),
                '+' | '*' | '/' | '%' => return Err(syntax(start, "arithmetic is not in the subset")),
                '{' | '}' => return Err(syntax(start, "map and message literals are not in the subset")),
                other => return Err(syntax(start, format!("unexpected character {other:?}"))),
            },
        };
        self.at += len;
        Ok((tok, start))
    }

    fn word(&mut self, start: usize) -> Result<(Tok, usize), ParseError> {
        let len = self.rest().find(|c: char| !(c == '_' || c.is_ascii_alphanumeric())).unwrap_or(self.rest().len());
        let word = &self.rest()[..len];
        let after = self.rest()[len..].chars().next();
        if matches!(after, Some('"' | '\'')) {
            match word {
                "r" | "R" => {
                    self.at += len;
                    return self.string(start, true);
                }
                "b" | "B" | "rb" | "rB" | "Rb" | "RB" | "br" | "bR" | "Br" | "BR" => {
                    return Err(syntax(start, "bytes literals are not in the subset"));
                }
                _ => {}
            }
        }
        self.at += len;
        let tok = match word {
            "true" => Tok::True,
            "false" => Tok::False,
            "null" => Tok::Null,
            "in" => Tok::In,
            _ => Tok::Ident(word.to_owned()),
        };
        Ok((tok, start))
    }

    fn escaped(&mut self, start: usize) -> Result<(Tok, usize), ParseError> {
        let body = &self.rest()[1..];
        let len = body.find(|c: char| !is_escaped_char(c)).unwrap_or(body.len());
        if len == 0 || !body[len..].starts_with('`') {
            return Err(syntax(start, "an escaped identifier holds one or more letters, digits or _ . - / space between backticks"));
        }
        let name = body[..len].to_owned();
        self.at += len + 2;
        Ok((Tok::Escaped(name), start))
    }

    fn number(&mut self, start: usize) -> Result<(Tok, usize), ParseError> {
        let rest = self.rest();
        let bytes = rest.as_bytes();
        if rest.starts_with("0x") || rest.starts_with("0X") {
            let len = 2 + rest[2..].bytes().take_while(u8::is_ascii_hexdigit).count();
            if len == 2 {
                return Err(literal(start, "a hex integer needs digits"));
            }
            let value = u64::from_str_radix(&rest[2..len], 16).map_err(|_| literal(start, "integer is out of range"))?;
            self.at += len;
            return self.int_suffix(value, start);
        }
        let mut len = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
        let mut float = false;
        if bytes.get(len) == Some(&b'.') && bytes.get(len + 1).is_some_and(u8::is_ascii_digit) {
            float = true;
            len += 1 + bytes[len + 1..].iter().take_while(|b| b.is_ascii_digit()).count();
        }
        if matches!(bytes.get(len), Some(b'e' | b'E')) {
            let mut exp = len + 1;
            if matches!(bytes.get(exp), Some(b'+' | b'-')) {
                exp += 1;
            }
            let digits = bytes[exp..].iter().take_while(|b| b.is_ascii_digit()).count();
            if digits == 0 {
                return Err(literal(start, "a float exponent needs digits"));
            }
            float = true;
            len = exp + digits;
        }
        let lexeme = &rest[..len];
        self.at += len;
        if float {
            let value: f64 = lexeme.parse().map_err(|_| literal(start, "float does not parse"))?;
            if !value.is_finite() {
                return Err(literal(start, "float is out of range"));
            }
            Ok((Tok::Float(value), start))
        } else {
            let value = lexeme.parse().map_err(|_| literal(start, "integer is out of range"))?;
            self.int_suffix(value, start)
        }
    }

    fn int_suffix(&mut self, value: u64, start: usize) -> Result<(Tok, usize), ParseError> {
        match self.rest().chars().next() {
            Some('u' | 'U') => Err(syntax(start, "unsigned integers are not in the subset")),
            Some(c) if c == '_' || c.is_ascii_alphanumeric() => Err(literal(start, "a number runs into a name")),
            _ => Ok((Tok::Int(value), start)),
        }
    }

    fn string(&mut self, start: usize, raw: bool) -> Result<(Tok, usize), ParseError> {
        let rest = self.rest();
        let quote = &rest[..1];
        let triple = rest.starts_with(&quote.repeat(3));
        let delimiter = if triple { quote.repeat(3) } else { quote.to_owned() };
        let mut i = delimiter.len();
        let mut out = String::new();
        loop {
            let tail = &rest[i..];
            if tail.starts_with(&delimiter) {
                i += delimiter.len();
                break;
            }
            let Some(c) = tail.chars().next() else { return Err(literal(start, "unterminated string")) };
            if !triple && (c == '\n' || c == '\r') {
                return Err(literal(start, "a newline in a single-quoted string"));
            }
            if c == '\\' && !raw {
                let (decoded, len) = escape(tail).map_err(|m| literal(self.at + i, m))?;
                out.push(decoded);
                i += len;
            } else {
                out.push(c);
                i += c.len_utf8();
            }
        }
        self.at += i;
        Ok((Tok::Str(out), start))
    }
}

/// One escape sequence at the start of `tail`: the character and the bytes it used.
fn escape(tail: &str) -> Result<(char, usize), &'static str> {
    let bytes = tail.as_bytes();
    let simple = match bytes.get(1) {
        Some(b'a') => Some('\x07'),
        Some(b'b') => Some('\x08'),
        Some(b'f') => Some('\x0c'),
        Some(b'n') => Some('\n'),
        Some(b'r') => Some('\r'),
        Some(b't') => Some('\t'),
        Some(b'v') => Some('\x0b'),
        Some(b'\\') => Some('\\'),
        Some(b'?') => Some('?'),
        Some(b'"') => Some('"'),
        Some(b'\'') => Some('\''),
        Some(b'`') => Some('`'),
        _ => None,
    };
    if let Some(c) = simple {
        return Ok((c, 2));
    }
    let hex = |len: usize| -> Result<u32, &'static str> {
        let digits = tail.get(2..2 + len).ok_or("truncated escape")?;
        if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("bad hex escape");
        }
        u32::from_str_radix(digits, 16).map_err(|_| "bad hex escape")
    };
    let (code, len) = match bytes.get(1) {
        Some(b'x' | b'X') => (hex(2)?, 4),
        Some(b'u') => (hex(4)?, 6),
        Some(b'U') => (hex(8)?, 10),
        Some(b'0'..=b'3') => {
            let digits = tail.get(1..4).ok_or("truncated octal escape")?;
            if !digits.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
                return Err("bad octal escape");
            }
            (u32::from_str_radix(digits, 8).map_err(|_| "bad octal escape")?, 4)
        }
        _ => return Err("unknown escape"),
    };
    char::from_u32(code).map(|c| (c, len)).ok_or("escape is not a Unicode scalar value")
}

// ---------------------------------------------------------------- parser

struct Parser<'a> {
    lexer: Lexer<'a>,
    tok: Tok,
    offset: usize,
    /// The token after `tok`, read only when the grammar needs to look ahead.
    peeked: Option<(Tok, usize)>,
}

pub(crate) fn parse(text: &str, mode: Mode) -> Result<Condition, ParseError> {
    if text.len() > MAX_TEXT_BYTES {
        return Err(ParseError { kind: ParseErrorKind::Limit(Limit::TextBytes), offset: MAX_TEXT_BYTES });
    }
    let mut parser = Parser::new(text)?;
    let condition = parser.or(0)?;
    parser.expect_end()?;
    if mode == Mode::Strict {
        let canonical = condition.to_string();
        if canonical != text {
            let offset = canonical.bytes().zip(text.bytes()).take_while(|(a, b)| a == b).count();
            return Err(ParseError { kind: ParseErrorKind::NotCanonical { canonical }, offset });
        }
    }
    Ok(condition)
}

/// Parses canonical path text.
pub(crate) fn parse_path(text: &str) -> Result<Path, ParseError> {
    let mut parser = Parser::new(text)?;
    let path = match parser.tok.clone() {
        Tok::Ident(_) | Tok::Escaped(_) => parser.path()?,
        _ => return Err(syntax(parser.offset, "expected a path")),
    };
    parser.expect_end()?;
    let canonical = path.to_string();
    if canonical != text {
        return Err(ParseError { kind: ParseErrorKind::NotCanonical { canonical }, offset: 0 });
    }
    Ok(path)
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Result<Self, ParseError> {
        let mut lexer = Lexer { text, at: 0 };
        let (tok, offset) = lexer.next()?;
        Ok(Parser { lexer, tok, offset, peeked: None })
    }

    fn bump(&mut self) -> Result<Tok, ParseError> {
        let (tok, offset) = match self.peeked.take() {
            Some(next) => next,
            None => self.lexer.next()?,
        };
        self.offset = offset;
        Ok(std::mem::replace(&mut self.tok, tok))
    }

    fn peek(&mut self) -> Result<&Tok, ParseError> {
        if self.peeked.is_none() {
            self.peeked = Some(self.lexer.next()?);
        }
        Ok(self.peeked.as_ref().map(|(tok, _)| tok).unwrap_or(&Tok::End))
    }

    fn expect(&mut self, tok: Tok, what: &str) -> Result<(), ParseError> {
        if self.tok == tok {
            self.bump()?;
            Ok(())
        } else {
            Err(syntax(self.offset, format!("expected {what}")))
        }
    }

    fn expect_end(&mut self) -> Result<(), ParseError> {
        match self.tok {
            Tok::End => Ok(()),
            Tok::Rel(_) | Tok::In => Err(syntax(self.offset, "a field must be on the left of a comparison or in")),
            _ => Err(syntax(self.offset, "unexpected text after the condition")),
        }
    }

    fn or(&mut self, depth: usize) -> Result<Condition, ParseError> {
        let start = self.offset;
        let mut terms = vec![self.and(depth)?];
        while self.tok == Tok::OrOr {
            self.bump()?;
            terms.push(self.and(depth)?);
        }
        self.nary(terms, false, start)
    }

    fn and(&mut self, depth: usize) -> Result<Condition, ParseError> {
        let start = self.offset;
        let mut terms = vec![self.unary(depth)?];
        while self.tok == Tok::AndAnd {
            self.bump()?;
            terms.push(self.unary(depth)?);
        }
        self.nary(terms, true, start)
    }

    fn nary(&self, terms: Vec<Condition>, and: bool, start: usize) -> Result<Condition, ParseError> {
        let condition = if and { Condition::and(terms) } else { Condition::or(terms) };
        match &condition {
            Condition::And(terms) | Condition::Or(terms) if terms.len() > MAX_TERMS => {
                Err(ParseError { kind: ParseErrorKind::Limit(Limit::Terms), offset: start })
            }
            _ => Ok(condition),
        }
    }

    fn nest(&self, depth: usize) -> Result<usize, ParseError> {
        if depth >= MAX_NESTING {
            return Err(ParseError { kind: ParseErrorKind::Limit(Limit::Nesting), offset: self.offset });
        }
        Ok(depth + 1)
    }

    fn unary(&mut self, depth: usize) -> Result<Condition, ParseError> {
        if self.tok == Tok::Bang {
            let depth = self.nest(depth)?;
            self.bump()?;
            return Ok(Condition::Not(Box::new(self.unary(depth)?)));
        }
        self.atom(depth)
    }

    fn atom(&mut self, depth: usize) -> Result<Condition, ParseError> {
        match self.tok.clone() {
            Tok::LParen => {
                let depth = self.nest(depth)?;
                self.bump()?;
                let inner = self.or(depth)?;
                self.expect(Tok::RParen, ")")?;
                Ok(inner)
            }
            Tok::True | Tok::False => Ok(Condition::Bool(self.bump()? == Tok::True)),
            Tok::Str(key) => {
                self.bump()?;
                self.expect(Tok::In, "in after a string on the left")?;
                let field = self.field()?;
                Ok(Condition::Member { key, field })
            }
            Tok::Ident(name) if name == "has" && *self.peek()? == Tok::LParen => {
                self.bump()?;
                self.bump()?;
                let path = match self.tok {
                    Tok::Ident(_) | Tok::Escaped(_) => self.path()?,
                    _ => return Err(syntax(self.offset, "has() takes a field path")),
                };
                if self.tok == Tok::LBracket {
                    return Err(syntax(self.offset, "has() takes a path with no index; a map key's presence is \"k\" in m"));
                }
                self.expect(Tok::RParen, ")")?;
                Ok(Condition::Has(path))
            }
            Tok::Ident(_) | Tok::Escaped(_) => self.after_field(),
            Tok::Null => Err(syntax(self.offset, "null is not in the subset; test presence with has()")),
            Tok::End => Err(syntax(self.offset, "expected a condition")),
            _ => Err(syntax(self.offset, "a field must be on the left of a comparison or in")),
        }
    }

    fn after_field(&mut self) -> Result<Condition, ParseError> {
        let (field, under) = self.field_or_under()?;
        if under {
            self.bump()?;
            let prefix = self.operand()?;
            self.expect(Tok::RParen, ")")?;
            return Ok(Condition::Under { field, prefix });
        }
        match self.tok {
            Tok::Rel(op) => {
                self.bump()?;
                Ok(Condition::Compare { field, op, operand: self.operand()? })
            }
            Tok::In => {
                self.bump()?;
                let open = self.offset;
                self.expect(Tok::LBracket, "[ after in")?;
                let mut list = Vec::new();
                while self.tok != Tok::RBracket {
                    list.push(self.operand()?);
                    if list.len() > MAX_LIST_ELEMENTS {
                        return Err(ParseError { kind: ParseErrorKind::Limit(Limit::ListElements), offset: open });
                    }
                    if self.tok == Tok::Comma {
                        self.bump()?;
                    } else {
                        break;
                    }
                }
                self.expect(Tok::RBracket, "] or , in a list")?;
                Ok(Condition::In { field, list })
            }
            _ => Ok(Condition::Field(field)),
        }
    }

    fn field(&mut self) -> Result<Field, ParseError> {
        match self.tok {
            Tok::Ident(_) | Tok::Escaped(_) => {}
            _ => return Err(syntax(self.offset, "expected a field")),
        }
        let (field, under) = self.field_or_under()?;
        if under {
            return Err(syntax(self.offset, "unexpected under()"));
        }
        Ok(field)
    }

    /// A field, stopping before `.under(` (and reporting it) when it follows.
    fn field_or_under(&mut self) -> Result<(Field, bool), ParseError> {
        let (path, under) = self.segments(true)?;
        if under {
            return Ok((Field::new(path), true));
        }
        let mut field = Field::new(path);
        if self.tok == Tok::LBracket {
            self.bump()?;
            let Tok::Str(key) = self.bump()? else { return Err(syntax(self.offset, "a map index is a string literal")) };
            self.expect(Tok::RBracket, "]")?;
            field.key = Some(key);
            if self.tok == Tok::Dot {
                self.bump()?;
                if matches!(&self.tok, Tok::Ident(name) if name == "under") && *self.peek()? == Tok::LParen {
                    self.bump()?;
                    return Ok((field, true));
                }
                return Err(syntax(self.offset, "a map index ends the field"));
            }
        }
        Ok((field, false))
    }

    fn path(&mut self) -> Result<Path, ParseError> {
        let (path, under) = self.segments(false)?;
        debug_assert!(!under);
        Ok(path)
    }

    /// Segments separated by `.`. With `allow_under`, stops at `.under(` and
    /// leaves `(` as the current token.
    fn segments(&mut self, allow_under: bool) -> Result<(Path, bool), ParseError> {
        let start = self.offset;
        let mut segments = Vec::new();
        match self.bump()? {
            Tok::Ident(name) if RESERVED.contains(&name.as_str()) => {
                return Err(syntax(start, format!("{name} is a reserved word; write it as `{name}`")));
            }
            Tok::Ident(name) | Tok::Escaped(name) => segments.push(name),
            _ => return Err(syntax(start, "expected a field")),
        }
        while self.tok == Tok::Dot {
            self.bump()?;
            match self.tok.clone() {
                Tok::Ident(name) if allow_under && name == "under" && *self.peek()? == Tok::LParen => {
                    self.bump()?;
                    return Ok((self.make_path(segments, start)?, true));
                }
                Tok::Ident(name) | Tok::Escaped(name) => {
                    self.bump()?;
                    segments.push(name);
                }
                Tok::True | Tok::False | Tok::Null | Tok::In => {
                    return Err(syntax(self.offset, "a keyword is not a field name; escape it with backticks"));
                }
                _ => return Err(syntax(self.offset, "expected a field name after .")),
            }
        }
        Ok((self.make_path(segments, start)?, false))
    }

    fn make_path(&self, segments: Vec<String>, start: usize) -> Result<Path, ParseError> {
        if segments.len() > MAX_SEGMENTS {
            return Err(ParseError { kind: ParseErrorKind::Limit(Limit::Segments), offset: start });
        }
        Path::new(segments).map_err(|e| syntax(start, e.0))
    }

    fn operand(&mut self) -> Result<Operand, ParseError> {
        let start = self.offset;
        let literal = match self.tok.clone() {
            Tok::Str(s) => {
                self.bump()?;
                Literal::String(s)
            }
            Tok::True | Tok::False => Literal::Bool(self.bump()? == Tok::True),
            Tok::Int(_) | Tok::Float(_) | Tok::Minus => self.number()?,
            Tok::Ident(name) if (name == "timestamp" || name == "duration") && *self.peek()? == Tok::LParen => {
                self.bump()?;
                self.bump()?;
                let Tok::Str(text) = self.bump()? else { return Err(syntax(self.offset, format!("{name}() takes a string literal"))) };
                self.expect(Tok::RParen, ")")?;
                if name == "timestamp" {
                    Literal::Timestamp(Timestamp::parse_rfc3339(&text).map_err(|e| literal(start, e.0))?)
                } else {
                    Literal::Duration(Duration::parse(&text).map_err(|e| literal(start, e.0))?)
                }
            }
            Tok::Ident(name) => {
                if !is_ident(&name) {
                    return Err(syntax(start, format!("{name} is a reserved word")));
                }
                if *self.peek()? == Tok::LParen {
                    return Err(syntax(start, format!("{name}() is not a function in the subset")));
                }
                let path = self.path()?;
                return Ok(Operand::Variable(Variable::new(path).map_err(|e| syntax(start, e.0))?));
            }
            Tok::Null => return Err(syntax(start, "null is not in the subset; test presence with has()")),
            Tok::Escaped(_) => return Err(syntax(start, "a field cannot be on the right; field-to-field comparison is not in the subset")),
            _ => return Err(syntax(start, "expected a literal or a bound variable")),
        };
        Ok(Operand::Literal(literal))
    }

    fn number(&mut self) -> Result<Literal, ParseError> {
        let start = self.offset;
        let negative = self.tok == Tok::Minus;
        if negative {
            self.bump()?;
        }
        match self.bump()? {
            Tok::Int(magnitude) => {
                let value = if negative { 0i128 - i128::from(magnitude) } else { i128::from(magnitude) };
                i64::try_from(value).map(Literal::Int).map_err(|_| literal(start, "integer is out of range"))
            }
            Tok::Float(value) => Ok(Literal::Float(if negative { -value } else { value })),
            _ => Err(syntax(start, "unary minus applies only to a number literal")),
        }
    }
}

// ---------------------------------------------------------------- printer

/// Writes `s` double-quoted, escaped exactly as `serde_json` prints it.
pub(crate) fn write_string(out: &mut impl fmt::Write, s: &str) -> fmt::Result {
    out.write_char('"')?;
    for c in s.chars() {
        match c {
            '"' => out.write_str("\\\"")?,
            '\\' => out.write_str("\\\\")?,
            '\x08' => out.write_str("\\b")?,
            '\x0c' => out.write_str("\\f")?,
            '\n' => out.write_str("\\n")?,
            '\r' => out.write_str("\\r")?,
            '\t' => out.write_str("\\t")?,
            c if (c as u32) < 0x20 => write!(out, "\\u{:04x}", c as u32)?,
            c => out.write_char(c)?,
        }
    }
    out.write_char('"')
}

fn write_segment(f: &mut fmt::Formatter<'_>, segment: &str) -> fmt::Result {
    if is_ident(segment) { f.write_str(segment) } else { write!(f, "`{segment}`") }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, segment) in self.segments().iter().enumerate() {
            if i > 0 {
                f.write_char('.')?;
            }
            write_segment(f, segment)?;
        }
        Ok(())
    }
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path)?;
        if let Some(key) = &self.key {
            f.write_char('[')?;
            write_string(f, key)?;
            f.write_char(']')?;
        }
        Ok(())
    }
}

impl fmt::Display for Variable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path())
    }
}

impl fmt::Display for Literal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Literal::String(s) => write_string(f, s),
            Literal::Int(n) => write!(f, "{n}"),
            Literal::Float(x) if *x == 0.0 => f.write_str("0.0"),
            Literal::Float(x) => write!(f, "{x:?}"),
            Literal::Bool(b) => write!(f, "{b}"),
            Literal::Timestamp(t) => write!(f, "timestamp(\"{t}\")"),
            Literal::Duration(d) => write!(f, "duration(\"{d}\")"),
        }
    }
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operand::Literal(literal) => write!(f, "{literal}"),
            Operand::Variable(variable) => write!(f, "{variable}"),
        }
    }
}

impl fmt::Display for Relop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.symbol())
    }
}

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Condition::And(terms) => {
                for (i, term) in terms.iter().enumerate() {
                    if i > 0 {
                        f.write_str(" && ")?;
                    }
                    if matches!(term, Condition::Or(_)) { write!(f, "({term})")? } else { write!(f, "{term}")? }
                }
                Ok(())
            }
            Condition::Or(terms) => {
                for (i, term) in terms.iter().enumerate() {
                    if i > 0 {
                        f.write_str(" || ")?;
                    }
                    write!(f, "{term}")?;
                }
                Ok(())
            }
            Condition::Not(inner) => match **inner {
                Condition::Field(_) | Condition::Has(_) | Condition::Under { .. } => write!(f, "!{inner}"),
                _ => write!(f, "!({inner})"),
            },
            Condition::Has(path) => write!(f, "has({path})"),
            Condition::Compare { field, op, operand } => write!(f, "{field} {op} {operand}"),
            Condition::In { field, list } => {
                write!(f, "{field} in [")?;
                for (i, operand) in list.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{operand}")?;
                }
                f.write_char(']')
            }
            Condition::Member { key, field } => {
                write_string(f, key)?;
                write!(f, " in {field}")
            }
            Condition::Under { field, prefix } => write!(f, "{field}.under({prefix})"),
            Condition::Field(field) => write!(f, "{field}"),
            Condition::Bool(b) => write!(f, "{b}"),
        }
    }
}
