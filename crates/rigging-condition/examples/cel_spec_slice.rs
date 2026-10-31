//! Regenerates the `cel_spec` cases of `corpus/corpus.json` from a cel-spec
//! checkout:
//!
//! ```text
//! git clone https://github.com/google/cel-spec && git -C cel-spec checkout 21ec6f4e52e8d694687ff9ed7408d3eccbb955d7
//! cargo run -p rigging-condition --example cel_spec_slice -- cel-spec
//! ```
//!
//! It reads `tests/simple/testdata/{logic,comparisons,fields,lists,timestamps}.textproto`
//! and keeps the tests with a boolean result whose expression is inside the
//! subset once each literal on the left of a comparison or `in` becomes a
//! field holding that literal (`1 < 2` becomes `lhs0 < 2` with `lhs0 = 1`),
//! and each binding becomes a field. A test that does not check against the
//! schema this builds is outside the subset and left out.

use std::{collections::BTreeMap, env, fs, path::PathBuf};

use cel::{
    IdedExpr,
    common::ast::{Expr, LiteralValue},
    parser::Parser,
};
use rigging_condition::{Checked, Condition, Duration, Field, Literal, Operand, Path, Relop, Schema, Timestamp, Type};
use serde_json::{Value as Json, json};

const FILES: &[&str] = &["logic", "comparisons", "fields", "lists", "timestamps"];

fn main() {
    let spec = PathBuf::from(env::args().nth(1).expect("usage: cel_spec_slice <cel-spec checkout>"));
    let mut cases = Vec::new();
    for file in FILES {
        let text = fs::read_to_string(spec.join(format!("tests/simple/testdata/{file}.textproto"))).unwrap();
        let root = TextProto::parse(&text);
        for section in root.messages("section") {
            for test in section.messages("test") {
                let name = format!("cel-spec/{file}/{}/{}", section.string("name").unwrap(), test.string("name").unwrap());
                if let Some(case) = convert(&name, test) {
                    cases.push(case);
                }
            }
        }
    }
    let corpus_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus/corpus.json");
    let corpus = fs::read_to_string(&corpus_path).unwrap();
    let start = corpus.find("  \"cel_spec\": [\n").expect("corpus.json has a cel_spec array") + "  \"cel_spec\": [\n".len();
    let end = start - 1 + corpus[start - 1..].find("\n  ]").unwrap();
    let lines: Vec<String> = cases.iter().map(|case| format!("    {case}")).collect();
    let mut out = String::from(&corpus[..start]);
    out.push_str(&lines.join(",\n"));
    out.push_str(&corpus[end..]);
    fs::write(&corpus_path, out).unwrap();
    eprintln!("wrote {} cel-spec cases", cases.len());
}

/// One test, lifted into the subset, or `None` when it is outside it.
fn convert(name: &str, test: &TextProto) -> Option<Json> {
    let expr = test.string("expr")?;
    let expect = match test.message("value")?.scalar("bool_value")? {
        "true" => "T",
        "false" => "F",
        _ => return None,
    };
    let mut lift = Lift::default();
    for binding in test.messages("bindings") {
        let key = binding.string("key")?;
        let value = binding.message("value")?.message("value")?;
        let (ty, literal) = if let Some(n) = value.scalar("int64_value") {
            (Type::Int, Literal::Int(n.parse().ok()?))
        } else if let Some(x) = value.scalar("double_value") {
            (Type::Number, Literal::Float(x.parse().ok()?))
        } else if let Some(s) = value.string("string_value") {
            (Type::String, Literal::String(s))
        } else {
            (Type::Bool, Literal::Bool(value.scalar("bool_value")? == "true"))
        };
        lift.fields.insert(key, (ty, literal));
    }
    let parsed = Parser::new().parse(&expr).ok()?;
    let condition = lift.condition(&parsed)?;
    let mut schema = Schema::new();
    let mut fields = serde_json::Map::new();
    let mut values = serde_json::Map::new();
    for (key, (ty, literal)) in &lift.fields {
        let path = Path::new([key.clone()]).ok()?;
        schema.insert_field(path.clone(), ty.clone(), true).ok()?;
        fields.insert(path.to_string(), json!({ "type": ty.to_string() }));
        values.insert(path.to_string(), literal_json(literal)?);
    }
    let checked = Checked::new(condition, &schema).ok()?;
    let canonical = checked.to_string();
    // A test that needed no lifting keeps its own spelling, as a lenient case.
    let mut case = json!({ "name": name, "schema": { "fields": fields }, "input": canonical });
    if !lift.lifted && Condition::parse_lenient(&expr).ok().as_ref() == Some(&*checked) && expr != canonical {
        case["input"] = json!(expr);
        case["lenient"] = json!(true);
        case["canonical"] = json!(canonical);
    }
    case["rows"] = json!([{ "values": values, "expect": expect }]);
    case["sql"] = json!({});
    Some(case)
}

fn literal_json(literal: &Literal) -> Option<Json> {
    Some(match literal {
        Literal::String(s) => json!(s),
        Literal::Int(n) => json!(n),
        Literal::Float(x) => json!(x),
        Literal::Bool(b) => json!(b),
        Literal::Timestamp(t) => json!(t.to_string()),
        Literal::Duration(d) => json!(d.to_string()),
        _ => return None,
    })
}

#[derive(Default)]
struct Lift {
    fields: BTreeMap<String, (Type, Literal)>,
    lifted: bool,
}

impl Lift {
    fn condition(&mut self, e: &IdedExpr) -> Option<Condition> {
        match &e.expr {
            Expr::Literal(LiteralValue::Boolean(b)) => Some(Condition::Bool(*b.inner())),
            Expr::Ident(name) if matches!(self.fields.get(name), Some((Type::Bool, _))) => Some(Condition::Field(self.field(name)?)),
            Expr::Call(call) if call.target.is_none() => {
                let args = &call.args;
                match (call.func_name.as_str(), args.len()) {
                    ("_&&_", 2) => Some(Condition::and([self.condition(&args[0])?, self.condition(&args[1])?])),
                    ("_||_", 2) => Some(Condition::or([self.condition(&args[0])?, self.condition(&args[1])?])),
                    ("!_", 1) => Some(Condition::Not(Box::new(self.condition(&args[0])?))),
                    ("@in", 2) => {
                        let Expr::List(list) = &args[1].expr else { return None };
                        let list = list.elements.iter().map(|e| literal(e).map(Operand::Literal)).collect::<Option<Vec<_>>>()?;
                        Some(Condition::In { field: self.left(&args[0])?, list })
                    }
                    (op, 2) => {
                        let op = match op {
                            "_==_" => Relop::Eq,
                            "_!=_" => Relop::Ne,
                            "_<_" => Relop::Lt,
                            "_<=_" => Relop::Le,
                            "_>_" => Relop::Gt,
                            "_>=_" => Relop::Ge,
                            _ => return None,
                        };
                        let operand = Operand::Literal(literal(&args[1])?);
                        Some(Condition::Compare { field: self.left(&args[0])?, op, operand })
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn field(&self, name: &str) -> Option<Field> {
        Some(Field::new(Path::new([name]).ok()?))
    }

    /// The left of a comparison: a bound name, or a literal lifted into a field.
    fn left(&mut self, e: &IdedExpr) -> Option<Field> {
        if let Expr::Ident(name) = &e.expr {
            self.fields.contains_key(name).then_some(())?;
            return self.field(name);
        }
        let literal = literal(e)?;
        let ty = match &literal {
            Literal::String(_) => Type::String,
            Literal::Int(_) => Type::Int,
            Literal::Float(_) => Type::Number,
            Literal::Bool(_) => Type::Bool,
            Literal::Timestamp(_) => Type::Timestamp,
            Literal::Duration(_) => Type::Duration,
            _ => return None,
        };
        let name = format!("lhs{}", self.fields.len());
        self.fields.insert(name.clone(), (ty, literal));
        self.lifted = true;
        self.field(&name)
    }
}

fn literal(e: &IdedExpr) -> Option<Literal> {
    match &e.expr {
        Expr::Literal(LiteralValue::Int(n)) => Some(Literal::Int(*n.inner())),
        Expr::Literal(LiteralValue::Double(x)) if x.inner().is_finite() => Some(Literal::Float(*x.inner())),
        Expr::Literal(LiteralValue::String(s)) => Some(Literal::String(s.inner().to_owned())),
        Expr::Literal(LiteralValue::Boolean(b)) => Some(Literal::Bool(*b.inner())),
        Expr::Call(call) if call.target.is_none() && call.args.len() == 1 => match (call.func_name.as_str(), literal(&call.args[0])?) {
            ("-_", Literal::Int(n)) => n.checked_neg().map(Literal::Int),
            ("-_", Literal::Float(x)) => Some(Literal::Float(-x)),
            ("timestamp", Literal::String(s)) => Timestamp::parse_rfc3339(&s).ok().map(Literal::Timestamp),
            ("duration", Literal::String(s)) => Duration::parse(&s).ok().map(Literal::Duration),
            _ => None,
        },
        _ => None,
    }
}

/// Just enough of the protobuf text format for cel-spec's simple tests:
/// fields are `name: scalar`, `name { … }` or `name: { … }`, strings may be
/// split into adjacent quoted parts, and `#` starts a comment.
#[derive(Default)]
struct TextProto {
    fields: Vec<(String, Entry)>,
}

enum Entry {
    Scalar(String),
    Str(String),
    Message(TextProto),
}

impl TextProto {
    fn parse(text: &str) -> TextProto {
        let tokens = tokenize(text);
        let mut at = 0;
        let message = Self::message_body(&tokens, &mut at);
        assert_eq!(at, tokens.len(), "trailing textproto");
        message
    }

    fn message_body(tokens: &[Token], at: &mut usize) -> TextProto {
        let mut out = TextProto::default();
        loop {
            // An extension or Any field is named in brackets: `[type.googleapis.com/…]`.
            let name = match tokens.get(*at) {
                Some(Token::Word(name)) => name.clone(),
                Some(Token::Punct('[')) => match &tokens[*at + 1] {
                    Token::Word(name) => {
                        *at += 2;
                        name.clone()
                    }
                    other => panic!("unexpected {other:?} in a bracketed name"),
                },
                _ => break,
            };
            *at += 1;
            if tokens.get(*at) == Some(&Token::Punct(':')) {
                *at += 1;
            }
            let entry = match &tokens[*at] {
                Token::Punct('{' | '<') => {
                    *at += 1;
                    let inner = Self::message_body(tokens, at);
                    assert!(matches!(tokens[*at], Token::Punct('}' | '>')), "unclosed message {name}");
                    *at += 1;
                    Entry::Message(inner)
                }
                Token::Str(_) => {
                    let mut s = String::new();
                    while let Some(Token::Str(part)) = tokens.get(*at) {
                        s.push_str(part);
                        *at += 1;
                    }
                    Entry::Str(s)
                }
                Token::Word(word) => {
                    *at += 1;
                    Entry::Scalar(word.clone())
                }
                other => panic!("unexpected {other:?} after {name}"),
            };
            out.fields.push((name, entry));
        }
        out
    }

    fn messages<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a TextProto> {
        self.fields.iter().filter(move |(n, _)| n == name).filter_map(|(_, e)| match e {
            Entry::Message(m) => Some(m),
            _ => None,
        })
    }

    fn message<'a>(&'a self, name: &'a str) -> Option<&'a TextProto> {
        self.messages(name).next()
    }

    fn string(&self, name: &str) -> Option<String> {
        self.fields.iter().find_map(|(n, e)| match e {
            Entry::Str(s) if n == name => Some(s.clone()),
            _ => None,
        })
    }

    fn scalar(&self, name: &str) -> Option<&str> {
        self.fields.iter().find_map(|(n, e)| match e {
            Entry::Scalar(s) if n == name => Some(s.as_str()),
            _ => None,
        })
    }
}

#[derive(Debug, PartialEq)]
enum Token {
    Word(String),
    Str(String),
    Punct(char),
}

fn tokenize(text: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            '#' => while chars.next_if(|&c| c != '\n').is_some() {},
            c if c.is_whitespace() => {
                chars.next();
            }
            ':' | '{' | '}' | '<' | '>' | '[' | ']' | ',' | ';' => {
                chars.next();
                tokens.push(Token::Punct(c));
            }
            '"' | '\'' => {
                chars.next();
                let mut bytes = Vec::new();
                loop {
                    match chars.next().expect("unterminated textproto string") {
                        '\\' => escape(&mut chars, &mut bytes),
                        end if end == c => break,
                        other => bytes.extend_from_slice(other.encode_utf8(&mut [0; 4]).as_bytes()),
                    }
                }
                tokens.push(Token::Str(String::from_utf8(bytes).expect("textproto string is UTF-8")));
            }
            _ => {
                let mut word = String::new();
                while let Some(c) = chars.next_if(|c| !c.is_whitespace() && !":{}<>[],;#\"'".contains(*c)) {
                    word.push(c);
                }
                tokens.push(Token::Word(word));
            }
        }
    }
    tokens
}

/// One C-style escape after a backslash; `\NNN` and `\xNN` are bytes.
fn escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>, bytes: &mut Vec<u8>) {
    let c = chars.next().expect("truncated escape");
    let mut digits = |radix: u32, max: usize| {
        let mut n = 0u32;
        for _ in 0..max {
            match chars.peek().and_then(|d| d.to_digit(radix)) {
                Some(d) => {
                    n = n * radix + d;
                    chars.next();
                }
                None => break,
            }
        }
        n
    };
    match c {
        'n' => bytes.push(b'\n'),
        'r' => bytes.push(b'\r'),
        't' => bytes.push(b'\t'),
        'a' => bytes.push(7),
        'b' => bytes.push(8),
        'f' => bytes.push(12),
        'v' => bytes.push(11),
        '0'..='7' => {
            let mut n = c.to_digit(8).unwrap();
            for _ in 0..2 {
                match chars.peek().and_then(|d| d.to_digit(8)) {
                    Some(d) => {
                        n = n * 8 + d;
                        chars.next();
                    }
                    None => break,
                }
            }
            bytes.push(n as u8)
        }
        'x' => bytes.push(digits(16, 2) as u8),
        'u' => bytes.extend_from_slice(char::from_u32(digits(16, 4)).unwrap().encode_utf8(&mut [0; 4]).as_bytes()),
        'U' => bytes.extend_from_slice(char::from_u32(digits(16, 8)).unwrap().encode_utf8(&mut [0; 4]).as_bytes()),
        other => bytes.extend_from_slice(other.encode_utf8(&mut [0; 4]).as_bytes()),
    }
}
