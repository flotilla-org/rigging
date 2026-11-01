//! Regenerates the `cel_spec` cases of `corpus/corpus.json` from a cel-spec
//! checkout:
//!
//! ```text
//! git clone https://github.com/google/cel-spec && git -C cel-spec checkout 21ec6f4e52e8d694687ff9ed7408d3eccbb955d7
//! cargo run -p rigging-condition --example cel_spec_slice -- cel-spec
//! ```
//!
//! It reads `tests/simple/testdata/{logic,comparisons,fields,lists,timestamps}.textproto`
//! and keeps the tests with a boolean or error result whose expression is
//! inside the subset once some of its parts become fields, an error result
//! read as U (§3). The parts that become fields:
//!
//! - a literal on the left of a comparison or `in`, as a field holding it
//!   (`1 < 2` becomes `lhs0 < 2` with `lhs0 = 1`);
//! - a binding, as a field, and a bound map's entries as fields under it;
//! - a map literal with string keys that is selected from, as a field per
//!   entry (`has({'a': 1}.a)` becomes `has(lhs0.a)` with `lhs0.a = 1`); a
//!   key it lacks is an absent field;
//! - a part below the top that the `cel` crate fails to evaluate, as an
//!   absent field of the type its place needs (`1/0 != 0 && true` becomes
//!   `lhs0 != 0 && true` with `lhs0` absent), since an error is U.
//!
//! A test that does not then check against the schema this builds is outside
//! the subset and left out.

use std::{
    collections::{BTreeMap, HashMap},
    env, fs,
    path::PathBuf,
    sync::Arc,
};

use cel::{
    Context, ExecutionError, IdedExpr, Value as Cel,
    common::ast::{EntryExpr, Expr, LiteralValue},
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
    let expect = match test.message("value").and_then(|v| v.scalar("bool_value")) {
        Some("true") => "T",
        Some("false") => "F",
        Some(_) => return None,
        None if test.message("eval_error").is_some() => "U",
        None => return None,
    };
    let mut lift = Lift::default();
    for binding in test.messages("bindings") {
        let key = binding.string("key")?;
        let value = binding.message("value")?.message("value")?;
        match value.message("map_value") {
            Some(map) => {
                let mut entries = BTreeMap::new();
                let mut value_type = None;
                for entry in map.messages("entries") {
                    let key = entry.message("key")?.string("string_value")?;
                    let value = entry.message("value")?;
                    let (ty, literal) = scalar(value)?;
                    value_type = Some(ty.clone());
                    entries.insert(key.clone(), cel_value(&literal)?);
                    lift.declare(Path::new([binding.string("key")?, key]).ok()?, ty, Some(literal));
                }
                lift.context.add_variable_from_value(key.clone(), Cel::Map(entries.into_iter().collect::<HashMap<_, _>>().into()));
                lift.maps.insert(key, value_type);
            }
            None => {
                let (ty, literal) = scalar(value)?;
                lift.context.add_variable_from_value(key.clone(), cel_value(&literal)?);
                lift.declare(Path::new([key]).ok()?, ty, Some(literal));
            }
        }
    }
    let parsed = Parser::new().enable_ident_escape_syntax(true).parse(&expr).ok()?;
    let condition = lift.condition(&parsed, true)?;
    let mut schema = Schema::new();
    let mut fields = serde_json::Map::new();
    let mut values = serde_json::Map::new();
    for (path, (ty, literal)) in &lift.fields {
        schema.insert_field(path.clone(), ty.clone(), true).ok()?;
        fields.insert(path.to_string(), json!({ "type": ty.to_string() }));
        if let Some(literal) = literal {
            values.insert(path.to_string(), literal_json(literal)?);
        }
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

fn scalar(value: &TextProto) -> Option<(Type, Literal)> {
    Some(if let Some(n) = value.scalar("int64_value") {
        (Type::Int, Literal::Int(n.parse().ok()?))
    } else if let Some(x) = value.scalar("double_value") {
        (Type::Number, Literal::Float(x.parse().ok()?))
    } else if let Some(s) = value.string("string_value") {
        (Type::String, Literal::String(s))
    } else {
        (Type::Bool, Literal::Bool(value.scalar("bool_value")? == "true"))
    })
}

fn cel_value(literal: &Literal) -> Option<Cel> {
    Some(match literal {
        Literal::Int(n) => Cel::Int(*n),
        Literal::Float(x) => Cel::Float(*x),
        Literal::String(s) => Cel::String(Arc::new(s.clone())),
        Literal::Bool(b) => Cel::Bool(*b),
        _ => return None,
    })
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

fn literal_type(literal: &Literal) -> Option<Type> {
    Some(match literal {
        Literal::String(_) => Type::String,
        Literal::Int(_) => Type::Int,
        Literal::Float(_) => Type::Number,
        Literal::Bool(_) => Type::Bool,
        Literal::Timestamp(_) => Type::Timestamp,
        Literal::Duration(_) => Type::Duration,
        _ => return None,
    })
}

#[derive(Default)]
struct Lift {
    /// Each field, and its value when it is present.
    fields: BTreeMap<Path, (Type, Option<Literal>)>,
    /// The bound or lifted maps, whose entries are fields, and the type of
    /// their values when they have any.
    maps: BTreeMap<String, Option<Type>>,
    /// The bindings, for evaluating a part with the `cel` crate.
    context: Context<'static, 'static>,
    next: usize,
    lifted: bool,
}

impl Lift {
    fn declare(&mut self, path: Path, ty: Type, literal: Option<Literal>) {
        self.fields.insert(path, (ty, literal));
    }

    fn fresh(&mut self) -> String {
        self.lifted = true;
        self.next += 1;
        format!("lhs{}", self.next - 1)
    }

    /// `e` in a boolean place; `top` when it is the whole expression.
    fn condition(&mut self, e: &IdedExpr, top: bool) -> Option<Condition> {
        match &e.expr {
            Expr::Literal(LiteralValue::Boolean(b)) => Some(Condition::Bool(*b.inner())),
            Expr::Ident(_) | Expr::Select(_) if !matches!(&e.expr, Expr::Select(select) if select.test) => {
                let field = self.field(e, Type::Bool)?;
                matches!(self.fields.get(&field.path), Some((Type::Bool, _))).then_some(Condition::Field(field))
            }
            Expr::Select(select) if select.test => {
                let root = self.map(&select.operand)?;
                let ty = self.maps[&root].clone().unwrap_or(Type::Bool);
                let path = Path::new([root, select.field.clone()]).ok()?;
                self.fields.entry(path.clone()).or_insert((ty, None));
                Some(Condition::Has(path))
            }
            Expr::Call(call) if call.target.is_none() => {
                let args = &call.args;
                match (call.func_name.as_str(), args.len()) {
                    ("_&&_", 2) => Some(Condition::and([self.condition(&args[0], false)?, self.condition(&args[1], false)?])),
                    ("_||_", 2) => Some(Condition::or([self.condition(&args[0], false)?, self.condition(&args[1], false)?])),
                    ("!_", 1) => Some(Condition::Not(Box::new(self.condition(&args[0], false)?))),
                    ("@in", 2) => {
                        let Expr::List(list) = &args[1].expr else { return None };
                        let list = list.elements.iter().map(|e| literal(e).map(Operand::Literal)).collect::<Option<Vec<_>>>()?;
                        let ty = match list.first() {
                            Some(Operand::Literal(first)) => literal_type(first)?,
                            _ => return None,
                        };
                        Some(Condition::In { field: self.left(&args[0], ty)?, list })
                    }
                    (op, 2) if relop(op).is_some() => {
                        let literal = literal(&args[1])?;
                        let field = self.left(&args[0], literal_type(&literal)?)?;
                        Some(Condition::Compare { field, op: relop(op)?, operand: Operand::Literal(literal) })
                    }
                    _ if !top => self.failing(e, Type::Bool).map(Condition::Field),
                    _ => None,
                }
            }
            _ if !top => self.failing(e, Type::Bool).map(Condition::Field),
            _ => None,
        }
    }

    /// The path a name or a select from a map spells, if it names a field.
    fn path(&mut self, e: &IdedExpr) -> Option<Path> {
        match &e.expr {
            Expr::Ident(name) if !self.maps.contains_key(name) => {
                let path = Path::new([name.clone()]).ok()?;
                self.fields.contains_key(&path).then_some(path)
            }
            Expr::Select(select) if !select.test => {
                let root = self.map(&select.operand)?;
                Path::new([root, select.field.clone()]).ok()
            }
            _ => None,
        }
    }

    /// A bound map's name, or a map literal with string keys lifted into fields.
    fn map(&mut self, e: &IdedExpr) -> Option<String> {
        match &e.expr {
            Expr::Ident(name) if self.maps.contains_key(name) => Some(name.clone()),
            Expr::Map(map) => {
                let mut entries = Vec::new();
                for entry in &map.entries {
                    let EntryExpr::MapEntry(entry) = &entry.expr else { return None };
                    let Some(Literal::String(key)) = literal(&entry.key) else { return None };
                    let value = literal(&entry.value)?;
                    Path::new([key.as_str()]).ok()?;
                    entries.push((key, literal_type(&value)?, value));
                }
                let root = self.fresh();
                let value_type = entries.first().map(|(_, ty, _)| ty.clone());
                for (key, ty, value) in entries {
                    self.declare(Path::new([root.clone(), key]).ok()?, ty, Some(value));
                }
                self.maps.insert(root.clone(), value_type);
                Some(root)
            }
            _ => None,
        }
    }

    /// The field a name or select reads; a map's missing key is an absent
    /// field of the map's value type, or `ty` for a map with no values.
    fn field(&mut self, e: &IdedExpr, ty: Type) -> Option<Field> {
        let path = self.path(e)?;
        let ty = self.maps.get(&path.segments()[0]).cloned().flatten().unwrap_or(ty);
        self.fields.entry(path.clone()).or_insert((ty, None));
        Some(Field::new(path))
    }

    /// The left of a comparison of type `ty`: a field, a literal lifted into
    /// one, or a part that fails to evaluate.
    fn left(&mut self, e: &IdedExpr, ty: Type) -> Option<Field> {
        if matches!(&e.expr, Expr::Ident(_) | Expr::Select(_)) {
            return self.field(e, ty);
        }
        if let Some(literal) = literal(e) {
            let path = Path::new([self.fresh()]).ok()?;
            self.declare(path.clone(), literal_type(&literal)?, Some(literal));
            return Some(Field::new(path));
        }
        self.failing(e, ty)
    }

    /// An absent field of type `ty` standing for `e`, when evaluating `e`
    /// fails with one of CEL's errors on plain values: division by zero, or
    /// a missing or ill-typed key or index. Other failures of the `cel` crate
    /// can be what it lacks (protobuf messages, nanoseconds), not CEL errors.
    fn failing(&mut self, e: &IdedExpr, ty: Type) -> Option<Field> {
        use ExecutionError::*;
        let cel_error = matches!(
            self.context.resolve(e),
            Err(DivisionByZero(_) | RemainderByZero(_) | NoSuchKey(_) | IndexOutOfBounds(_) | UnsupportedIndex(..))
        );
        cel_error.then_some(())?;
        let path = Path::new([self.fresh()]).ok()?;
        self.declare(path.clone(), ty, None);
        Some(Field::new(path))
    }
}

fn relop(op: &str) -> Option<Relop> {
    Some(match op {
        "_==_" => Relop::Eq,
        "_!=_" => Relop::Ne,
        "_<_" => Relop::Lt,
        "_<=_" => Relop::Le,
        "_>_" => Relop::Gt,
        "_>=_" => Relop::Ge,
        _ => return None,
    })
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
