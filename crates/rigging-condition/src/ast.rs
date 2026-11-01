//! The condition AST (§4.2 of the design note). `Display` prints canonical text.

pub use crate::time::{Duration, Timestamp};

/// CEL keywords: never a bare segment.
pub(crate) const KEYWORDS: &[&str] = &["false", "in", "null", "true"];
/// CEL reserved words: never an identifier, and backticked as a segment.
pub(crate) const RESERVED: &[&str] = &[
    "as",
    "break",
    "const",
    "continue",
    "else",
    "for",
    "function",
    "if",
    "import",
    "let",
    "loop",
    "package",
    "namespace",
    "return",
    "var",
    "void",
    "while",
];

/// At most this many segments in a field or variable (CEL's minimum for `.` in a row).
pub const MAX_SEGMENTS: usize = 12;

/// A condition: a boolean expression over the named, typed fields of one row.
///
/// `And` and `Or` are n-ary with at least two operands, and never directly
/// contain another node of the same kind: parsing `a && (b && c)` gives
/// `And[a, b, c]`. A tree built by hand must keep that shape to print and
/// parse back to itself.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Condition {
    And(Vec<Condition>),
    Or(Vec<Condition>),
    Not(Box<Condition>),
    /// `has(path)`: the field is present.
    Has(Path),
    /// `field op operand`.
    Compare {
        field: Field,
        op: Relop,
        operand: Operand,
    },
    /// `field in [operand, …]`.
    In {
        field: Field,
        list: Vec<Operand>,
    },
    /// `"key" in field`: a key of a map, or a member of a list.
    Member {
        key: String,
        field: Field,
    },
    /// `field.under(prefix)` (§4.6).
    Under {
        field: Field,
        prefix: Operand,
    },
    /// A bare `bool` field.
    Field(Field),
    Bool(bool),
}

/// A field reference: a declared path, and an index when the path is a map.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Field {
    pub path: Path,
    pub key: Option<String>,
}

/// A dotted name: one to twelve segments, each a CEL selector or an escaped
/// identifier (letters, digits and `_ . - / space`). A path names one field;
/// it is not a walk through nested maps.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Path(Vec<String>);

/// A bound variable on the right of a comparison (`row.convoy`, `revision`):
/// a path whose first segment is a CEL identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Variable(Path);

#[derive(Clone, Debug, PartialEq)]
pub enum Operand {
    Literal(Literal),
    Variable(Variable),
}

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Literal {
    String(String),
    Int(i64),
    /// Finite; `-0.0` prints as `0.0` and compares equal to it.
    Float(f64),
    Bool(bool),
    Timestamp(Timestamp),
    Duration(Duration),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Relop {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// Why a path or variable could not be built.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct NameError(pub(crate) String);

pub(crate) fn is_selector(segment: &str) -> bool {
    let mut chars = segment.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic()) && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

pub(crate) fn is_escaped_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '/' | ' ')
}

/// A CEL `IDENT`: a selector that is neither a keyword nor a reserved word.
pub(crate) fn is_ident(segment: &str) -> bool {
    is_selector(segment) && !KEYWORDS.contains(&segment) && !RESERVED.contains(&segment)
}

impl Path {
    pub fn new<I, S>(segments: I) -> Result<Self, NameError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let segments: Vec<String> = segments.into_iter().map(Into::into).collect();
        if segments.is_empty() {
            return Err(NameError("a path needs at least one segment".into()));
        }
        if segments.len() > MAX_SEGMENTS {
            return Err(NameError(format!("a path has at most {MAX_SEGMENTS} segments")));
        }
        if let Some(bad) = segments.iter().find(|s| s.is_empty() || !s.chars().all(is_escaped_char)) {
            return Err(NameError(format!("segment {bad:?} is empty or has a character outside letters, digits and _ . - / space")));
        }
        Ok(Path(segments))
    }

    pub fn segments(&self) -> &[String] {
        &self.0
    }

    /// Whether `self` is `other` or a proper prefix of it.
    pub fn is_prefix_of(&self, other: &Path) -> bool {
        other.0.starts_with(&self.0)
    }
}

/// Parses canonical path text, such as `` `latest-claim`.disposition ``.
impl std::str::FromStr for Path {
    type Err = crate::syntax::ParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        crate::syntax::parse_path(text)
    }
}

impl Variable {
    pub fn new(path: Path) -> Result<Self, NameError> {
        if !is_ident(&path.0[0]) {
            return Err(NameError(format!("variable {:?} must start with a CEL identifier", path.0[0])));
        }
        Ok(Variable(path))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Field {
    pub fn new(path: Path) -> Self {
        Field { path, key: None }
    }

    pub fn indexed(path: Path, key: impl Into<String>) -> Self {
        Field { path, key: Some(key.into()) }
    }
}

impl Relop {
    pub fn symbol(self) -> &'static str {
        match self {
            Relop::Eq => "==",
            Relop::Ne => "!=",
            Relop::Lt => "<",
            Relop::Le => "<=",
            Relop::Gt => ">",
            Relop::Ge => ">=",
        }
    }

    pub fn is_ordering(self) -> bool {
        !matches!(self, Relop::Eq | Relop::Ne)
    }

    /// Whether `ordering` (left compared with right) satisfies the relation.
    pub fn holds(self, ordering: std::cmp::Ordering) -> bool {
        use std::cmp::Ordering::{Equal, Greater, Less};
        match self {
            Relop::Eq => ordering == Equal,
            Relop::Ne => ordering != Equal,
            Relop::Lt => ordering == Less,
            Relop::Le => ordering != Greater,
            Relop::Gt => ordering == Greater,
            Relop::Ge => ordering != Less,
        }
    }
}

impl Condition {
    /// The conjunction of `terms`, flattening nested `And`s; one term is itself.
    pub fn and(terms: impl IntoIterator<Item = Condition>) -> Condition {
        Self::nary(terms, true)
    }

    /// The disjunction of `terms`, flattening nested `Or`s; one term is itself.
    pub fn or(terms: impl IntoIterator<Item = Condition>) -> Condition {
        Self::nary(terms, false)
    }

    fn nary(terms: impl IntoIterator<Item = Condition>, and: bool) -> Condition {
        let mut flat = Vec::new();
        for term in terms {
            match term {
                Condition::And(inner) if and => flat.extend(inner),
                Condition::Or(inner) if !and => flat.extend(inner),
                other => flat.push(other),
            }
        }
        match flat.len() {
            0 => Condition::Bool(and),
            1 => flat.pop().unwrap_or(Condition::Bool(and)),
            _ if and => Condition::And(flat),
            _ => Condition::Or(flat),
        }
    }

    /// Strict parsing: canonical text only (§4.7).
    pub fn parse_strict(text: &str) -> Result<Condition, crate::syntax::ParseError> {
        crate::syntax::parse(text, crate::syntax::Mode::Strict)
    }

    /// Lenient parsing: any CEL spelling of a condition in the subset.
    pub fn parse_lenient(text: &str) -> Result<Condition, crate::syntax::ParseError> {
        crate::syntax::parse(text, crate::syntax::Mode::Lenient)
    }
}

/// Parses canonical text (`parse_strict`).
impl std::str::FromStr for Condition {
    type Err = crate::syntax::ParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Condition::parse_strict(text)
    }
}

/// The canonical text is the serialized form, on every wire and in storage.
impl serde::Serialize for Condition {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Condition {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        Condition::parse_strict(&text).map_err(serde::de::Error::custom)
    }
}
