//! Three-valued evaluation over one row (§4.5 of the design note).

use std::{borrow::Cow, cmp::Ordering, collections::BTreeMap};

use crate::{
    ast::{Condition, Field, Literal, Operand, Path, Variable},
    check::Checked,
    time::{Duration, Timestamp},
};

/// T, F or U (unknown). `!`, `&&` and `||` use the strong Kleene tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Truth {
    T,
    F,
    U,
}

impl std::ops::Not for Truth {
    type Output = Truth;

    fn not(self) -> Truth {
        match self {
            Truth::T => Truth::F,
            Truth::F => Truth::T,
            Truth::U => Truth::U,
        }
    }
}

impl Truth {
    pub fn and(self, other: Truth) -> Truth {
        match (self, other) {
            (Truth::F, _) | (_, Truth::F) => Truth::F,
            (Truth::T, Truth::T) => Truth::T,
            _ => Truth::U,
        }
    }

    pub fn or(self, other: Truth) -> Truth {
        match (self, other) {
            (Truth::T, _) | (_, Truth::T) => Truth::T,
            (Truth::F, Truth::F) => Truth::F,
            _ => Truth::U,
        }
    }

    pub fn is_true(self) -> bool {
        self == Truth::T
    }
}

impl From<bool> for Truth {
    fn from(b: bool) -> Truth {
        if b { Truth::T } else { Truth::F }
    }
}

/// A field's value in a row. Enums and addresses are strings.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Value {
    Bool(bool),
    Int(i64),
    /// A NaN reads as absent.
    Number(f64),
    String(String),
    Timestamp(Timestamp),
    Duration(Duration),
    Map(BTreeMap<String, Value>),
    List(Vec<Value>),
}

/// What a row knows about one field.
#[derive(Clone, Debug, PartialEq)]
pub enum Lookup<'a> {
    Present(Cow<'a, Value>),
    /// The row knows the field has no value.
    Absent,
    /// The row cannot say whether the field has a value: the subject is
    /// unobserved, or the observation is stale.
    Unknown,
}

/// One row of named, typed fields: the solution mapping a condition reads.
/// It is looked up by each field's full declared path, never walked.
pub trait Row {
    fn get(&self, path: &Path) -> Lookup<'_>;
}

/// A row held in memory: present values, and the fields that are unknown.
/// Every other field is absent.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Values {
    pub present: BTreeMap<Path, Value>,
    pub unknown: Vec<Path>,
}

impl Row for Values {
    fn get(&self, path: &Path) -> Lookup<'_> {
        match self.present.get(path) {
            Some(value) => Lookup::Present(Cow::Borrowed(value)),
            None if self.unknown.contains(path) => Lookup::Unknown,
            None => Lookup::Absent,
        }
    }
}

impl Checked<Condition> {
    /// The condition's truth over `row`.
    ///
    /// # Panics
    ///
    /// If a variable is still unbound: binding is the consumer's job, and an
    /// unbound variable at evaluation time is a bug, not U (§4.3).
    pub fn evaluate(&self, row: &impl Row) -> Truth {
        self.try_evaluate(row).unwrap_or_else(|variable| panic!("variable {variable} is unbound; bind it before evaluating"))
    }

    /// [`evaluate`](Self::evaluate) without the panic: the first unbound
    /// variable, if any is left, instead of a truth value.
    pub fn try_evaluate(&self, row: &impl Row) -> Result<Truth, Variable> {
        match self.unbound().into_iter().next() {
            Some(variable) => Err(variable),
            None => Ok(evaluate(self, row)),
        }
    }

    /// The first top-level conjunct that is not T, as the reason a condition
    /// failed; the whole condition when it is not a conjunction. `None` when
    /// the condition is T. It prints as canonical text.
    pub fn first_failing(&self, row: &impl Row) -> Option<&Condition> {
        let condition: &Condition = self;
        match condition {
            Condition::And(terms) => terms.iter().find(|term| evaluate(term, row) != Truth::T),
            other => (evaluate(other, row) != Truth::T).then_some(other),
        }
    }
}

fn evaluate(condition: &Condition, row: &impl Row) -> Truth {
    match condition {
        Condition::And(terms) => terms.iter().fold(Truth::T, |acc, term| acc.and(evaluate(term, row))),
        Condition::Or(terms) => terms.iter().fold(Truth::F, |acc, term| acc.or(evaluate(term, row))),
        Condition::Not(inner) => !evaluate(inner, row),
        Condition::Bool(b) => Truth::from(*b),
        Condition::Has(path) => match row.get(path) {
            Lookup::Present(value) if !is_nan(&value) => Truth::T,
            Lookup::Present(_) | Lookup::Absent => Truth::F,
            Lookup::Unknown => Truth::U,
        },
        Condition::Field(field) => with_value(row, field, |value| match value {
            Value::Bool(b) => Truth::from(*b),
            _ => Truth::U,
        }),
        Condition::Compare { field, op, operand } => {
            let literal = literal(operand);
            with_value(row, field, |value| compare(value, literal).map_or(Truth::U, |ordering| Truth::from(op.holds(ordering))))
        }
        Condition::In { field, list } => with_value(row, field, |value| {
            let mut found = Truth::F;
            for operand in list {
                match compare(value, literal(operand)) {
                    Some(Ordering::Equal) => return Truth::T,
                    Some(_) => {}
                    None => found = Truth::U,
                }
            }
            found
        }),
        Condition::Member { key, field } => with_value(row, field, |value| match value {
            Value::Map(map) => Truth::from(map.contains_key(key)),
            Value::List(items) => Truth::from(items.iter().any(|item| matches!(item, Value::String(s) if s == key))),
            _ => Truth::U,
        }),
        Condition::Under { field, prefix } => {
            let Literal::String(prefix) = literal(prefix) else { return Truth::U };
            with_value(row, field, |value| match value {
                Value::String(s) => Truth::from(under(s, prefix)),
                _ => Truth::U,
            })
        }
    }
}

/// §4.6: `f` is `p`, or starts with `p` followed by `/`.
pub fn under(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

fn literal(operand: &Operand) -> &Literal {
    match operand {
        Operand::Literal(literal) => literal,
        Operand::Variable(variable) => panic!("variable {variable} is unbound; bind it before evaluating"),
    }
}

fn is_nan(value: &Value) -> bool {
    matches!(value, Value::Number(x) if x.is_nan())
}

/// Applies `f` to the field's value, or gives U when it is absent or unknown.
/// A value of a type other than the declared one is the row's bug, and reads
/// as U rather than being converted.
fn with_value(row: &impl Row, field: &Field, f: impl FnOnce(&Value) -> Truth) -> Truth {
    let Lookup::Present(value) = row.get(&field.path) else { return Truth::U };
    let value = match (&field.key, &*value) {
        (None, value) => value,
        (Some(key), Value::Map(map)) => match map.get(key) {
            Some(value) => value,
            None => return Truth::U,
        },
        (Some(_), _) => return Truth::U,
    };
    if is_nan(value) { Truth::U } else { f(value) }
}

/// Compares a value with a literal of its type: ints and numbers on the
/// number line, strings by code point, timestamps and durations by
/// microseconds. `None` when the two are not comparable.
fn compare(value: &Value, literal: &Literal) -> Option<Ordering> {
    match (value, literal) {
        (Value::Bool(a), Literal::Bool(b)) => Some(a.cmp(b)),
        (Value::Int(a), Literal::Int(b)) => Some(a.cmp(b)),
        (Value::Number(a), Literal::Float(b)) => a.partial_cmp(b),
        (Value::Number(a), Literal::Int(b)) => cmp_int_float(*b, *a).map(Ordering::reverse),
        (Value::String(a), Literal::String(b)) => Some(a.as_str().cmp(b.as_str())),
        (Value::Timestamp(a), Literal::Timestamp(b)) => Some(a.cmp(b)),
        (Value::Duration(a), Literal::Duration(b)) => Some(a.cmp(b)),
        _ => None,
    }
}

/// Exact comparison of an i64 with a finite f64, with no rounding of the int.
fn cmp_int_float(i: i64, x: f64) -> Option<Ordering> {
    if x.is_nan() {
        return None;
    }
    // 2^63 is exactly representable; every i64 is below it and at or above -2^63.
    const TWO_63: f64 = 9_223_372_036_854_775_808.0;
    if x >= TWO_63 {
        return Some(Ordering::Less);
    }
    if x < -TWO_63 {
        return Some(Ordering::Greater);
    }
    let whole = x.trunc();
    match i.cmp(&(whole as i64)) {
        Ordering::Equal if x > whole => Some(Ordering::Less),
        Ordering::Equal if x < whole => Some(Ordering::Greater),
        ordering => Some(ordering),
    }
}
