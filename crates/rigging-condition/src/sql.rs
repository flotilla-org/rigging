//! Translation to a SQLite `WHERE` expression (§4.9 of the design note).
//!
//! The output is text and parameters only. Field paths never reach the SQL:
//! each resolves through the store's [`ColumnMap`] to an expression the store
//! wrote, and every literal is a numbered parameter, already converted to the
//! column's storage type so SQLite's type affinity never applies.
//!
//! U is SQL's NULL: an absent value is a NULL cell, and every form below
//! gives NULL exactly where the evaluator gives U, so a `WHERE` keeps exactly
//! the rows that evaluate to T.

use std::{collections::BTreeMap, fmt};

use crate::{
    ast::{Condition, Field, Literal, Operand, Path, Relop, Variable},
    check::Checked,
};

/// How the store holds each field it can filter on.
///
/// Every string in a [`Column`] and an [`InternTable`] is spliced into the
/// SQL as written: it is trusted SQL that the store wrote, and must never be
/// built from user input. Only condition literals are user input, and they
/// are always parameters.
pub trait ColumnMap {
    fn column(&self, path: &Path) -> Option<Column>;
}

/// One field's storage. Templates hold `{}` where the translator puts a
/// parameter reference (`?3`); a template has no other `{}`.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Column {
    /// A cell holding the value in its storage type: bool as 0 or 1,
    /// timestamp and duration as integer microseconds, text compared under
    /// `BINARY`. An enum column may store a code per value.
    Value { expr: String, codes: Option<BTreeMap<String, Param>> },
    /// A cell holding the id of a string interned in a table with a
    /// `UNIQUE(domain, text)` index. Equality, `in`, `under` and `has` only.
    Interned { expr: String, strings: InternTable },
    /// A list in a child table: `member` is a boolean expression of one
    /// element parameter, such as
    /// `EXISTS (SELECT 1 FROM labels WHERE owner = t.id AND label = {})`.
    /// Such a list is never absent: no elements is an empty list.
    List { member: String },
    /// A map in a child table: `lookup` is a scalar expression of one key
    /// parameter giving the value, or NULL when the key is missing. Never
    /// absent, like a list.
    Map { lookup: String, codes: Option<BTreeMap<String, Param>> },
}

/// Where interned strings live: `SELECT id FROM table WHERE domain = ? AND text …`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InternTable {
    pub table: String,
    pub id: String,
    pub domain_column: String,
    pub text_column: String,
    pub domain: String,
}

/// A bound parameter, in SQLite's storage classes.
#[derive(Clone, Debug, PartialEq)]
pub enum Param {
    Integer(i64),
    Real(f64),
    Text(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SqlError {
    /// The store cannot filter on this field.
    UnknownColumn(Path),
    UnboundVariable(Variable),
    /// An enum value with no stored code.
    MissingCode {
        field: Path,
        value: String,
    },
    /// A form the column's storage cannot express, such as ordering on an
    /// interned column or a list used as a scalar.
    Unsupported {
        at: String,
    },
    /// A `List` or `Map` template without exactly one `{}`: the store's bug.
    BadTemplate(Path),
}

impl SqlError {
    pub fn code(&self) -> &'static str {
        match self {
            SqlError::UnknownColumn(_) => "unknown-column",
            SqlError::UnboundVariable(_) => "unbound-variable",
            SqlError::MissingCode { .. } => "missing-code",
            SqlError::Unsupported { .. } => "unsupported",
            SqlError::BadTemplate(_) => "bad-template",
        }
    }
}

impl fmt::Display for SqlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SqlError::UnknownColumn(path) => write!(f, "no column for {path}"),
            SqlError::UnboundVariable(variable) => write!(f, "variable {variable} is unbound"),
            SqlError::MissingCode { field, value } => write!(f, "{field} has no stored code for {value:?}"),
            SqlError::Unsupported { at } => write!(f, "{at} cannot be translated for this column"),
            SqlError::BadTemplate(path) => write!(f, "the column template for {path} must hold exactly one {{}}"),
        }
    }
}

impl std::error::Error for SqlError {}

impl Checked<Condition> {
    /// SQLite `WHERE` text and its parameters, in order: the text names them
    /// `?1`, `?2`, ….
    pub fn to_sql(&self, columns: &impl ColumnMap) -> Result<(String, Vec<Param>), SqlError> {
        let mut out = Translator { columns, params: Vec::new() };
        let text = out.condition(self)?;
        Ok((text, out.params))
    }
}

struct Translator<'c, C> {
    columns: &'c C,
    params: Vec<Param>,
}

/// A field resolved to something a comparison can read.
enum Scalar {
    Value { expr: String, codes: Option<BTreeMap<String, Param>> },
    Interned { expr: String, strings: InternTable },
}

impl<C: ColumnMap> Translator<'_, C> {
    fn param(&mut self, param: Param) -> String {
        self.params.push(param);
        format!("?{}", self.params.len())
    }

    fn column(&self, path: &Path) -> Result<Column, SqlError> {
        self.columns.column(path).ok_or_else(|| SqlError::UnknownColumn(path.clone()))
    }

    fn condition(&mut self, condition: &Condition) -> Result<String, SqlError> {
        let unsupported = || SqlError::Unsupported { at: condition.to_string() };
        Ok(match condition {
            Condition::And(terms) | Condition::Or(terms) => {
                let joiner = if matches!(condition, Condition::And(_)) { " AND " } else { " OR " };
                let parts = terms.iter().map(|term| self.condition(term).map(|sql| format!("({sql})"))).collect::<Result<Vec<_>, _>>()?;
                parts.join(joiner)
            }
            Condition::Not(inner) => format!("NOT ({})", self.condition(inner)?),
            Condition::Bool(b) => if *b { "1" } else { "0" }.to_owned(),
            Condition::Has(path) => match self.column(path)? {
                Column::Value { expr, .. } | Column::Interned { expr, .. } => format!("{expr} IS NOT NULL"),
                Column::List { .. } | Column::Map { .. } => "1".to_owned(),
            },
            Condition::Field(field) => {
                let Scalar::Value { expr, .. } = self.scalar(field)? else { return Err(unsupported()) };
                format!("{expr} = 1")
            }
            Condition::Compare { field, op, operand } => match self.scalar(field)? {
                Scalar::Value { expr, codes } => {
                    let param = self.operand(field, operand, codes.as_ref())?;
                    let symbol = match op {
                        Relop::Eq => "=",
                        Relop::Ne => "<>",
                        other => other.symbol(),
                    };
                    format!("{expr} {symbol} {param}")
                }
                Scalar::Interned { expr, strings } => {
                    let text = self.text_param(operand)?;
                    let test = format!("{} = {text}", strings.text_column);
                    let eq = self.interned(&expr, &strings, &test);
                    match op {
                        Relop::Eq => eq,
                        Relop::Ne => format!("NOT ({eq})"),
                        _ => return Err(unsupported()),
                    }
                }
            },
            Condition::In { field, list } => match self.scalar(field)? {
                Scalar::Value { expr, codes } => {
                    let params = list.iter().map(|operand| self.operand(field, operand, codes.as_ref())).collect::<Result<Vec<_>, _>>()?;
                    format!("{expr} IN ({})", params.join(", "))
                }
                Scalar::Interned { expr, strings } => {
                    let params = list.iter().map(|operand| self.text_param(operand)).collect::<Result<Vec<_>, _>>()?;
                    let test = format!("{} IN ({})", strings.text_column, params.join(", "));
                    self.interned(&expr, &strings, &test)
                }
            },
            Condition::Member { key, field } => match (&field.key, self.column(&field.path)?) {
                (None, Column::List { member }) => self.fill(&field.path, &member, key)?,
                (None, Column::Map { lookup, .. }) => format!("({}) IS NOT NULL", self.fill(&field.path, &lookup, key)?),
                _ => return Err(unsupported()),
            },
            Condition::Under { field, prefix } => match self.scalar(field)? {
                Scalar::Value { expr, codes: None } => {
                    let p = self.text_param(prefix)?;
                    under(&expr, &p)
                }
                Scalar::Interned { expr, strings } => {
                    let p = self.text_param(prefix)?;
                    let test = under(&strings.text_column, &p);
                    self.interned(&expr, &strings, &test)
                }
                Scalar::Value { codes: Some(_), .. } => return Err(unsupported()),
            },
        })
    }

    /// Resolves a field a comparison reads: a cell, or a map's value.
    fn scalar(&mut self, field: &Field) -> Result<Scalar, SqlError> {
        let unsupported = || SqlError::Unsupported { at: field.to_string() };
        Ok(match (&field.key, self.column(&field.path)?) {
            (None, Column::Value { expr, codes }) => Scalar::Value { expr, codes },
            (None, Column::Interned { expr, strings }) => Scalar::Interned { expr, strings },
            (Some(key), Column::Map { lookup, codes }) => {
                Scalar::Value { expr: format!("({})", self.fill(&field.path, &lookup, key)?), codes }
            }
            _ => return Err(unsupported()),
        })
    }

    /// A child-table template with its one `{}` replaced by a parameter for `key`.
    fn fill(&mut self, path: &Path, template: &str, key: &str) -> Result<String, SqlError> {
        if template.matches("{}").count() != 1 {
            return Err(SqlError::BadTemplate(path.clone()));
        }
        let param = self.param(Param::Text(key.to_owned()));
        Ok(template.replace("{}", &param))
    }

    /// An interned cell tested against strings matching `test`. SQLite gives
    /// false, not NULL, for `NULL IN` an empty subquery, so a NULL cell is kept
    /// NULL by `OR (e IS NULL AND NULL)`, which is NULL for a NULL cell and false
    /// otherwise. Unlike a `CASE`, this form lets SQLite search the cell's index.
    fn interned(&mut self, expr: &str, strings: &InternTable, test: &str) -> String {
        let domain = self.param(Param::Text(strings.domain.clone()));
        format!(
            "({expr} IN (SELECT {id} FROM {table} WHERE {dc} = {domain} AND {test}) OR ({expr} IS NULL AND NULL))",
            id = strings.id,
            table = strings.table,
            dc = strings.domain_column,
        )
    }

    fn text_param(&mut self, operand: &Operand) -> Result<String, SqlError> {
        match bound(operand)? {
            Literal::String(s) => Ok(self.param(Param::Text(s.clone()))),
            other => Err(SqlError::Unsupported { at: other.to_string() }),
        }
    }

    fn operand(&mut self, field: &Field, operand: &Operand, codes: Option<&BTreeMap<String, Param>>) -> Result<String, SqlError> {
        let param = match (bound(operand)?, codes) {
            (Literal::String(s), Some(codes)) => {
                codes.get(s).cloned().ok_or_else(|| SqlError::MissingCode { field: field.path.clone(), value: s.clone() })?
            }
            (literal, _) => storage(literal),
        };
        Ok(self.param(param))
    }
}

/// `f.under(p)` as one index range, `[p, p || '0')`, and a residual test
/// that drops the values strictly between `p` and `p || '/'` (`p-x`, `p.x`).
/// It is `f = p OR (f >= p || '/' AND f < p || '0')` of §4.9, written so that
/// SQLite searches one range of an index on `f`. Sound under `BINARY`
/// collation, because `0` is the byte after `/` and a canonical address
/// never holds a bare `/` inside a segment.
fn under(f: &str, p: &str) -> String {
    format!("{f} >= {p} AND {f} < {p} || '0' AND ({f} = {p} OR {f} >= {p} || '/')")
}

fn bound(operand: &Operand) -> Result<&Literal, SqlError> {
    match operand {
        Operand::Literal(literal) => Ok(literal),
        Operand::Variable(variable) => Err(SqlError::UnboundVariable(variable.clone())),
    }
}

fn storage(literal: &Literal) -> Param {
    match literal {
        Literal::String(s) => Param::Text(s.clone()),
        Literal::Int(n) => Param::Integer(*n),
        Literal::Float(x) => Param::Real(*x),
        Literal::Bool(b) => Param::Integer(i64::from(*b)),
        Literal::Timestamp(t) => Param::Integer(t.unix_micros()),
        Literal::Duration(d) => Param::Integer(d.micros()),
    }
}
