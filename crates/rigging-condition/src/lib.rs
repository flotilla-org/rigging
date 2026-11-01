//! One condition language, a strict subset of CEL, shared by flotilla and
//! binnacle. The design is flotilla's research note
//! `docs/research/2026-10-31-condition-expression-language.md`; section
//! numbers in this crate refer to it.
//!
//! ```
//! use rigging_condition::{Checked, Condition, Path, Schema, Truth, Type, Value, Values};
//!
//! let mut schema = Schema::new();
//! schema.insert_field("state".parse().unwrap(), Type::enumeration(["open", "merged"]), false).unwrap();
//!
//! let parsed = Condition::parse_strict(r#"state == "merged""#).unwrap();
//! let checked = Checked::new(parsed, &schema).unwrap();
//!
//! let mut row = Values::default();
//! row.present.insert("state".parse().unwrap(), Value::String("open".into()));
//! assert_eq!(checked.evaluate(&row), Truth::F);
//! assert_eq!(checked.first_failing(&row).unwrap().to_string(), r#"state == "merged""#);
//! ```
//!
//! No I/O and no project dependencies (flotilla ADR 0068 §3).

pub mod ast;
pub mod check;
pub mod eval;
pub mod sql;
pub mod syntax;
mod time;

pub use ast::{Condition, Duration, Field, Literal, NameError, Operand, Path, Relop, Timestamp, Variable};
pub use check::{BindError, CheckError, Checked, FieldDecl, Schema, SchemaError, Type};
pub use eval::{Lookup, Row, Truth, Value, Values, under};
pub use sql::{Column, ColumnMap, InternTable, Param, SqlError};
pub use syntax::{Limit, ParseError, ParseErrorKind};
pub use time::TimeError;
