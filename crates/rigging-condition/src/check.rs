//! The schema and the type rules of §4.3. A [`Checked`] condition is proof
//! that every field is declared and every literal fits its field.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
};

use crate::{
    ast::{Condition, Field, Literal, Operand, Path, Variable},
    eval::Value,
};

/// A field's or variable's type.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Type {
    Bool,
    /// i64.
    Int,
    /// f64, never NaN: a NaN cell is absent.
    Number,
    String,
    /// One of the listed strings: equality and `in` only, no ordering.
    Enum(BTreeSet<String>),
    /// Canonical ADR 0066 address text: equality, `in` and `under`, no ordering.
    Address,
    Timestamp,
    Duration,
    /// A string-keyed map of scalars: `"k" in m` and `m["k"]`.
    Map(Box<Type>),
    /// A list of scalars: `"x" in l`, for strings, enums and addresses.
    List(Box<Type>),
}

impl Type {
    pub fn enumeration<I, S>(values: I) -> Type
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Type::Enum(values.into_iter().map(Into::into).collect())
    }

    pub fn is_scalar(&self) -> bool {
        !matches!(self, Type::Map(_) | Type::List(_))
    }

    fn is_ordered(&self) -> bool {
        matches!(self, Type::Int | Type::Number | Type::String | Type::Timestamp | Type::Duration)
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Bool => f.write_str("bool"),
            Type::Int => f.write_str("int"),
            Type::Number => f.write_str("number"),
            Type::String => f.write_str("string"),
            Type::Enum(values) => {
                f.write_str("enum{")?;
                for (i, value) in values.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    crate::syntax::write_string(f, value)?;
                }
                f.write_str("}")
            }
            Type::Address => f.write_str("address"),
            Type::Timestamp => f.write_str("timestamp"),
            Type::Duration => f.write_str("duration"),
            Type::Map(value) => write!(f, "map(string, {value})"),
            Type::List(element) => write!(f, "list({element})"),
        }
    }
}

/// A declared field: its type and whether it may be absent. The language's
/// meaning does not depend on `nullable`; it is there for consumers (a UI that
/// offers `has()`, a store that knows a column is NOT NULL).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldDecl {
    pub ty: Type,
    pub nullable: bool,
}

type AddressCheck = Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

/// The fields a condition may read, the variables it may name, and how
/// address literals are validated.
#[derive(Clone, Default)]
pub struct Schema {
    fields: BTreeMap<Path, FieldDecl>,
    variables: BTreeMap<Variable, Type>,
    addresses: Option<AddressCheck>,
}

impl fmt::Debug for Schema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Schema").field("fields", &self.fields).field("variables", &self.variables).finish_non_exhaustive()
    }
}

/// Why a declaration was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SchemaError {
    /// Declared twice, one path a prefix of another, or a field sharing its
    /// first segment with a variable.
    #[error("{0} conflicts with another declaration")]
    Conflict(Path),
    /// A map or list of something other than a scalar, a list of a type that
    /// `in` cannot test, an enum with no values, or a non-scalar variable.
    #[error("{0} cannot have type {1}")]
    InvalidType(Path, Type),
}

fn valid_type(ty: &Type, nested: bool) -> bool {
    match ty {
        Type::Enum(values) => !values.is_empty(),
        Type::Map(value) => !nested && value.is_scalar() && valid_type(value, true),
        Type::List(element) => !nested && matches!(**element, Type::String | Type::Enum(_) | Type::Address) && valid_type(element, true),
        _ => true,
    }
}

impl Schema {
    pub fn new() -> Self {
        Self::default()
    }

    /// Declares a field. A field's path may not be a prefix of another
    /// field's, since a dotted path names one field, not a walk.
    pub fn insert_field(&mut self, path: Path, ty: Type, nullable: bool) -> Result<(), SchemaError> {
        if !valid_type(&ty, false) {
            return Err(SchemaError::InvalidType(path, ty));
        }
        let clash = self.fields.keys().any(|other| other.is_prefix_of(&path) || path.is_prefix_of(other))
            || self.variables.keys().any(|v| v.path().segments()[0] == path.segments()[0]);
        if clash {
            return Err(SchemaError::Conflict(path));
        }
        self.fields.insert(path, FieldDecl { ty, nullable });
        Ok(())
    }

    /// Declares a bound variable, substituted by [`Checked::bind`]. A variable
    /// is a scalar, and no field may share its first segment.
    pub fn insert_variable(&mut self, variable: Variable, ty: Type) -> Result<(), SchemaError> {
        if !ty.is_scalar() || !valid_type(&ty, false) {
            return Err(SchemaError::InvalidType(variable.path().clone(), ty));
        }
        let root = &variable.path().segments()[0];
        let clash = self.fields.keys().any(|field| &field.segments()[0] == root)
            || self.variables.keys().any(|other| other.path().is_prefix_of(variable.path()) || variable.path().is_prefix_of(other.path()));
        if clash {
            return Err(SchemaError::Conflict(variable.path().clone()));
        }
        self.variables.insert(variable, ty);
        Ok(())
    }

    /// The hook that validates `address` literals and bound values, such as
    /// flotilla's check for canonical ADR 0066 text. `under` is defined on
    /// canonical text alone, so a consumer with addresses should set one.
    pub fn validate_addresses(&mut self, check: impl Fn(&str) -> Result<(), String> + Send + Sync + 'static) {
        self.addresses = Some(Arc::new(check));
    }

    pub fn field(&self, path: &Path) -> Option<&FieldDecl> {
        self.fields.get(path)
    }

    pub fn fields(&self) -> impl Iterator<Item = (&Path, &FieldDecl)> {
        self.fields.iter()
    }

    pub fn variable(&self, variable: &Variable) -> Option<&Type> {
        self.variables.get(variable)
    }

    fn check_address(&self, text: &str) -> Result<(), String> {
        match &self.addresses {
            Some(check) => check(text),
            None => Ok(()),
        }
    }
}

/// Why a condition does not check against a schema.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CheckError {
    #[error("unknown field {0}")]
    UnknownField(Path),
    #[error("unknown variable {0}")]
    UnknownVariable(Variable),
    /// A declared variable's name used as a field.
    #[error("{0} names a bound variable, not a field")]
    VariableAsField(Path),
    /// A literal, variable or field of the wrong type. `at` is the canonical
    /// text of the term.
    #[error("{at}: expected {expected}, found {found}")]
    TypeMismatch { at: String, expected: String, found: String },
    /// `<`, `<=`, `>` or `>=` on a bool, enum or address.
    #[error("{at}: {ty} has no ordering")]
    OrderingNotAllowed { at: String, ty: Type },
    /// A literal of the right type that is not allowed: outside an enum's
    /// set, refused by the address hook, or a non-finite float.
    #[error("{at}: {reason}")]
    InvalidLiteral { at: String, reason: String },
    /// `f in []`.
    #[error("{at}: in needs a non-empty list")]
    EmptyList { at: String },
    /// A tree built by hand that is over the parser's limits.
    #[error("{0}")]
    Limit(crate::syntax::Limit),
    /// A tree built by hand with an `&&` or `||` of fewer than two terms, or
    /// one directly holding another of its kind. No text parses to it, so it
    /// has no canonical text. `at` is the node's print.
    #[error("{at}: an && or || needs two or more terms, none of its own kind")]
    Shape { at: String },
}

impl CheckError {
    /// A stable name for the kind of error. The conformance corpus uses these.
    pub fn code(&self) -> &'static str {
        match self {
            CheckError::UnknownField(_) => "unknown-field",
            CheckError::UnknownVariable(_) => "unknown-variable",
            CheckError::VariableAsField(_) => "variable-as-field",
            CheckError::TypeMismatch { .. } => "type-mismatch",
            CheckError::OrderingNotAllowed { .. } => "ordering",
            CheckError::InvalidLiteral { .. } => "invalid-literal",
            CheckError::EmptyList { .. } => "empty-list",
            CheckError::Limit(_) => "limit",
            CheckError::Shape { .. } => "shape",
        }
    }
}

/// Why [`Checked::bind`] refused a value.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BindError {
    #[error("{0} is not a declared variable")]
    UnknownVariable(Variable),
    #[error("{variable} needs a {expected} value")]
    TypeMismatch { variable: Variable, expected: Type },
    #[error("{variable}: {reason}")]
    InvalidValue { variable: Variable, reason: String },
}

impl BindError {
    pub fn code(&self) -> &'static str {
        match self {
            BindError::UnknownVariable(_) => "unknown-variable",
            BindError::TypeMismatch { .. } => "type-mismatch",
            BindError::InvalidValue { .. } => "invalid-literal",
        }
    }
}

/// Proof that `T` checked against a schema. For a [`Condition`], it is the
/// only way to evaluate it or translate it to SQL.
#[derive(Clone)]
pub struct Checked<T> {
    value: T,
    schema: Schema,
}

impl<T: fmt::Debug> fmt::Debug for Checked<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Checked").field(&self.value).finish()
    }
}

impl<T: fmt::Display> fmt::Display for Checked<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt(f)
    }
}

impl<T> std::ops::Deref for Checked<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T> Checked<T> {
    pub fn into_inner(self) -> T {
        self.value
    }

    pub fn schema(&self) -> &Schema {
        &self.schema
    }
}

impl Checked<Condition> {
    /// Checks `condition` against `schema` (§4.3). A tree built in code must
    /// also be within the limits and in the parser's shape (see
    /// [`Condition::check_shape`]), so that it has canonical text.
    pub fn new(condition: Condition, schema: &Schema) -> Result<Self, CheckError> {
        condition.check_limits().map_err(CheckError::Limit)?;
        condition.check_shape()?;
        check(&condition, schema)?;
        Ok(Checked { value: condition, schema: schema.clone() })
    }

    /// Replaces the variables named in `bindings` with their values, as
    /// constant folding (§4.3). Variables not named stay unbound.
    pub fn bind(&self, bindings: &BTreeMap<Variable, Value>) -> Result<Self, BindError> {
        let mut literals = BTreeMap::new();
        for (variable, value) in bindings {
            let ty = self.schema.variable(variable).ok_or_else(|| BindError::UnknownVariable(variable.clone()))?;
            literals.insert(variable.clone(), bind_value(&self.schema, variable, ty, value)?);
        }
        let mut value = self.value.clone();
        substitute(&mut value, &literals);
        Ok(Checked { value, schema: self.schema.clone() })
    }

    /// The variables still to be bound.
    pub fn unbound(&self) -> BTreeSet<Variable> {
        let mut out = BTreeSet::new();
        visit_operands(&self.value, &mut |operand| {
            if let Operand::Variable(variable) = operand {
                out.insert(variable.clone());
            }
        });
        out
    }
}

impl Condition {
    /// Refuses an `&&` or `||` of fewer than two terms, or one directly
    /// holding another of its kind: the shapes the parser never builds,
    /// which print to text that parses to a different tree. Call it after
    /// [`check_limits`](Condition::check_limits), which bounds the depth.
    pub fn check_shape(&self) -> Result<(), CheckError> {
        match self {
            Condition::And(terms) | Condition::Or(terms) => {
                let and = matches!(self, Condition::And(_));
                let same_kind = |term: &Condition| matches!((and, term), (true, Condition::And(_)) | (false, Condition::Or(_)));
                if terms.len() < 2 || terms.iter().any(same_kind) {
                    return Err(CheckError::Shape { at: self.to_string() });
                }
                terms.iter().try_for_each(Condition::check_shape)
            }
            Condition::Not(inner) => inner.check_shape(),
            _ => Ok(()),
        }
    }
}

fn bind_value(schema: &Schema, variable: &Variable, ty: &Type, value: &Value) -> Result<Literal, BindError> {
    let mismatch = || BindError::TypeMismatch { variable: variable.clone(), expected: ty.clone() };
    let invalid = |reason: String| BindError::InvalidValue { variable: variable.clone(), reason };
    Ok(match (ty, value) {
        (Type::Bool, Value::Bool(b)) => Literal::Bool(*b),
        (Type::Int, Value::Int(n)) => Literal::Int(*n),
        (Type::Number, Value::Int(n)) => Literal::Int(*n),
        (Type::Number, Value::Number(x)) if x.is_finite() => Literal::Float(*x),
        (Type::Number, Value::Number(_)) => return Err(invalid("a number variable must be finite".into())),
        (Type::String, Value::String(s)) => Literal::String(s.clone()),
        (Type::Enum(values), Value::String(s)) if values.contains(s) => Literal::String(s.clone()),
        (Type::Enum(_), Value::String(s)) => return Err(invalid(format!("{s:?} is not in the enum"))),
        (Type::Address, Value::String(s)) => {
            schema.check_address(s).map_err(invalid)?;
            Literal::String(s.clone())
        }
        (Type::Timestamp, Value::Timestamp(t)) => Literal::Timestamp(*t),
        (Type::Duration, Value::Duration(d)) => Literal::Duration(*d),
        _ => return Err(mismatch()),
    })
}

fn substitute(condition: &mut Condition, literals: &BTreeMap<Variable, Literal>) {
    let replace = |operand: &mut Operand| {
        if let Operand::Variable(variable) = operand
            && let Some(literal) = literals.get(variable)
        {
            *operand = Operand::Literal(literal.clone());
        }
    };
    match condition {
        Condition::And(terms) | Condition::Or(terms) => terms.iter_mut().for_each(|term| substitute(term, literals)),
        Condition::Not(inner) => substitute(inner, literals),
        Condition::Compare { operand, .. } | Condition::Under { prefix: operand, .. } => replace(operand),
        Condition::In { list, .. } => list.iter_mut().for_each(replace),
        Condition::Has(_) | Condition::Member { .. } | Condition::Field(_) | Condition::Bool(_) => {}
    }
}

fn visit_operands(condition: &Condition, visit: &mut impl FnMut(&Operand)) {
    match condition {
        Condition::And(terms) | Condition::Or(terms) => terms.iter().for_each(|term| visit_operands(term, visit)),
        Condition::Not(inner) => visit_operands(inner, visit),
        Condition::Compare { operand, .. } | Condition::Under { prefix: operand, .. } => visit(operand),
        Condition::In { list, .. } => list.iter().for_each(visit),
        Condition::Has(_) | Condition::Member { .. } | Condition::Field(_) | Condition::Bool(_) => {}
    }
}

fn check(condition: &Condition, schema: &Schema) -> Result<(), CheckError> {
    let at = || condition.to_string();
    match condition {
        Condition::And(terms) | Condition::Or(terms) => terms.iter().try_for_each(|term| check(term, schema)),
        Condition::Not(inner) => check(inner, schema),
        Condition::Bool(_) => Ok(()),
        Condition::Has(path) => declared(schema, path).map(|_| ()),
        Condition::Field(field) => match field_type(schema, field)? {
            Type::Bool => Ok(()),
            other => Err(CheckError::TypeMismatch { at: at(), expected: "a bool field".into(), found: other.to_string() }),
        },
        Condition::Compare { field, op, operand } => {
            let ty = scalar_type(schema, field, condition)?;
            if op.is_ordering() && !ty.is_ordered() {
                return Err(CheckError::OrderingNotAllowed { at: at(), ty: ty.clone() });
            }
            check_operand(schema, ty, operand, condition)
        }
        Condition::In { field, list } => {
            let ty = scalar_type(schema, field, condition)?;
            if list.is_empty() {
                return Err(CheckError::EmptyList { at: at() });
            }
            list.iter().try_for_each(|operand| check_operand(schema, ty, operand, condition))
        }
        Condition::Member { key, field } => match field_type(schema, field)? {
            Type::Map(_) => Ok(()),
            Type::List(element) => check_literal(schema, element, &Literal::String(key.clone()), condition),
            other => Err(CheckError::TypeMismatch { at: at(), expected: "a map or list field".into(), found: other.to_string() }),
        },
        Condition::Under { field, prefix } => match scalar_type(schema, field, condition)? {
            Type::Address => check_operand(schema, &Type::Address, prefix, condition),
            other => Err(CheckError::TypeMismatch { at: at(), expected: "an address field".into(), found: other.to_string() }),
        },
    }
}

fn declared<'s>(schema: &'s Schema, path: &Path) -> Result<&'s Type, CheckError> {
    if let Some(decl) = schema.field(path) {
        return Ok(&decl.ty);
    }
    if schema.variables.keys().any(|v| v.path().segments()[0] == path.segments()[0]) {
        return Err(CheckError::VariableAsField(path.clone()));
    }
    Err(CheckError::UnknownField(path.clone()))
}

/// The type a field reference reads: the declared type, or a map's value type
/// when it is indexed.
fn field_type<'s>(schema: &'s Schema, field: &Field) -> Result<&'s Type, CheckError> {
    let ty = declared(schema, &field.path)?;
    match (&field.key, ty) {
        (None, ty) => Ok(ty),
        (Some(_), Type::Map(value)) => Ok(value),
        (Some(_), other) => {
            Err(CheckError::TypeMismatch { at: field.to_string(), expected: "a map field".into(), found: other.to_string() })
        }
    }
}

fn scalar_type<'s>(schema: &'s Schema, field: &Field, condition: &Condition) -> Result<&'s Type, CheckError> {
    let ty = field_type(schema, field)?;
    if !ty.is_scalar() {
        return Err(CheckError::TypeMismatch { at: condition.to_string(), expected: "a scalar field".into(), found: ty.to_string() });
    }
    Ok(ty)
}

fn check_operand(schema: &Schema, ty: &Type, operand: &Operand, condition: &Condition) -> Result<(), CheckError> {
    match operand {
        Operand::Literal(literal) => check_literal(schema, ty, literal, condition),
        Operand::Variable(variable) => {
            let declared = schema.variable(variable).ok_or_else(|| CheckError::UnknownVariable(variable.clone()))?;
            let fits = declared == ty || (*ty == Type::Number && *declared == Type::Int);
            if !fits {
                return Err(CheckError::TypeMismatch { at: condition.to_string(), expected: ty.to_string(), found: declared.to_string() });
            }
            Ok(())
        }
    }
}

fn check_literal(schema: &Schema, ty: &Type, literal: &Literal, condition: &Condition) -> Result<(), CheckError> {
    let invalid = |reason: String| CheckError::InvalidLiteral { at: condition.to_string(), reason };
    match (ty, literal) {
        (Type::Bool, Literal::Bool(_))
        | (Type::Int, Literal::Int(_))
        | (Type::Number, Literal::Int(_))
        | (Type::String, Literal::String(_))
        | (Type::Timestamp, Literal::Timestamp(_))
        | (Type::Duration, Literal::Duration(_)) => Ok(()),
        (Type::Number, Literal::Float(x)) if x.is_finite() => Ok(()),
        (Type::Number, Literal::Float(_)) => Err(invalid("a number literal must be finite".into())),
        (Type::Enum(values), Literal::String(s)) if values.contains(s) => Ok(()),
        (Type::Enum(_), Literal::String(s)) => Err(invalid(format!("{s:?} is not one of the enum's values"))),
        (Type::Address, Literal::String(s)) => schema.check_address(s).map_err(invalid),
        (ty, literal) => {
            Err(CheckError::TypeMismatch { at: condition.to_string(), expected: ty.to_string(), found: literal_kind(literal).into() })
        }
    }
}

fn literal_kind(literal: &Literal) -> &'static str {
    match literal {
        Literal::String(_) => "a string literal",
        Literal::Int(_) => "an int literal",
        Literal::Float(_) => "a float literal",
        Literal::Bool(_) => "a bool literal",
        Literal::Timestamp(_) => "a timestamp literal",
        Literal::Duration(_) => "a duration literal",
    }
}
