//! Loads `corpus/corpus.json` and runs every case through the parser, the
//! checker, the evaluator and, for SQL-marked cases, in-memory SQLite.

use std::{collections::BTreeMap, fs, path::PathBuf};

use rigging_condition::{Checked, Condition, Duration, Path, Schema, Timestamp, Truth, Type, Value, Values, Variable};
use serde_json::Value as Json;

use crate::sqlite;

pub struct Case {
    pub name: String,
    pub json: Json,
    pub schema: Json,
}

/// Every case: the hand-written ones, then the generated cel-spec slice.
pub fn cases() -> Vec<Case> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus/corpus.json");
    let corpus: Json = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let schemas = corpus["schemas"].as_object().unwrap();
    ["cases", "cel_spec"]
        .iter()
        .flat_map(|group| corpus[*group].as_array().unwrap().clone())
        .map(|json| {
            let name = json["name"].as_str().unwrap().to_owned();
            let schema = match &json["schema"] {
                Json::String(name) => schemas.get(name).unwrap_or_else(|| panic!("unknown schema {name}")).clone(),
                inline => inline.clone(),
            };
            Case { name, json, schema }
        })
        .collect()
}

pub fn parse_type(json: &Json) -> Type {
    match json {
        Json::String(name) => match name.as_str() {
            "bool" => Type::Bool,
            "int" => Type::Int,
            "number" => Type::Number,
            "string" => Type::String,
            "address" => Type::Address,
            "timestamp" => Type::Timestamp,
            "duration" => Type::Duration,
            other => panic!("unknown type {other}"),
        },
        Json::Object(map) => match map.iter().next().unwrap() {
            (key, values) if key == "enum" => Type::enumeration(values.as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_owned())),
            (key, inner) if key == "map" => Type::Map(Box::new(parse_type(inner))),
            (key, inner) if key == "list" => Type::List(Box::new(parse_type(inner))),
            (key, _) => panic!("unknown type {key}"),
        },
        other => panic!("bad type {other}"),
    }
}

/// The corpus's address check: `/`-separated `kind:value` segments, the kind
/// lowercase. It stands in for flotilla's canonical-address validation.
pub fn canonical_address(text: &str) -> Result<(), String> {
    let ok = text.split('/').all(|segment| {
        segment.split_once(':').is_some_and(|(kind, value)| {
            kind.starts_with(|c: char| c.is_ascii_lowercase())
                && kind.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                && !value.is_empty()
        })
    });
    if ok { Ok(()) } else { Err(format!("{text:?} is not a canonical address")) }
}

pub fn schema(json: &Json) -> Schema {
    let mut schema = Schema::new();
    for (path, decl) in json["fields"].as_object().into_iter().flatten() {
        let nullable = decl.get("nullable").and_then(Json::as_bool).unwrap_or(true);
        schema.insert_field(path.parse().unwrap(), parse_type(&decl["type"]), nullable).unwrap();
    }
    for (path, ty) in json["variables"].as_object().into_iter().flatten() {
        schema.insert_variable(Variable::new(path.parse().unwrap()).unwrap(), parse_type(ty)).unwrap();
    }
    if json.get("addresses").and_then(Json::as_str) == Some("canonical") {
        schema.validate_addresses(canonical_address);
    }
    schema
}

pub fn field_types(json: &Json) -> BTreeMap<Path, Type> {
    json["fields"].as_object().into_iter().flatten().map(|(path, decl)| (path.parse().unwrap(), parse_type(&decl["type"]))).collect()
}

pub fn value(ty: &Type, json: &Json) -> Value {
    match (ty, json) {
        (Type::Bool, Json::Bool(b)) => Value::Bool(*b),
        (Type::Int, json) => Value::Int(json.as_i64().unwrap_or_else(|| panic!("bad int {json}"))),
        (Type::Number, Json::String(nan)) if nan == "NaN" => Value::Number(f64::NAN),
        (Type::Number, json) => Value::Number(json.as_f64().unwrap()),
        (Type::String | Type::Enum(_) | Type::Address, Json::String(s)) => Value::String(s.clone()),
        (Type::Timestamp, Json::String(s)) => Value::Timestamp(Timestamp::parse_rfc3339(s).unwrap()),
        (Type::Duration, Json::String(s)) => Value::Duration(Duration::parse(s).unwrap()),
        (Type::Map(inner), Json::Object(map)) => Value::Map(map.iter().map(|(k, v)| (k.clone(), value(inner, v))).collect()),
        (Type::List(inner), Json::Array(items)) => Value::List(items.iter().map(|v| value(inner, v)).collect()),
        (ty, json) => panic!("{json} is not a {ty}"),
    }
}

pub fn row(types: &BTreeMap<Path, Type>, json: &Json) -> Values {
    let mut row = Values::default();
    for (path, v) in json["values"].as_object().into_iter().flatten() {
        let path: Path = path.parse().unwrap();
        let ty = types.get(&path).unwrap_or_else(|| panic!("row value for undeclared {path}"));
        row.present.insert(path, value(ty, v));
    }
    row.unknown = json["unknown"].as_array().into_iter().flatten().map(|p| p.as_str().unwrap().parse().unwrap()).collect();
    row
}

pub fn truth(json: &Json) -> Truth {
    match json.as_str().unwrap() {
        "T" => Truth::T,
        "F" => Truth::F,
        "U" => Truth::U,
        other => panic!("bad truth {other}"),
    }
}

/// A string, or a list of parts, each a string or `{"repeat": s, "count": n}`.
pub fn input(json: &Json) -> String {
    match json {
        Json::String(s) => s.clone(),
        Json::Array(parts) => parts
            .iter()
            .map(|part| match part {
                Json::String(s) => s.clone(),
                repeat => repeat["repeat"].as_str().unwrap().repeat(repeat["count"].as_u64().unwrap() as usize),
            })
            .collect(),
        other => panic!("bad input {other}"),
    }
}

/// What a case leads to: an error at one stage, or a checked and bound condition.
pub enum Outcome {
    Error(&'static str, String),
    Checked(Checked<Condition>),
}

/// Parses, prints, checks and binds the case, asserting each stage's
/// expectation on the way.
pub fn run_front(case: &Case) -> Outcome {
    let json = &case.json;
    let input = &input(&json["input"]);
    let lenient = json.get("lenient").and_then(Json::as_bool).unwrap_or(false);
    let parsed = if lenient { Condition::parse_lenient(input) } else { Condition::parse_strict(input) };
    let parsed = match parsed {
        Ok(parsed) => parsed,
        Err(error) => return Outcome::Error("parse_error", error.code().to_owned() + ": " + &error.to_string()),
    };
    let canonical = parsed.to_string();
    let expected = json.get("canonical").map(self::input).unwrap_or_else(|| input.clone());
    assert_eq!(canonical, expected, "{}: canonical print", case.name);
    assert!(lenient || json.get("canonical").is_none(), "{}: a strict case's input is its canonical text", case.name);
    assert_eq!(
        Condition::parse_strict(&canonical).as_ref(),
        Ok(&parsed),
        "{}: the canonical print parses strictly to the same AST",
        case.name
    );
    let schema = schema(&case.schema);
    let checked = match Checked::new(parsed, &schema) {
        Ok(checked) => checked,
        Err(error) => return Outcome::Error("check_error", error.code().to_owned() + ": " + &error.to_string()),
    };
    let mut bindings = BTreeMap::new();
    for (path, v) in json["bindings"].as_object().into_iter().flatten() {
        let variable = Variable::new(path.parse().unwrap()).unwrap();
        // A value of the wrong JSON kind is bound as what it is, for bind_error cases.
        let value = match (schema.variable(&variable), v) {
            (_, Json::Bool(b)) => Value::Bool(*b),
            (Some(Type::Number), v) | (None, v @ Json::Number(_)) if v.is_f64() => Value::Number(v.as_f64().unwrap()),
            (_, Json::Number(n)) if n.is_i64() => Value::Int(n.as_i64().unwrap()),
            (Some(ty), v) => value(ty, v),
            (None, v) => panic!("{}: binding {v} for an undeclared variable", case.name),
        };
        bindings.insert(variable, value);
    }
    match checked.bind(&bindings) {
        Ok(bound) => Outcome::Checked(bound),
        Err(error) => Outcome::Error("bind_error", error.code().to_owned() + ": " + &error.to_string()),
    }
}

fn expected_error(case: &Case) -> Option<(&'static str, &str)> {
    ["parse_error", "check_error", "bind_error"]
        .into_iter()
        .find_map(|stage| case.json.get(stage).and_then(Json::as_str).map(|code| (stage, code)))
}

// Behaviour (§8): every case parses, prints, checks and evaluates as the
// corpus says; SQL-marked cases keep exactly the T rows in SQLite.
#[test]
fn corpus() {
    let cases = cases();
    assert!(cases.len() > 100, "the corpus loaded only {} cases", cases.len());
    for case in &cases {
        let outcome = run_front(case);
        match (expected_error(case), outcome) {
            (Some((stage, code)), Outcome::Error(got_stage, message)) => {
                assert_eq!((got_stage, message.split(':').next().unwrap()), (stage, code), "{}: {message}", case.name)
            }
            (Some((stage, code)), Outcome::Checked(_)) => panic!("{}: expected {stage} {code}, but it checked", case.name),
            (None, Outcome::Error(stage, message)) => panic!("{}: unexpected {stage} {message}", case.name),
            (None, Outcome::Checked(checked)) => {
                let types = field_types(&case.schema);
                // A variable left unbound is refused, never read as U.
                if let Some(variable) = checked.unbound().into_iter().next() {
                    assert_eq!(checked.try_evaluate(&Values::default()), Err(variable), "{}", case.name);
                }
                for (i, row_json) in case.json["rows"].as_array().into_iter().flatten().enumerate() {
                    let row = row(&types, row_json);
                    assert_eq!(checked.evaluate(&row), truth(&row_json["expect"]), "{} row {i}", case.name);
                    if let Some(reason) = row_json.get("reason") {
                        let got = checked.first_failing(&row).map(ToString::to_string);
                        assert_eq!(got.as_deref(), reason.as_str(), "{} row {i}: reason", case.name);
                    }
                }
                if case.json.get("sql").is_some() {
                    sqlite::run(case, &checked);
                }
            }
        }
    }
}
