//! Runs an SQL-marked corpus case against in-memory SQLite: one table `t`
//! with an indexed column per scalar field, a child table per list or map,
//! and a `strings` table for interned columns.

use std::collections::BTreeMap;

use rigging_condition::{Checked, Column, ColumnMap, Condition, InternTable, Param, Path, Truth, Type, Value};
use rusqlite::{Connection, params_from_iter, types::Value as Sql};
use serde_json::Value as Json;

use crate::corpus::{Case, field_types, row, truth};

const DOMAIN: &str = "ad";

struct Columns(BTreeMap<Path, Column>);

impl ColumnMap for Columns {
    fn column(&self, path: &Path) -> Option<Column> {
        self.0.get(path).cloned()
    }
}

/// How the corpus stores one field.
enum Storage {
    Cell { name: String, codes: Option<BTreeMap<String, Param>> },
    Interned { name: String },
    List { table: String },
    Map { table: String, codes: Option<BTreeMap<String, Param>> },
}

fn param(json: &Json) -> Param {
    match json {
        Json::String(s) => Param::Text(s.clone()),
        other => Param::Integer(other.as_i64().unwrap()),
    }
}

fn sql_param(param: &Param) -> Sql {
    match param {
        Param::Integer(n) => Sql::Integer(*n),
        Param::Real(x) => Sql::Real(*x),
        Param::Text(s) => Sql::Text(s.clone()),
    }
}

fn sql_type(ty: &Type, codes: &Option<BTreeMap<String, Param>>) -> &'static str {
    match (ty, codes) {
        (_, Some(codes)) if codes.values().all(|c| matches!(c, Param::Integer(_))) => "INTEGER",
        (_, Some(_)) => "TEXT",
        (Type::Number, _) => "REAL",
        (Type::String | Type::Enum(_) | Type::Address, _) => "TEXT",
        _ => "INTEGER",
    }
}

fn cell(value: &Value, codes: &Option<BTreeMap<String, Param>>) -> Sql {
    match (value, codes) {
        (Value::String(s), Some(codes)) => sql_param(&codes[s]),
        (Value::Bool(b), _) => Sql::Integer(i64::from(*b)),
        (Value::Int(n), _) => Sql::Integer(*n),
        (Value::Number(x), _) if x.is_nan() => Sql::Null,
        (Value::Number(x), _) => Sql::Real(*x),
        (Value::String(s), _) => Sql::Text(s.clone()),
        (Value::Timestamp(t), _) => Sql::Integer(t.unix_micros()),
        (Value::Duration(d), _) => Sql::Integer(d.micros()),
        (other, _) => panic!("{other:?} is not a cell"),
    }
}

/// Interns `text` in [`DOMAIN`], after a decoy copy in another domain so a
/// translation that ignores the domain picks the wrong id.
fn intern(db: &Connection, text: &str) -> i64 {
    for domain in ["zz", DOMAIN] {
        db.execute("INSERT OR IGNORE INTO strings(domain, s) VALUES (?1, ?2)", (domain, text)).unwrap();
    }
    db.query_row("SELECT id FROM strings WHERE domain = ?1 AND s = ?2", (DOMAIN, text), |r| r.get(0)).unwrap()
}

pub fn run(case: &Case, checked: &Checked<Condition>) {
    let spec = &case.json["sql"];
    let types = field_types(&case.schema);
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE strings(id INTEGER PRIMARY KEY, domain TEXT NOT NULL, s TEXT NOT NULL, UNIQUE(domain, s));").unwrap();

    let mut storage = BTreeMap::new();
    let mut columns = BTreeMap::new();
    let mut ddl = vec!["id INTEGER PRIMARY KEY".to_owned()];
    for (i, (path, ty)) in types.iter().enumerate() {
        let declared = case.schema["storage"].get(path.to_string()).cloned().unwrap_or(Json::Null);
        let codes = declared.get("codes").and_then(Json::as_object).map(|codes| codes.iter().map(|(k, v)| (k.clone(), param(v))).collect());
        let entry = match (ty, declared.as_str()) {
            (_, Some("none")) => continue,
            (_, Some("interned")) => Storage::Interned { name: format!("c{i}") },
            // A store's bug: a template with no parameter slot.
            (_, Some("bad-template")) => {
                columns.insert(path.clone(), Column::List { member: "1".into() });
                continue;
            }
            (Type::List(_), _) => Storage::List { table: format!("l{i}") },
            (Type::Map(_), _) => Storage::Map { table: format!("m{i}"), codes },
            _ => Storage::Cell { name: format!("c{i}"), codes },
        };
        let column = match &entry {
            Storage::Cell { name, codes } => {
                ddl.push(format!("{name} {}", sql_type(ty, codes)));
                Column::Value { expr: format!("t.{name}"), codes: codes.clone() }
            }
            Storage::Interned { name } => {
                ddl.push(format!("{name} INTEGER"));
                let strings = InternTable {
                    table: "strings".into(),
                    id: "id".into(),
                    domain_column: "domain".into(),
                    text_column: "s".into(),
                    domain: DOMAIN.into(),
                };
                Column::Interned { expr: format!("t.{name}"), strings }
            }
            Storage::List { table } => {
                db.execute_batch(&format!("CREATE TABLE {table}(owner INTEGER NOT NULL, value TEXT NOT NULL, PRIMARY KEY(owner, value));"))
                    .unwrap();
                Column::List { member: format!("EXISTS (SELECT 1 FROM {table} WHERE {table}.owner = t.id AND {table}.value = {{}})") }
            }
            Storage::Map { table, codes } => {
                let Type::Map(inner) = ty else { unreachable!() };
                let value_type = sql_type(inner, codes);
                db.execute_batch(&format!(
                    "CREATE TABLE {table}(owner INTEGER NOT NULL, key TEXT NOT NULL, value {value_type}, PRIMARY KEY(owner, key));"
                ))
                .unwrap();
                Column::Map {
                    lookup: format!("SELECT value FROM {table} WHERE {table}.owner = t.id AND {table}.key = {{}}"),
                    codes: codes.clone(),
                }
            }
        };
        columns.insert(path.clone(), column);
        storage.insert(path.clone(), entry);
    }
    db.execute_batch(&format!("CREATE TABLE t({});", ddl.join(", "))).unwrap();
    for entry in storage.values() {
        if let Storage::Cell { name, .. } | Storage::Interned { name } = entry {
            db.execute_batch(&format!("CREATE INDEX t_{name} ON t({name});")).unwrap();
        }
    }

    let rows = case.json["rows"].as_array().cloned().unwrap_or_default();
    let mut keep = Vec::new();
    for (i, row_json) in rows.iter().enumerate() {
        let id = i as i64 + 1;
        let row = row(&types, row_json);
        assert!(row.unknown.is_empty(), "{}: SQL rows are present or absent, never unknown", case.name);
        let mut names = vec!["id".to_owned()];
        let mut values = vec![Sql::Integer(id)];
        for (path, entry) in &storage {
            let value = row.present.get(path);
            match (entry, value) {
                (Storage::Cell { name, codes }, Some(value)) => {
                    names.push(name.clone());
                    values.push(cell(value, codes));
                }
                (Storage::Interned { name }, Some(Value::String(s))) => {
                    names.push(name.clone());
                    values.push(Sql::Integer(intern(&db, s)));
                }
                (Storage::List { table }, Some(Value::List(items))) => {
                    for item in items {
                        db.execute(&format!("INSERT INTO {table}(owner, value) VALUES (?1, ?2)"), (id, cell(item, &None))).unwrap();
                    }
                }
                (Storage::Map { table, codes }, Some(Value::Map(map))) => {
                    for (key, item) in map {
                        db.execute(&format!("INSERT INTO {table}(owner, key, value) VALUES (?1, ?2, ?3)"), (id, key, cell(item, codes)))
                            .unwrap();
                    }
                }
                // A collection in a child table is never absent: no value is empty.
                (_, None) => {}
                (_, Some(other)) => panic!("{}: {other:?} does not fit its storage", case.name),
            }
        }
        let placeholders = (1..=names.len()).map(|n| format!("?{n}")).collect::<Vec<_>>().join(", ");
        db.execute(&format!("INSERT INTO t({}) VALUES ({placeholders})", names.join(", ")), params_from_iter(values)).unwrap();
        if truth(&row_json["expect"]) == Truth::T {
            keep.push(id);
        }
    }

    let result = checked.to_sql(&Columns(columns));
    if let Some(error) = spec.get("error") {
        assert_eq!(result.as_ref().map_err(|e| e.code()).err(), error.as_str(), "{}: {result:?}", case.name);
        return;
    }
    let (text, params) = result.unwrap_or_else(|e| panic!("{}: {e}", case.name));
    if let Some(expected) = spec.get("text") {
        assert_eq!(Some(text.as_str()), expected.as_str(), "{}: SQL text", case.name);
    }
    let params: Vec<Sql> = params.iter().map(sql_param).collect();
    let query = format!("SELECT id FROM t WHERE {text} ORDER BY id");
    let mut statement = db.prepare(&query).unwrap_or_else(|e| panic!("{}: {e} in {query}", case.name));
    let got: Vec<i64> = statement.query_map(params_from_iter(params.clone()), |r| r.get(0)).unwrap().map(Result::unwrap).collect();
    assert_eq!(got, keep, "{}: SQLite keeps exactly the T rows of {query}", case.name);

    if let Some(plan) = spec.get("plan") {
        let mut explain = db.prepare(&format!("EXPLAIN QUERY PLAN SELECT id FROM t WHERE {text}")).unwrap();
        let details: Vec<String> = explain.query_map(params_from_iter(params), |r| r.get(3)).unwrap().map(Result::unwrap).collect();
        let expected: Vec<&str> = plan.as_array().unwrap().iter().map(|line| line.as_str().unwrap()).collect();
        assert_eq!(details, expected, "{}: query plan of {query}", case.name);
    }
}
