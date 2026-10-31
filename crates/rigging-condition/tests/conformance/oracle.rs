//! The differential oracle (§3 of the design note): every corpus case whose
//! rows have no unknown fields runs through the stock `cel` crate, with its
//! error read as U, and must agree with the corpus.
//!
//! The adapter follows the compatibility promise: the row is one map `r`
//! with absent fields left out and every intermediate map of a dotted path
//! present; enums and addresses are strings; `under` is
//! `f == P || f.startsWith(P + "/")`. `cel` 0.15 does not parse backticked
//! identifiers, so each field segment is renamed to `s0`, `s1`, …; a name has
//! no meaning beyond telling fields apart.

use std::{collections::HashMap, sync::Arc};

use cel::{Context, Env, Value as Cel};
use rigging_condition::{Condition, Field, Operand, Path, Type, Value};
use serde_json::Value as Json;

use crate::corpus::{Outcome, cases, field_types, row, run_front, truth};

struct Names(HashMap<String, String>);

impl Names {
    fn segment(&mut self, segment: &str) -> String {
        let next = format!("s{}", self.0.len());
        self.0.entry(segment.to_owned()).or_insert(next).clone()
    }

    fn path(&mut self, path: &Path) -> String {
        let mut out = "r".to_owned();
        for segment in path.segments() {
            out.push('.');
            out.push_str(&self.segment(segment));
        }
        out
    }

    fn field(&mut self, field: &Field) -> String {
        let mut out = self.path(&field.path);
        if let Some(key) = &field.key {
            out.push_str(&format!("[{}]", rigging_condition::Literal::String(key.clone())));
        }
        out
    }

    fn print(&mut self, condition: &Condition) -> String {
        let operand = |operand: &Operand| match operand {
            Operand::Literal(literal) => literal.to_string(),
            Operand::Variable(variable) => panic!("unbound {variable}"),
        };
        match condition {
            Condition::And(terms) => terms.iter().map(|t| format!("({})", self.print(t))).collect::<Vec<_>>().join(" && "),
            Condition::Or(terms) => terms.iter().map(|t| format!("({})", self.print(t))).collect::<Vec<_>>().join(" || "),
            Condition::Not(inner) => format!("!({})", self.print(inner)),
            Condition::Has(path) => format!("has({})", self.path(path)),
            Condition::Compare { field, op, operand: o } => format!("{} {op} {}", self.field(field), operand(o)),
            Condition::In { field, list } => {
                format!("{} in [{}]", self.field(field), list.iter().map(operand).collect::<Vec<_>>().join(", "))
            }
            Condition::Member { key, field } => format!("{} in {}", rigging_condition::Literal::String(key.clone()), self.field(field)),
            Condition::Under { field, prefix } => {
                let (f, p) = (self.field(field), operand(prefix));
                format!("({f} == {p} || {f}.startsWith({p} + \"/\"))")
            }
            Condition::Field(field) => self.field(field),
            Condition::Bool(b) => b.to_string(),
            other => panic!("no oracle form for {other}"),
        }
    }
}

fn cel_value(value: &Value) -> Option<Cel> {
    Some(match value {
        Value::Bool(b) => Cel::Bool(*b),
        Value::Int(n) => Cel::Int(*n),
        Value::Number(x) if x.is_nan() => return None,
        Value::Number(x) => Cel::Float(*x),
        Value::String(s) => Cel::String(Arc::new(s.clone())),
        Value::Timestamp(t) => Cel::Timestamp(chrono::DateTime::from_timestamp_micros(t.unix_micros()).unwrap().fixed_offset()),
        Value::Duration(d) => Cel::Duration(chrono::Duration::microseconds(d.micros())),
        Value::Map(map) => Cel::Map(map.iter().map(|(k, v)| (k.clone(), cel_value(v).unwrap())).collect::<HashMap<_, _>>().into()),
        Value::List(items) => Cel::List(Arc::new(items.iter().map(|v| cel_value(v).unwrap()).collect())),
        other => panic!("no oracle value for {other:?}"),
    })
}

/// A nested map node of the oracle's row.
#[derive(Default)]
struct Node {
    value: Option<Cel>,
    children: HashMap<String, Node>,
}

impl Node {
    fn into_cel(self) -> Cel {
        match self.value {
            Some(value) => value,
            None => Cel::Map(self.children.into_iter().map(|(k, v)| (k, v.into_cel())).collect::<HashMap<_, _>>().into()),
        }
    }
}

fn oracle_row(names: &mut Names, types: &std::collections::BTreeMap<Path, Type>, row: &rigging_condition::Values) -> Cel {
    let mut root = Node::default();
    // Every declared path's intermediate maps exist, present or not.
    for path in types.keys() {
        let mut node = &mut root;
        let segments = path.segments();
        for segment in &segments[..segments.len() - 1] {
            node = node.children.entry(names.segment(segment)).or_default();
        }
        if let Some(value) = row.present.get(path).and_then(cel_value) {
            node.children.entry(names.segment(&segments[segments.len() - 1])).or_default().value = Some(value);
        }
    }
    root.into_cel()
}

// Behaviour (§3): over rows whose fields are present or absent, a stock CEL
// evaluator returns true for T, false for F and an error for U.
#[test]
fn cel_crate_agrees_with_the_corpus() {
    let env = Arc::new(Env::stdlib());
    let mut compared = 0;
    for case in cases() {
        let Outcome::Checked(checked) = run_front(&case) else { continue };
        let types = field_types(&case.schema);
        for (i, row_json) in case.json["rows"].as_array().into_iter().flatten().enumerate() {
            if row_json.get("unknown").and_then(Json::as_array).is_some_and(|u| !u.is_empty()) {
                continue;
            }
            let mut names = Names(HashMap::new());
            let text = names.print(&checked);
            let program = env.compile(&text).unwrap_or_else(|e| panic!("{}: cel cannot parse {text}: {e}", case.name));
            let mut context = Context::with_env(Arc::clone(&env));
            context.add_variable_from_value("r", oracle_row(&mut names, &types, &row(&types, row_json)));
            let got = match program.execute(&context) {
                Ok(Cel::Bool(true)) => "T",
                Ok(Cel::Bool(false)) => "F",
                Ok(other) => panic!("{}: cel gave {other:?} for {text}", case.name),
                Err(_) => "U",
            };
            assert_eq!(truth(&Json::String(got.into())), truth(&row_json["expect"]), "{} row {i}: cel on {text}", case.name);
            compared += 1;
        }
    }
    assert!(compared > 100, "only {compared} rows were compared");
}
