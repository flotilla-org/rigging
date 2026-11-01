//! The differential oracle (§3 of the design note): every corpus case whose
//! rows have no unknown fields runs through the stock `cel` crate, with its
//! error read as U, and must agree with the corpus.
//!
//! The canonical text itself is the CEL program, parsed with backticked
//! identifiers enabled (cel-go's `EnableIdentEscapeSyntax`). The row follows
//! the compatibility promise: each first segment is a variable, a dotted
//! path is nested maps with every intermediate map present, absent fields are
//! left out, and enums and addresses are strings. `under` is a function
//! whose body is the CEL `f == p || f.startsWith(p + "/")`.
//!
//! Two canonical spellings are not CEL as written: a backticked first
//! segment (CEL escapes only a selected field), and `has()` of a one-segment
//! path (CEL's `has` takes a selection). For those the oracle reprints the
//! condition with the row as one map `r`, each segment renamed `s0`, `s1`,
//! …, and `under` written out.

use std::{collections::HashMap, sync::Arc};

use cel::{Context, Env, ExecutionError, Value as Cel, extractors::This, parser::Parser};
use rigging_condition::{Condition, Field, Operand, Path, Type, Value};
use serde_json::Value as Json;

use crate::corpus::{Outcome, cases, field_types, row, run_front, truth};

/// Field names in the oracle's row: the segments themselves, or renamed.
struct Names(Option<HashMap<String, String>>);

impl Names {
    fn segment(&mut self, segment: &str) -> String {
        match &mut self.0 {
            None => segment.to_owned(),
            Some(names) => {
                let next = format!("s{}", names.len());
                names.entry(segment.to_owned()).or_insert(next).clone()
            }
        }
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

/// The row's variables: one per first segment.
fn oracle_row(names: &mut Names, types: &std::collections::BTreeMap<Path, Type>, row: &rigging_condition::Values) -> HashMap<String, Cel> {
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
    root.children.into_iter().map(|(k, v)| (k, v.into_cel())).collect()
}

/// Whether the canonical text is CEL as written: no path starts with a
/// backticked segment, and no `has()` takes a one-segment path.
fn written_in_cel(condition: &Condition) -> bool {
    let plain = |path: &Path| !path.to_string().starts_with('`');
    match condition {
        Condition::And(terms) | Condition::Or(terms) => terms.iter().all(written_in_cel),
        Condition::Not(inner) => written_in_cel(inner),
        Condition::Has(path) => plain(path) && path.segments().len() > 1,
        Condition::Compare { field, .. }
        | Condition::In { field, .. }
        | Condition::Member { field, .. }
        | Condition::Under { field, .. } => plain(&field.path),
        Condition::Field(field) => plain(&field.path),
        _ => true,
    }
}

fn parse(text: &str) -> Result<cel::parser::Expression, cel::parser::ParseErrors> {
    Parser::new().enable_ident_escape_syntax(true).parse(text)
}

// Behaviour (§3, §4.7): canonical text is CEL, but for the two spellings
// above; and over rows whose fields are present or absent, a stock CEL
// evaluator returns true for T, false for F and an error for U.
#[test]
fn cel_crate_agrees_with_the_corpus() {
    let env = Arc::new(Env::stdlib());
    let definition = Arc::new(parse("f == p || f.startsWith(p + \"/\")").unwrap());
    let (mut as_written, mut reprinted) = (0, 0);
    for case in cases() {
        let Outcome::Checked(checked) = run_front(&case) else { continue };
        let canonical = checked.to_string();
        let cel = written_in_cel(&checked);
        let program = match (cel, parse(&canonical)) {
            (true, Ok(program)) => Some(program),
            (true, Err(e)) => panic!("{}: canonical text is not CEL: {canonical}: {e}", case.name),
            (false, Ok(_)) => panic!("{}: canonical text unexpectedly CEL as written: {canonical}", case.name),
            (false, Err(_)) => None,
        };
        let types = field_types(&case.schema);
        for (i, row_json) in case.json["rows"].as_array().into_iter().flatten().enumerate() {
            if row_json.get("unknown").and_then(Json::as_array).is_some_and(|u| !u.is_empty()) {
                continue;
            }
            let row = row(&types, row_json);
            let mut context = Context::with_env(Arc::clone(&env));
            let definition = Arc::clone(&definition);
            context
                .add_function("under", move |This(f): This<Arc<String>>, p: Arc<String>| -> Result<Cel, ExecutionError> {
                    let mut scope = Context::default();
                    scope.add_variable_from_value("f", Cel::String(f));
                    scope.add_variable_from_value("p", Cel::String(p));
                    scope.resolve(&definition)
                })
                .unwrap();
            let (text, result) = match &program {
                Some(program) => {
                    for (name, value) in oracle_row(&mut Names(None), &types, &row) {
                        context.add_variable_from_value(name, value);
                    }
                    as_written += 1;
                    (canonical.clone(), context.resolve(program))
                }
                None => {
                    let mut names = Names(Some(HashMap::new()));
                    let text = names.print(&checked);
                    let program = parse(&text).unwrap_or_else(|e| panic!("{}: cel cannot parse {text}: {e}", case.name));
                    context.add_variable_from_value("r", Cel::Map(oracle_row(&mut names, &types, &row).into()));
                    reprinted += 1;
                    (text, context.resolve(&program))
                }
            };
            let got = match result {
                Ok(Cel::Bool(true)) => "T",
                Ok(Cel::Bool(false)) => "F",
                Ok(other) => panic!("{}: cel gave {other:?} for {text}", case.name),
                Err(_) => "U",
            };
            assert_eq!(truth(&Json::String(got.into())), truth(&row_json["expect"]), "{} row {i}: cel on {text}", case.name);
        }
    }
    assert!(as_written > 250 && reprinted > 20, "compared {as_written} rows as written and {reprinted} reprinted");
}
