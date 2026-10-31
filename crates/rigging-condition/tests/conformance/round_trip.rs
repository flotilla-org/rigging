//! The canonical printer and the strict parser are inverses (§4.7).

use hegel::{TestCase, generators as gs};
use rigging_condition::{Condition, Duration, Field, Literal, Operand, Path, Relop, Timestamp, Variable};

// Segments that cover each printing rule: plain selectors, keywords and
// reserved words (backticked), names that are only escaped identifiers, and
// names the grammar gives a meaning to elsewhere (has, under, timestamp).
const SEGMENTS: &[&str] = &[
    "state",
    "a",
    "_x",
    "Z9",
    "latest-claim",
    "updated-at",
    "in",
    "true",
    "null",
    "if",
    "as",
    "has",
    "under",
    "timestamp",
    "x.y",
    "a b",
    "a/b",
    "9lives",
];
const VARIABLE_ROOTS: &[&str] = &["row", "param", "revision"];
const RELOPS: &[Relop] = &[Relop::Eq, Relop::Ne, Relop::Lt, Relop::Le, Relop::Gt, Relop::Ge];

fn path(tc: &TestCase, first: &[&str]) -> Path {
    let len = tc.draw(gs::integers::<usize>().min_value(1).max_value(3));
    let mut segments = vec![tc.draw(gs::sampled_from(first.to_vec())).to_owned()];
    for _ in 1..len {
        segments.push(tc.draw(gs::sampled_from(SEGMENTS.to_vec())).to_owned());
    }
    Path::new(segments).unwrap()
}

// Any text: control characters, quotes, backslashes and characters outside
// the BMP all have their own escaping rule.
fn string(tc: &TestCase) -> String {
    tc.draw(gs::text().max_size(6))
}

fn field(tc: &TestCase) -> Field {
    let path = path(tc, SEGMENTS);
    if tc.draw(gs::weighted_booleans(0.2)) { Field::indexed(path, string(tc)) } else { Field::new(path) }
}

fn literal(tc: &TestCase) -> Literal {
    match tc.draw(gs::integers::<u8>().max_value(5)) {
        0 => Literal::String(string(tc)),
        1 => Literal::Int(tc.draw(gs::integers::<i64>())),
        2 => Literal::Float(tc.draw(gs::floats::<f64>().allow_nan(false).allow_infinity(false))),
        3 => Literal::Bool(tc.draw(gs::booleans())),
        // The whole of CEL's ranges, so both ends and the epoch are reachable.
        4 => Literal::Timestamp(
            Timestamp::from_unix_micros(
                tc.draw(gs::integers::<i64>().min_value(-62_135_596_800_000_000).max_value(253_402_300_799_999_999)),
            )
            .unwrap(),
        ),
        _ => Literal::Duration(
            Duration::from_micros(tc.draw(gs::integers::<i64>().min_value(-315_576_000_000_000_000).max_value(315_576_000_000_000_000)))
                .unwrap(),
        ),
    }
}

fn operand(tc: &TestCase) -> Operand {
    if tc.draw(gs::weighted_booleans(0.2)) {
        Operand::Variable(Variable::new(path(tc, VARIABLE_ROOTS)).unwrap())
    } else {
        Operand::Literal(literal(tc))
    }
}

/// A condition in the parser's normal form (n-ary nodes never directly hold
/// their own kind), at most `depth` connectives deep. Each connective adds at
/// most two to the parser's nesting count, so depth 4 stays inside the limit.
fn condition(tc: &TestCase, depth: usize) -> Condition {
    let top = if depth == 0 { 6 } else { 9 };
    match tc.draw(gs::integers::<u8>().max_value(top)) {
        0 => Condition::Has(path(tc, SEGMENTS)),
        1 => Condition::Compare {
            field: field(tc),
            op: RELOPS[tc.draw(gs::integers::<usize>().max_value(RELOPS.len() - 1))],
            operand: operand(tc),
        },
        2 => {
            let len = tc.draw(gs::integers::<usize>().max_value(4));
            Condition::In { field: field(tc), list: (0..len).map(|_| operand(tc)).collect() }
        }
        3 => Condition::Member { key: string(tc), field: field(tc) },
        4 => Condition::Under { field: field(tc), prefix: operand(tc) },
        5 => Condition::Field(field(tc)),
        6 => Condition::Bool(tc.draw(gs::booleans())),
        7 => Condition::Not(Box::new(condition(tc, depth - 1))),
        kind => {
            let and = kind == 8;
            let len = tc.draw(gs::integers::<usize>().min_value(2).max_value(4));
            let terms = (0..len)
                .map(|_| match condition(tc, depth - 1) {
                    Condition::And(inner) if and => Condition::Not(Box::new(Condition::And(inner))),
                    Condition::Or(inner) if !and => Condition::Not(Box::new(Condition::Or(inner))),
                    term => term,
                })
                .collect();
            if and { Condition::And(terms) } else { Condition::Or(terms) }
        }
    }
}

// Behaviour (§4.7): print-then-parse returns exactly the AST, so the strict
// parser accepts every canonical print and nothing is lost in printing.
#[hegel::test(test_cases = 500)]
fn strict_parse_of_print_is_identity(tc: TestCase) {
    let ast = condition(&tc, 4);
    let text = ast.to_string();
    assert_eq!(Condition::parse_strict(&text), Ok(ast), "{text}");
}
