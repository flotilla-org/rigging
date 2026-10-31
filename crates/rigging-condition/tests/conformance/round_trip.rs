//! The canonical printer and the strict parser are inverses (§4.7).

use hegel::{TestCase, generators as gs};
use rigging_condition::{
    CheckError, Checked, Condition, Duration, Field, Limit, Literal, Operand, ParseError, ParseErrorKind, Path, Relop, Schema, Timestamp,
    Variable,
};

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

/// A short length from `min`, or now and then 32 or 33, either side of the limit.
fn length(tc: &TestCase, min: usize) -> usize {
    if tc.draw(gs::weighted_booleans(0.15)) {
        tc.draw(gs::integers::<usize>().min_value(32).max_value(33))
    } else {
        tc.draw(gs::integers::<usize>().min_value(min).max_value(4))
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
            let len = length(tc, 0);
            Condition::In { field: field(tc), list: (0..len).map(|_| operand(tc)).collect() }
        }
        3 => Condition::Member { key: string(tc), field: field(tc) },
        4 => Condition::Under { field: field(tc), prefix: operand(tc) },
        5 => Condition::Field(field(tc)),
        6 => Condition::Bool(tc.draw(gs::booleans())),
        7 => Condition::Not(Box::new(condition(tc, depth - 1))),
        kind => {
            let and = kind == 8;
            let len = length(tc, 2);
            // A run long enough to cross the term limit holds only leaves.
            let depth = if len > 4 { 1 } else { depth };
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

// Behaviour (§4.7, §4.2): print-then-parse returns exactly the AST, so the
// strict parser accepts every canonical print and nothing is lost in
// printing; and `check_limits`, which `Checked::new` applies to trees built
// by hand, refuses exactly the trees whose print the parser refuses for a limit.
#[hegel::test(test_cases = 500)]
fn strict_parse_of_print_is_identity(tc: TestCase) {
    // The tree under 0 to 13 wrappings, each adding one or two to the nesting
    // count, so some wrapping is the first to cross the limit of 12: `!`
    // (two, or one over a field, has or under), or `(… || true) && true`
    // (one), which mixes the parities.
    let mut ast = condition(&tc, 4);
    for _ in 0..=13 {
        let text = ast.to_string();
        match (ast.check_limits(), Condition::parse_strict(&text)) {
            (Ok(()), parsed) => assert_eq!(parsed.as_ref(), Ok(&ast), "{text}"),
            (Err(limit), Err(ParseError { kind: ParseErrorKind::Limit(parsed), .. })) => assert_eq!(limit, parsed, "{text}"),
            (Err(limit), parsed) => panic!("check_limits gave {limit:?}, the parser {parsed:?}: {text}"),
        }
        ast = if tc.draw(gs::booleans()) {
            Condition::Not(Box::new(ast))
        } else {
            let term = if matches!(ast, Condition::Or(_)) { Condition::Not(Box::new(ast)) } else { ast };
            Condition::And(vec![Condition::Or(vec![term, Condition::Bool(true)]), Condition::Bool(true)])
        };
    }
}

// Behaviour: a hand-built tree too deep for the parser's counts to see (a
// same-kind `&&` chain prints flat) is refused as a limit before anything
// recurses over it, and so is a deep `!` chain. The depth is one that the
// derived `Drop` survives but the printer and checker would not.
#[test]
fn deep_hand_built_trees_are_refused() {
    for and in [true, false] {
        let mut tree = Condition::Bool(true);
        for _ in 0..5_000 {
            tree = if and { Condition::And(vec![Condition::Bool(true), tree]) } else { Condition::Not(Box::new(tree)) };
        }
        assert_eq!(Checked::new(tree, &Schema::new()).err(), Some(CheckError::Limit(Limit::Depth)));
    }
}
