# rigging-condition

One condition language for flotilla and binnacle: a strict subset of
[CEL](https://github.com/google/cel-spec), chosen so that CEL, SQLite `WHERE`
and SPARQL `FILTER` agree on it. The design, and the reasons for each rule, are
in flotilla's research note
[`docs/research/2026-10-31-condition-expression-language.md`](https://github.com/flotilla-org/flotilla/blob/main/docs/research/2026-10-31-condition-expression-language.md);
section numbers here refer to it. The crate has no project dependencies and no
I/O, and builds for `wasm32-unknown-unknown`.

A condition is a boolean expression over the named, typed fields of one row.
It never names its subject: choosing the row (an address, a `$var`, a table)
and combining several subjects is the consumer's job.

```text
state == "merged"
`latest-claim`.disposition == "changes pushed" && `updated-at` > timestamp("2026-10-01T00:00:00Z")
phase in ["Running", "Landing"] && !has(`closed-at`)
inbox.under("project:flotilla/convoy:fix-3774")
"kind:bug" in labels
```

```rust
let parsed = Condition::parse_strict(text)?;          // or parse_lenient
let checked = Checked::new(parsed, &schema)?;          // CheckError: UnknownField, TypeMismatch, …
let bound = checked.bind(&variables)?;                 // when the schema declares variables
let truth = bound.evaluate(&row);                      // Truth::{T, F, U}
let reason = bound.first_failing(&row);                // Option<&Condition>, printed canonically
let (sql, params) = bound.to_sql(&column_map)?;
```

## Modules

| Module | Contents |
|---|---|
| `syntax` | Lexer, strict and lenient parsing, the canonical printer (`Display`) and the limits |
| `ast` | `Condition` (n-ary `And`/`Or`, `Not`, `Has`, `Compare`, `In`, `Member`, `Under`, `Field`, `Bool`), `Field`, `Path`, `Variable`, `Literal`, `Timestamp`, `Duration` |
| `check` | `Schema` (field → `Type` and nullable flag, declared variables, the address-literal hook), the type rules, `Checked<Condition>` and `bind` |
| `eval` | `Row`, `Lookup` (present, absent or unknown), `Truth`, `evaluate`, `first_failing`, and `under` |
| `sql` | SQLite text and parameters through a store's `ColumnMap`; no `rusqlite` dependency |

## Parsing

There is one parser. Lenient parsing accepts any CEL spelling of a condition
in the subset: whitespace and `//` comments, single, raw and triple-quoted
strings, every CEL escape, hex integers, redundant parentheses, timestamps
with an offset. Strict parsing accepts only canonical text: it is lenient
parsing plus the rule that the text equals the canonical print of what it
parsed to. So `parse_strict(print(ast)) == ast`, and canonical text is the one
spelling for storage, interned keys and the wire. `Condition` serializes with
serde as that text.

Erratum against the note: its grammar has `Unary = "!" Atom`, and an atom
can be a whole comparison, so `!` takes the comparison after it. The parser
follows the note: `!count == 1` is `!(count == 1)`, where CEL reads
`(!count) == 1`, a type error for an int. For a bool field the two readings
agree (`!draft == true` either way). Canonical text never meets this, since
`!` before anything but a field, `has(…)` or `under(…)` prints with
parentheses.

Canonical text (§4.7): one space around binary operators, none after `!`;
strings double-quoted with `serde_json`'s escaping; floats as Rust's `{:?}`
(`1e21`, `1e-7`, `0.0` for `-0.0`); `timestamp("…Z")` in UTC and
`duration("…s")`, fractions trimmed; segments bare when they are a CEL
identifier and backticked otherwise; `&&` and `||` n-ary, an `||` inside `&&`
parenthesised, and `!` followed by parentheses unless its operand is a field,
`has(…)` or an `under` call. Nothing is reordered.

Canonical text is CEL as written, with backticked identifiers enabled
(cel-go's `EnableIdentEscapeSyntax`), with two exceptions. CEL escapes only a
selected field, so a path whose first segment needs backticks
(`` `updated-at` ``) is not CEL, and CEL's `has` takes a selection, so
`has(state)` is not. Both read as CEL once the row is one map `r`
(`` r.`updated-at` ``, `has(r.state)`), which is how the oracle runs them.

The parser enforces CEL's minimum limits before any schema is read: 32 terms
in one `&&` or `||` run (after flattening), 32 list elements, 12 nested
parentheses or `!`, 12 segments in a name, and 4,096 bytes of text.

A timestamp has at most six fractional digits and lies in years 1 to 9999. A
duration uses `h`, `m`, `s`, `ms` and `us`, is a whole number of microseconds,
and lies within CEL's ±315,576,000,000 seconds. Both are checked as the
literal is parsed.

## Checking

Every field must be declared, and every literal must fit its field's type:
`bool`, `int`, `number` (takes an int or a float literal), `string`,
`enum{…}` (a string in the set), `address`, `timestamp`, `duration`,
`map(string, T)` and `list(T)` of scalars. Ordering is refused on `bool`,
enums and addresses; `in` needs a non-empty list; the whole condition is
`bool`. A field path may not be a prefix of another, since a dotted path names
one field rather than walking maps.

`Schema::validate_addresses` sets the hook that validates address literals
and bound address values. `under` is defined on canonical text alone, so a
consumer with address fields should set it to its canonical-address check.

Declared variables (`row.convoy`, `param.limit`, `revision`) appear only on
the right. `bind` substitutes them as literals, checking the value's type;
`evaluate` panics on a variable still unbound, since that is the consumer's
bug; `try_evaluate` returns it as an error instead, and is the one to call
where a panic is unwelcome, such as the wasm build. `to_sql` reports it as
`SqlError::UnboundVariable`.

`Checked::new` also applies the parser's limits to a tree built in code,
and refuses one more than 32 levels deep, so evaluation, translation and
printing never recurse without a bound. It refuses an `&&` or `||` of fewer
than two terms, or one directly holding another of its kind (`shape`): the
parser never builds these, and their print parses to a different tree. So
every checked condition has canonical text that parses back to it.

## Evaluation

`Row::get` looks a field up by its full declared path and answers present,
absent or unknown. Absent means the row knows there is no value (a NULL cell,
a NaN number, no such map key); unknown means it cannot say (an unobserved or
stale subject). Any comparison that reads an absent or unknown field gives U.
`has(f)` gives T, F, or U when unknown. `!`, `&&` and `||` use the strong
Kleene tables. What U means is the consumer's decision (§4.5).

`f.under(p)` is T when `f == p` or `f` starts with `p + "/"` (§4.6), so
`…/convoy:demo2` is not under `…/convoy:demo`.

`first_failing` gives the first top-level conjunct that is not T, or the whole
condition when it is not a conjunction: the reason a verb's `when` failed.
Like `evaluate`, it panics on a variable still unbound.

## SQL

`to_sql` gives a `WHERE` expression and its parameters. Every literal is a
parameter in the column's storage type: bools as 0 or 1, timestamps and
durations as integer microseconds, enums as their stored code. Field paths
never appear in the SQL; each resolves through the store's `ColumnMap` to:

- `Column::Value`: a cell, optionally with a code per enum value;
- `Column::Interned`: the id of a string in a table with a `UNIQUE(domain, text)` index;
- `Column::List`, `Column::Map`: a child-table template with one `{}` parameter.

A NULL cell gives NULL wherever the evaluator gives U, so the `WHERE` keeps
exactly the rows that evaluate to T. `under` is one index range plus a residual
test (`f >= p AND f < p || '0' AND (f = p OR f >= p || '/')`), sound under
`BINARY` collation. Interned forms add `OR (e IS NULL AND NULL)` to their
subquery test, because SQLite gives false rather than NULL for `NULL IN` an
empty subquery. Lists and
maps in child tables are never absent: no elements is empty.

## Conformance

`corpus/corpus.json` is the language-neutral conformance corpus; its
[README](corpus/README.md) gives the format. `tests/conformance` runs it:

- every case through the parsers, printer, checker and evaluator;
- SQL-marked cases against in-memory SQLite, including the pinned query plans;
- every case without unknown fields through the `cel` crate (0.15.0, which runs
  cel-spec v0.25.3), with its error read as U: the differential oracle of §3.
  The program is the canonical text itself, but for the two exceptions above;
- a Hegel property that strict-parsing the canonical print of a generated AST
  gives the AST back, and that the limit and shape checks refuse exactly the
  trees for which it does not;
- Hegel properties that timestamp parsing and printing agree with `chrono`
  over CEL's whole range.

The `cel` and `rusqlite` crates are dev-dependencies only.

## Deferred

Field-to-field comparison, arithmetic, string functions, more macros and
`now` are left out (§4.4), not excluded. Each can be added later as a CEL
construct with an exact SQLite and SPARQL mapping and corpus cases;
`Condition`, `Literal`, `Type` and the error enums are `#[non_exhaustive]` for
that.

Evaluation walks the checked AST; a compiled form can come behind the same
API when a hot path needs it, checked against the same corpus.
