# Condition language conformance corpus

Cases for the condition language of `rigging-condition`. Every
implementation (the Rust crate, binnacle's wasm build, any later native
evaluator) should pass them; `tests/conformance` runs them against the Rust
crate. `corpus.json` is plain JSON with one case per line.

## Layout

- `schemas`: named schemas that cases refer to by name.
- `cases`: hand-written cases, one or more for each rule of §4 of the design
  note: canonical spelling, lenient spellings, syntax and literal errors,
  limits, checker errors, absent and unknown values under every operator, the
  Kleene tables, ordering by type, `under` on segment boundaries, reasons,
  bound variables, hostile identifiers and query plans.
- `cel_spec`: cases generated from cel-spec at
  `21ec6f4e52e8d694687ff9ed7408d3eccbb955d7` by
  `cargo run -p rigging-condition --example cel_spec_slice -- <cel-spec checkout>`.
  The generator reads `tests/simple/testdata/{logic,comparisons,fields,lists,timestamps}.textproto`,
  turns each literal on the left of a comparison or `in` into a field holding
  that literal, and keeps the tests with a boolean result that check against
  the schema this builds. Regenerate rather than edit them.

## Schemas

- `fields`: canonical path text to `{"type": T, "nullable": bool}`. Types are
  `"bool"`, `"int"`, `"number"`, `"string"`, `"address"`, `"timestamp"`,
  `"duration"`, `{"enum": [values]}`, `{"map": T}` and `{"list": T}`.
- `variables`: canonical variable text to a type.
- `addresses`: `"canonical"` installs the corpus's address check: `/`-separated
  `kind:value` segments, the kind starting with a lowercase letter and holding
  only lowercase letters, digits and `-`, the value non-empty. It stands in for
  flotilla's canonical-address validation.
- `storage`: for SQL cases, per field: `"interned"` (the cell holds an id in
  `strings(id, domain, s)` with `UNIQUE(domain, s)`, domain `ad`), `{"codes":
  {value: code}}` for an enum, `"none"` (the store has no column for it), or
  `"bad-template"` (a list whose template has no `{}`, a store bug).
  Other scalars are an indexed cell in table `t`; lists and maps are child
  tables. Columns are named `c<i>` by the field's position in path order.

A case's `schema` is a schema's name or an inline schema.

## Cases

- `name`.
- `input`: the text, or a list of parts, each a string or
  `{"repeat": s, "count": n}`, concatenated.
- `lenient`: `true` parses leniently; otherwise strictly, and the input is its
  own canonical print.
- `canonical`: for a lenient case, the canonical print. Printing it and
  strict-parsing it again gives the same AST.
- Exactly one of these errors, or none:
  - `parse_error`: `syntax`, `literal`, `limit` or `not-canonical`;
  - `check_error`: `unknown-field`, `unknown-variable`, `variable-as-field`,
    `type-mismatch`, `ordering`, `invalid-literal`, `empty-list` or `limit`;
  - `bind_error`: `unknown-variable`, `type-mismatch` or `invalid-literal`.
- `bindings`: variable text to a value, bound before evaluation.
- `rows`: each `{"values": {path: value}, "unknown": [path], "expect": "T" | "F" | "U", "reason": text | null}`.
  A field not in `values` or `unknown` is absent. Values are JSON in the
  field's type: timestamps as RFC 3339 strings, durations as CEL duration
  strings, a number as `"NaN"` for NaN. `reason`, when present, is the
  canonical text of the first top-level conjunct that is not T, or `null`.
- `sql`: run against in-memory SQLite, which must keep exactly the rows that
  expect T. It may hold `error` (`unknown-column`, `unbound-variable`,
  `missing-code`, `unsupported` or `bad-template`), `text` (the exact SQL) and `plan` (the
  `detail` lines of `EXPLAIN QUERY PLAN SELECT id FROM t WHERE …`, from the
  bundled SQLite of the pinned `rusqlite`). SQL rows have no unknown fields.

Error codes are the Rust crate's `code()` names. An implementation in another
language may name errors differently, but must refuse exactly these inputs at
the same stage.

## The differential oracle

Every case that checks, and every row without unknown fields, also runs
through the `cel` crate under the conventions of §3: the row is one map with
absent fields left out and intermediate maps present, enums and addresses are
strings, `under` is `f == P || f.startsWith(P + "/")`, and an error is U.
`cel` 0.15 does not parse backticked identifiers, so the oracle renames each
field segment.
