# rigging

Shared leaf crates for the flotilla-org projects: flotilla, cleat, porthole,
jackstay, wheelhouse, binnacle and the rest. The rules and their reasons are in
[flotilla ADR 0068](https://github.com/flotilla-org/flotilla/blob/main/docs/adr/0068-shared-crates-live-in-rigging-and-http-uses-axum.md).

## Rules

- **Rigging depends on no project crate.** Projects depend on rigging, never the
  other way round, and never on each other's internals. `ci/no_project_deps.py`
  enforces this in CI.
- **A crate moves here when a second project needs it.** Until then it stays in
  the project that owns it.
- **Each consumer pins rigging once,** in its workspace `Cargo.toml`
  `[workspace.dependencies]`, with a single `rev`. Its crates use
  `workspace = true`.
- **`consumers.toml` lists every consumer and the revision it pins.** Update it
  in the same change that bumps a consumer.
- **HTTP serving uses axum** (hyper 1, tower 0.5) in every tokio project, and
  HTTP clients use reqwest.
- Publishing to a Cargo registry with semver versions comes later.

## Crates

| Crate | What it is |
|---|---|
| `flotilla-cbor` | The stack's CBOR profile: deterministic writers, safe readers, limits and framing |

## Gates

```bash
python3 ci/no_project_deps.py
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option, as flotilla and cleat are.
