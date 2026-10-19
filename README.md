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
| `rigging-tls` | Rustls provider selection and reqwest builders with a default User-Agent |
| `rigging-process` | Command execution, environment variables, bounded filesystem probes, scan cache and binary/version probes |
| `rigging-http-client` | Injectable HTTP execution with a streaming reqwest implementation |
| `rigging-replay-testkit` | Dev-only record/replay sessions, masks, YAML fixtures, mock runners and axum HTTP stand-ins |

## Runtime and replay seams

`ProcessCommandRunner` executes local processes without project policy. A consumer
that needs a pre-spawn check constructs `ProcessRunner::new(guard)` with a
`CommandGuard`. The guard runs before every subprocess spawn, including streams,
existence probes, deadlines and long-lived commands. Flotilla keeps its Git
configuration guard and helper/atomic-write shell scripts in its own runtime
crate. The guard can supply the consumer's runtime-directory namespace; the
unconfigured runner uses `rigging`.

Command and HTTP replay use the same `ChannelLabel` types (reexported by the HTTP
crate). `ChannelRequest::Extra { namespace, key }` and
`ChannelLabel::Extra(namespace, label)` reserve independent FIFO queues for
consumer-defined channels. HTTP clients use reqwest requests and return standard
`http::Response<bytes::Bytes>` values.

Use `rigging-replay-testkit` only in `[dev-dependencies]`; its HTTP stand-in starts
a loopback listener and is test infrastructure. `Session` defaults to command and
HTTP channels. A consumer can use `Session<MyChannel>` by implementing
`ExtraChannel`: serde owns the channel's existing YAML fields, `channel_label`
defines its queue, and `transform` masks/unmasks payload values. Implement the
extension as a serde internally tagged enum with a `channel` discriminator;
`Interaction::Extra(value)` is untagged so it adds no YAML wrapper. Labels stay
stable during masking. This lets Flotilla keep its `gh_api` schema and adapters
outside rigging while replaying the existing fixtures unchanged.

Sessions preserve flat and multi-round fixture formats, default command exit
status, per-channel FIFO order, barriers and completion checks. Extra-channel
adapters use the public `Session::next` and `Session::record` operations; command
and HTTP wrappers accept the same extended session. Call `finish()` to save a
recording or reject unconsumed replay interactions. `MockRunner` and
`http_contract::StandIn` are reusable process/network boundary collaborators.

The Flotilla migration and boundary/build-graph reanchoring are tracked in
[flotilla#3518](https://github.com/flotilla-org/flotilla/issues/3518).

## Gates

```bash
python3 ci/no_project_deps.py
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option, as flotilla and cleat are.
