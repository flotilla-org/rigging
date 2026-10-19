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

### Runtime limits and packaging

The four runtime/testkit crates inherit the workspace's Rust 2024 edition and
repository metadata and are `publish = false`: consumers use pinned Git revisions
until registry publication and versioning are introduced. Older crates may retain
their original edition independently.

On Unix, process deadlines terminate a process group, allow
`COMMAND_TERMINATION_GRACE` for SIGTERM cleanup, then escalate to SIGKILL and reap
the leader. On non-Unix platforms, timeout cancellation kills only the child
leader immediately; descendants are not supervised as a group. The non-Unix
`sysinfo` free-space implementation is selected by the target platform. Unix
subprocess scenarios do not validate Windows behavior.

HTTP `execute` buffers an unlimited body and returns non-2xx responses normally.
`execute_to_file` streams successful bodies, leaves existing destinations alone
on non-2xx responses, and can leave a truncated/partial destination on I/O or
stream errors. Use a temporary destination and publish it after success when an
atomic file is required. Constructors document their TLS/client initialization
panics. Transport errors retain the extracted `String` signatures for consumer
and replay compatibility.

The replay testkit uses `serde_norway` for YAML (rather than the source project's
`serde_yml` 0.0.12, affected by
[RUSTSEC-2025-0068](https://rustsec.org/advisories/RUSTSEC-2025-0068)). Existing
fixture fields and flat/multi-round formats remain readable. The binary-resolution
probe has a neutral shell marker by default; `resolve_binary_path_with_marker`
lets consumers preserve their recorded argv marker without editing fixtures.

## Gates

```bash
python3 ci/no_project_deps.py
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option, as flotilla and cleat are.
