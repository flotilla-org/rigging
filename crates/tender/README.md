# Tender

Moved from flotilla at `2378973cbcbad2b4a265ec8015db23e902184948`
([flotilla-org/flotilla#4365](https://github.com/flotilla-org/flotilla/issues/4365)),
with no change in behaviour: its SSH adapter now drives SSH through
`rigging-ssh`, and its byte types are `rigging-stream`'s.

## Publications and Bindings

The model follows the [flotilla#3995 resolution](https://github.com/flotilla-org/flotilla/issues/3995#issuecomment-6953784738)
and the Publication and Binding entries in flotilla's `CONTEXT.md`; the
contract suite in `tests/contracts.rs` states each rule against both adapters.

- **Identity is scope and name.** A `PublicationId` is a `Scope` (a vessel, or
  the publishing instance for a host endpoint) plus a name chosen by whoever
  asks. The publisher and its route are not part of it. A `Grant` names who may
  publish under a scope; the host publishes under any scope on its own
  authority. Publishing an identity whose publisher is unavailable or withdrawn
  takes it over at the next generation, whoever was there before; a live
  incumbent wins with `LivePublisher`. Withdrawal is not terminal: any
  publisher granted the scope may publish a withdrawn identity again,
  including one that is not the publisher that withdrew it, since withdrawal
  ends a publisher's claim rather than the identity. Streams already open stay
  on the old route and break with it; nothing is replayed or moved.
- **Bindings.** `bind` gives a Local Endpoint keyed by publication identity
  and the instance that bound it. Its streams are authorised as that
  instance, and every local client of the instance shares it. Its `BindingState` is available
  (with its `Route`: the carrying instance and any relay), unavailable (with
  an `UnavailableReason`) or revoked (the audience or grant no longer admits
  the caller). The state is for display; an unavailable or revoked Binding
  keeps its endpoint, which closes fresh connections promptly without
  injecting bytes.
- **Labels.** Each publication carries a protocol `Label` and display text.
  Tender never interprets either; the application's handshake checks the label.
- **Default audience.** A request with no audience gets the host's Trusted
  Group (`MemoryTender::set_trusted_group`), within the grant's ceiling, and
  follows the group as it changes. The host's own publications never reach
  beyond its group.

## The daemon

`tender serve` runs one instance per OS account (`daemon::serve`, Unix only).
Directories come from `daemon::Paths::from_env`: configuration and state
follow `rigging-paths` (`TENDER_ROOT`, then XDG), and sockets live in the
runtime directory, `$TENDER_ROOT/runtime`, else `$XDG_RUNTIME_DIR/tender`,
else `tender-<uid>` in the temporary directory. All three are created 0700.

- **State:** the instance key (`identity`) and the authority store, as for
  `ssh::Server::open`. The key is the instance's identity for as long as the
  state directory lasts.
- **`runtime/peer`:** the Tender protocol socket other instances reach, over
  SSH or on this machine. Trusted Group members may browse and connect;
  anyone else is refused.
- **`runtime/control`:** the control API, HTTP over the Local Endpoint
  (`rigging-http-serve`), with JSON or CBOR bodies (`rigging-http-wire`). Its
  paths and bodies are in `api`:

  | Route | Body | Answer |
  |---|---|---|
  | `GET /v1/identity` | | `Instance`: public key, fingerprint, peer socket |
  | `GET /v1/publications` | | every `PublicationEntry` this instance hosts |
  | `POST /v1/publish` | `PublishEndpoint` | the `Publication`; 409 `live_publisher` while one is live |
  | `POST /v1/withdraw` | `PublicationId` | 404 unless this instance published it; a publication already withdrawn or taken over is forgotten with its error, so a repeat answers 404 |
  | `GET /v1/trusted` | | the Trusted Group, as `TrustedMember`s |
  | `POST /v1/trusted` | `TrustedInstance` | adds or replaces a member |
  | `POST /v1/trusted/remove` | `Untrust` | 404 unless a member |
  | `GET /v1/diagnostics` | | `Diagnostics` |

- **`config.toml`** (read at start) lists `[[publication]]`s, each with an
  optional `scope` (default `tender/<fingerprint>`), `name`, `label`,
  `display`, `endpoint` and optional `audience`, and `[[grant]]`s letting
  another instance's key publish into this one under a `scope`, for the
  Trusted Group. Grants no longer configured are revoked at start.
- **`trusted.toml`** holds the Trusted Group as `[[instance]]`s with `key`,
  `name` and an optional `route`. The daemon rewrites it when the group
  changes through the control API.

The daemon publishes a local socket as itself and never starts or stops the
service behind it. A connection that cannot open the endpoint makes the
publication unavailable; the daemon checks unavailable endpoints once a second
and publishes again, at the next generation, once one answers. A publication
taken over by another publisher, or withdrawn, is no longer the daemon's.
Shutting down leaves its publications unavailable and their identities kept;
publications from `config.toml` are published again at the next start, and
those from the control API wait for their publisher.

```toml
# config.toml
[[publication]]
name = "cleat"
label = "cleat"
display = "Desktop cleat"
endpoint = "/run/user/1000/cleat/default/socket"

[[grant]]
grantee = "<helper fingerprint>"
scope = "vessel/7"
```

## SSH adapter

`ssh::Server` hosts the slice-1 publication authority behind a private Unix
listener inside a required mode-0700 parent directory. `Server::publish_endpoint` publishes an existing Unix socket and pumps
ordinary application bytes; it never starts or cleans the application's daemon.
`Server::open(socket, private_state_directory, clock)` owns a durable authority:
it loads or creates `identity`, locks `authority.lock`, and loads the versioned
`authority.json`. The state directory must exist with mode 0700. `Server::bind`
remains the explicit ephemeral adapter/test constructor. Host-side grants,
browse/connect policy and the Trusted Group are controls on `server.policy`;
they return errors if durable policy cannot be saved.

`ssh::Identity::load_or_create` persists a separate Ed25519 instance key with
mode 0600, atomically installing a complete synced file without replacement. Existing readable-by-group keys are refused. Enrolment supplies the remote key's SHA-256 fingerprint out of band.
SSH host authentication is additional transport authentication, not that pin.
The bounded, version-labelled handshake proves possession of both instance
keys with fresh challenges. Every channel authenticates before processing a
control request; callers cannot send a Session identity assertion to the host.

`ssh::Forward::start(target, remote_socket)` holds a `rigging-ssh` session and
its stream-local forward (`SshSession::forward_unix`). The `rigging_ssh::Target`
uses ordinary SSH account and ProxyJump configuration, or a pinned host key and
identity. rigging-ssh runs batch authentication, keeps the forward in a private
directory and never runs a remote command for it. `Forward::stop` closes only
that SSH session.

`ssh::SshTender` implements `Tender` over that forward, or over any `Dial`
(`SshTender::with_dial`). A dialer opens one fresh byte stream toward a named
instance; it only carries bytes, so the handshake still authenticates whatever
answers. `UnixDial` dials one socket path, such as a forward. Supply only the
caller identities this client may use, and the pinned host fingerprint. Control records
are capped at 64 KiB and the server admits at most 256 live channels; after an authorized Open response each connection becomes
a raw bidirectional stream. Each accepted Binding connection authenticates and
checks host authority anew. Stream-local SSH channels provide multiplexing and
flow control; local byte pumps use bounded buffers and preserve directional EOF.
No control/error bytes enter an ordinary bound application connection.

`bind` creates one private, user-only Unix socket per caller and publication
identity. It stays bound for the adapter's lifetime,
including while the publication is unavailable, withdrawn or revoked, and then
closes fresh connections promptly. Expiry permits established streams to
finish; explicit revocation closes streams at the host. Returned addresses
belong to this adapter's lifetime.
The hosting runtime persists policy and identity, never routes or streams.
Consumer restart-persistent binding configuration remains the hosting
application's responsibility.

After SSH loss, retained browse/watch metadata becomes Unavailable rather than
Withdrawn. `replace_route` supplies a restored forward; watch re-establishes its
control subscription and fresh connects use that route. Existing application
streams are never migrated or replayed. A remote publisher holds a separate
registration control channel: transient Accept failures retry with backoff from
100 ms to eight seconds while that lease is healthy, but losing it reserves the identity and closes its Published
receiver. The owner explicitly publishes again to obtain the new generation's
Lease; an automatic republish would silently stale the caller's existing Lease.
Every connection to a Binding checks admission at the host as it opens. Endpoint-open failure marks the publication Unavailable and closes its
streams; it does not manage the application process. The host's
publication authority and the route are separate, so a consumer SSH outage does
not withdraw a healthy host-side publication.

A session naming a relay in `Session::via` dials that relay, pins it with the
caller's own handshake, and asks it to carry the stream to the pinned host.
The relay admits callers holding connect authority in its own policy, then
authenticates to the next instance as itself. `Server::route_relays` supplies
the hosting application's `Router`, which names each next hop and dials it;
Tender never stores or learns routes. A single-path `UnixDial` cannot reach a
distinct relay, so relayed sessions need a dialer that resolves instances.

The host accepts only a relay it trusts (`trust_intermediary`), records it as
the session's `via` from the relay's own handshake, and then authenticates the
caller end to end over the splice. In a chain the host sees only the relay that
delivered the caller; trusting an earlier relay is not enough. A chain is
bounded at eight hops, so a routing loop fails as Unavailable. Refusals reach
the caller unchanged, while a hop that stalls surfaces as the caller's own
Deadline. Like a direct connect, an open relayed stream has no idle bound and
holds a channel permit until either side closes; idle policy belongs to the
hosting application. Relays see plaintext: each link's transport, such as SSH,
provides confidentiality.

Container outward publication is slice 3. Windows local adapters and Flotilla
resource consumption are later slices. Cleat reaches a Tender Binding only
through its connect-only `packets --socket` and `attach --socket` clients
([flotilla-org/cleat#303](https://github.com/flotilla-org/cleat/pull/303)). Its
other commands select a daemon by runtime layout and may start one, so they
cannot target an arbitrary socket. `ci/tender/README.md` describes the real-SSH proof.

## Hosting clocks and storage

Inject `runtime::Clock` into `MemoryTender::hosted` or `Server::open`. Ticks are
milliseconds within the clock's opaque epoch; a grant is invalid at
`expires_at <= current_tick`. Sample the injected clock to issue a deadline,
using checked addition for the desired lifetime. `Clock::read` is fallible;
a clock error refuses work and closes streams without poisoning the authority
lock. Restore the clock and reopen the host to resume. Every publish, connect and
Binding open samples the clock under the authority lock, without publisher or
operator activity. Browse/watch and the server's maintenance loop also observe
expiry. Mere expiry retires the identity and refuses new work while established
streams finish. Explicit revocation closes even streams grandfathered by expiry.

On Linux use `runtime::BootClock::new()`: its boot ID and `CLOCK_BOOTTIME` ticks
survive process restarts and include suspend time. Reboot changes the epoch and
expires prior grants. On other platforms inject an equivalent boot-scoped clock,
or use `ProcessClock` with conservative expiry of all prior grants on restart.
Epoch mismatch or clock regression fails closed, never rebases deadlines into a
fresh lifetime. The store remembers the sampled tick high-water mark.

`runtime::Store` has memory and atomic file adapters. File saves sync a private
temporary file, atomically replace the record, and sync the directory before
acknowledgment. One host owns each store; an advisory file lock rejects competing
processes. Storage failure refuses subsequent work and closes live streams;
operators must restore storage and reopen the authority. Unreadable, malformed,
unsupported-version, or identity-mismatched state is refused, never overwritten
as an empty authority.

The version-2 Tender-owned document stores host fingerprint, grants, capability
sets, intermediary trust, the Trusted Group, publication metadata keyed by scope
and name, requested audiences, expiry, reserved/withdrawn state and generations.
Available records are written as reserved Unavailable. No live route,
registration sender, stream or application-domain type is serialized. The
independent instance key stays in `identity`. The fixed
`tests/fixtures/authority-v1.json` and `authority-v2.json` are compatibility
contracts: future decoders must read both; add defaults/aliases when evolving
stored records rather than replacing a fixture. Version 1's numeric identities
load as scope and name, keeping each name's latest record at the highest
generation any reached; its replacement assignments are dropped, since a grant
for the scope now admits a takeover. Slice 2 stored only the key, whose format
is unchanged; an absent policy document bootstraps empty, default-deny policy.
