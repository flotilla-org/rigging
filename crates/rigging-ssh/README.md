# rigging-ssh

`SshSession` covers non-PTY exec, opening remote Unix streams, accepting streams
on a remote Unix listener, and session closure. `SshListener` is the accept port.
Both are object-safe async traits. `rigging-stream` owns the shared byte types.
PTY attach remains native `ssh -tt` in the consumer.

The Unix `OpenSsh` backend requires OpenSSH 8.7 or newer
([release notes](https://www.openssh.org/txt/release-8.7)). It explicitly sets
`ForkAfterAuthentication=no` so ambient configuration cannot daemonize the owned
master, and `ControlPersist=no` so it cannot survive session ownership.

The backend is seeded from drydock-transport at
`b076dbea24883af99356410c14cff40f44b9fd8a` (drydock#12). It retains its private
socket directory, bounded 8 KiB diagnostic tail, authenticated forward
acknowledgement, and kill/reap-before-directory-removal lifecycle. Routing,
purpose headers, transport multiplexing and project policy stay in consumers.

```rust,no_run
use std::{path::Path, time::Duration};
use rigging_ssh::{OpenSsh, SshSession, Target};
# async fn example() -> std::io::Result<()> {
let session = OpenSsh::connect(
    Target::Ambient { destination: "operator@build-host".into() },
    Duration::from_secs(10),
).await?;
let stream = session.open_unix(Path::new("/run/user/1000/service.sock")).await?;
let output = session.exec("uname -s").await?;
assert!(output.status.success());
# Ok(())
# }
```

`Ambient` reads the operator's ssh_config, including ProxyJump, certificates and
agents. `Pinned` requires an exact raw host public key and readable identity file;
it sets `-F /dev/null`, `IdentitiesOnly=yes`, `IdentityAgent=none`, a private
known-hosts file and strict host-key checking. It never prompts interactively.
Host certificates and known-hosts markers are not pinned raw keys.

Construct one session per destination and share it (usually via `Arc<dyn
SshSession>`). Each object owns one foreground ControlMaster; no global pool
implicitly shares authentication between destinations. Multiplexed operations
cannot fall back to an independent ambient connection if that master disappears.
The connection budget covers authentication and each forward setup. Exec returns
buffered `std::process::Output` with separate stdout/stderr and remote status;
callers choose output limits and execution deadlines. Cancellation kills the
local exec client; remote process termination is governed by SSH and the command.

Each distinct outgoing socket path gets a cached local forward until session
drop. Opening that path creates a new independent SSH channel. As with ordinary
OpenSSH local forwarding, opening the local socket can succeed before a refused
remote target is observed as stream EOF/reset. Socket paths must be absolute and
contain no colon, whitespace, or NUL. Remote listener paths must be unique to the
caller; replacing stale sockets is the server/operator's `StreamLocalBindUnlink`
policy. Listener creation waits for remote acknowledgement. Listener drop cancels
the forward asynchronously, preserving accepted streams. Outside a Tokio runtime,
destructors use a best-effort background thread to kill/reap a setup process or
cancel a forward; dropping values after runtime shutdown does not panic. Session drop closes all
channels and reaps the master asynchronously; keep Tokio running for teardown.
There is no automatic reconnect. `closed()` completes for all observers when the
master exits. The port compiles on other platforms, but this backend needs Unix
sockets and OpenSSH on PATH.

## Contract suite

`tests/contract.rs` lifts drydock#12's routing, conservation, half-close,
concurrency, stall isolation, key refusal, forward refusal and drop scenarios,
then adds exec status/stderr, listener lifetime and closing notification. Additional regressions delay one first-open while another completes, and drop
setup/listener values after their runtime shuts down. Routing
uses two socket destinations in place of drydock's project-specific purposes.
The generated scenario draws direction, destination, binary payload and length
for every operation and checks the invariant after each step. Assertions exercise
`dyn SshSession`; a future backend changes `Fixture::session` and runs the same
scenarios. The fixture uses disposable loopback sshd, host keys and identity keys,
with no external SSH server or ambient credentials.

On Linux install `openssh-client` and `openssh-server`. Root sshd also requires
`/run/sshd`. Run `cargo test -p rigging-ssh`; set `RIGGING_TEST_SSHD` to an absolute
sshd path if it is not `/usr/sbin/sshd`. CI provisions the server and runs the suite
as part of the workspace gates. Tests fail if sshd is unavailable; they never skip
acceptance silently. The fixture runs as the current user and uses an ephemeral
loopback port; it is not a production sshd configuration.
