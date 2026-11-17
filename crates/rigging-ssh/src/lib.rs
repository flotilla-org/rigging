//! An SSH session port. PTY attach remains native `ssh -tt`, outside this port.
//! OpenSSH socket forwarding is Unix-only; the port and byte types are portable.
use async_trait::async_trait;
use rigging_stream::ByteStream;
use std::{
    io,
    path::{Path, PathBuf},
    process::Output,
    time::Duration,
};
use tokio::io::AsyncRead;

#[cfg(unix)]
mod openssh;
#[cfg(unix)]
mod process;
#[cfg(unix)]
pub use openssh::OpenSsh;

/// Authentication and destination policy, independent of any project identity.
#[derive(Clone, Debug)]
pub enum Target {
    /// An operator's ssh_config destination (including user@alias).
    Ambient { destination: String },
    /// An exact host key and identity; no operator ssh_config or agent is read.
    Pinned { host: String, port: u16, user: String, host_key: String, identity_file: PathBuf },
}

/// Accepting is cancellation-safe. Dropping a listener stops new connections;
/// already accepted streams remain usable while their session is alive.
#[async_trait]
pub trait SshListener: Send + Sync {
    async fn accept(&self) -> io::Result<ByteStream>;
}

/// A local Unix socket held for its owner: each connection to `local_path` opens
/// a fresh channel to one remote socket. Unlike `open_unix`'s cached forward, it
/// exists for clients that dial a path themselves. Dropping it stops new
/// connections; established streams keep their channels while the session lives.
pub trait UnixForward: Send + Sync {
    fn local_path(&self) -> &Path;
}

/// Keep the session alive while using its streams/listeners. Concurrent opens
/// are independent channels. Dropping it closes all channels and reaps the master.
#[async_trait]
pub trait SshSession: Send + Sync {
    /// A remote shell command, with no PTY and closed stdin. Output is buffered;
    /// there is no implicit execution deadline. Callers can wrap this future in
    /// `tokio::time::timeout`; cancellation kills the local exec client without
    /// closing the session. Remote termination depends on SSH and the command.
    async fn exec(&self, command: &str) -> io::Result<Output>;
    /// Like `exec`, but the command's stdin is `input`, copied as it is read
    /// (never buffered whole) and closed at its end, so a command that reads to
    /// end of input finishes. Returns the same output and status as `exec`. If
    /// the command exits without reading all of `input`, the unread rest is
    /// dropped and the exit status is still returned; an error reading `input`
    /// kills the exec client and fails the call, so the command never sees the
    /// truncated stream as a clean end. Cancellation behaves as for `exec`.
    async fn exec_with_input(&self, command: &str, input: &mut (dyn AsyncRead + Send + Unpin)) -> io::Result<Output>;
    async fn open_unix(&self, path: &Path) -> io::Result<ByteStream>;
    /// Returns only after the session has bound the local socket.
    async fn forward_unix(&self, path: &Path) -> io::Result<Box<dyn UnixForward>>;
    /// Returns only after the server acknowledges the remote forward.
    async fn listen_unix(&self, path: &Path) -> io::Result<Box<dyn SshListener>>;
    /// Completes when the session closes; safe to call repeatedly or concurrently.
    async fn closed(&self);
}

/// Budget for connection/authentication and each forward setup operation.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
