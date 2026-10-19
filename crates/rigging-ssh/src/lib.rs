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

/// Keep the session alive while using its streams/listeners. Concurrent opens
/// are independent channels. Dropping it closes all channels and reaps the master.
#[async_trait]
pub trait SshSession: Send + Sync {
    /// A remote shell command, with no PTY and closed stdin. Output is buffered;
    /// callers bound execution with their own timeout/cancellation policy.
    async fn exec(&self, command: &str) -> io::Result<Output>;
    async fn open_unix(&self, path: &Path) -> io::Result<ByteStream>;
    /// Returns only after the server acknowledges the remote forward.
    async fn listen_unix(&self, path: &Path) -> io::Result<Box<dyn SshListener>>;
    /// Completes when the session closes; safe to call repeatedly or concurrently.
    async fn closed(&self);
}

/// Budget for connection/authentication and each forward setup operation.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
