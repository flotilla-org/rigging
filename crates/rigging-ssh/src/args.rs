//! Argument builders for callers that run a forwarding-only `ssh` process
//! themselves, and a waiter for the socket it binds. Unlike [`crate::OpenSsh`],
//! these leave destination, authentication and process ownership to the caller.

use std::{path::Path, process::ExitStatus, time::Duration};

use tokio::time::{Instant, sleep};

/// A `local:remote` stream-local forward specification. Paths are not
/// validated; a path containing `:` produces a specification OpenSSH misreads.
pub fn forward_spec(local: &Path, remote: &Path) -> String {
    format!("{}:{}", local.display(), remote.display())
}

/// Whether the forward may replace a stale socket file at its local path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExistingSocket {
    Refuse,
    Unlink,
}

/// Arguments for a process that only forwards `local` to `remote`, and
/// optionally publishes a local endpoint at a remote listener; it runs no
/// remote command. The destination is the last argument. Liveness probes end
/// the process after about 45 seconds of silence.
pub fn forwarding_arguments(
    destination: &str,
    local: &Path,
    remote: &Path,
    reverse: Option<(&Path, &Path)>,
    existing_socket: ExistingSocket,
) -> Vec<String> {
    let mut args = vec!["-N".into(), "-L".into(), forward_spec(local, remote)];
    if let Some((remote_listener, local_endpoint)) = reverse {
        args.extend(["-R".into(), forward_spec(remote_listener, local_endpoint)]);
    }
    args.extend([
        "-o".into(),
        "ExitOnForwardFailure=yes".into(),
        "-o".into(),
        format!(
            "StreamLocalBindUnlink={}",
            match existing_socket {
                ExistingSocket::Unlink => "yes",
                ExistingSocket::Refuse => "no",
            }
        ),
        "-o".into(),
        "ServerAliveInterval=15".into(),
        "-o".into(),
        "ServerAliveCountMax=3".into(),
        destination.into(),
    ]);
    args
}

/// Arguments that publish a local endpoint at a remote socket path and nothing
/// else: no local forward and no remote command. The remote listener is bound
/// by sshd, whose own `StreamLocalBindUnlink` decides whether a stale file is
/// replaced, so callers remove a stale remote socket before dialling.
pub fn reverse_forwarding_arguments(destination: &str, remote_listener: &Path, local_endpoint: &Path) -> Vec<String> {
    vec![
        "-N".into(),
        "-T".into(),
        "-R".into(),
        forward_spec(remote_listener, local_endpoint),
        "-o".into(),
        "ExitOnForwardFailure=yes".into(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "ServerAliveInterval=15".into(),
        "-o".into(),
        "ServerAliveCountMax=3".into(),
        destination.into(),
    ]
}

/// Waits for a forward's local socket, failing early if the process exits. The
/// probe reports the caller's process status, so any process runner fits.
pub async fn wait_for_socket(
    socket: &Path,
    bound: Duration,
    mut process_status: impl FnMut() -> Result<Option<ExitStatus>, String>,
) -> Result<(), String> {
    let deadline = Instant::now() + bound;
    loop {
        if let Some(status) = process_status()? {
            return Err(format!("ssh exited prematurely with {status}"));
        }
        if socket.exists() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for forwarded socket at {}", socket.display()));
        }
        sleep(Duration::from_millis(20)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn option(args: &[String], value: &str) -> bool {
        args.windows(2).any(|pair| pair == ["-o", value])
    }

    #[test]
    fn forward_carries_both_directions_and_the_unlink_policy() {
        let args = forwarding_arguments(
            "host",
            Path::new("/l.sock"),
            Path::new("/r.sock"),
            Some((Path::new("/rl.sock"), Path::new("/le.sock"))),
            ExistingSocket::Unlink,
        );
        assert_eq!(args[..3], ["-N", "-L", "/l.sock:/r.sock"]);
        assert_eq!(args[args.iter().position(|arg| arg == "-R").expect("-R") + 1], "/rl.sock:/le.sock");
        assert!(option(&args, "ExitOnForwardFailure=yes"));
        assert!(option(&args, "StreamLocalBindUnlink=yes"));
        assert_eq!(args.last().map(String::as_str), Some("host"));

        let args = forwarding_arguments("host", Path::new("/l.sock"), Path::new("/r.sock"), None, ExistingSocket::Refuse);
        assert!(!args.iter().any(|arg| arg == "-R"));
        assert!(option(&args, "StreamLocalBindUnlink=no"));
    }

    // A reverse forward publishes only the remote listener. It carries no local
    // forward or remote command, and the destination is the last word.
    #[test]
    fn reverse_forward_carries_only_the_remote_listener() {
        let args = reverse_forwarding_arguments("b1", Path::new("/run/user/1000/f.sock"), Path::new("/tmp/env/f.sock"));
        assert_eq!(args.iter().filter(|arg| *arg == "-R").count(), 1);
        assert!(!args.iter().any(|arg| arg == "-L"));
        assert_eq!(args[args.iter().position(|arg| arg == "-R").expect("-R") + 1], "/run/user/1000/f.sock:/tmp/env/f.sock");
        assert!(option(&args, "ExitOnForwardFailure=yes"));
        assert!(option(&args, "BatchMode=yes"));
        assert_eq!(args.last().map(String::as_str), Some("b1"));
        assert_eq!(args[0], "-N");
    }

    #[tokio::test]
    async fn socket_waiter_returns_once_the_socket_exists_and_times_out_otherwise() {
        let directory = tempfile::tempdir().expect("directory");
        let socket = directory.path().join("forward");
        assert!(wait_for_socket(&socket, Duration::from_millis(60), || Ok(None)).await.is_err());
        std::fs::write(&socket, b"").expect("socket file");
        assert_eq!(wait_for_socket(&socket, Duration::from_secs(1), || Ok(None)).await, Ok(()));
    }

    // A stale file cannot hide a dead forward, and process-probe errors are
    // surfaced instead of falsely certifying readiness from the file alone.
    #[cfg(unix)]
    #[tokio::test]
    async fn socket_waiter_checks_process_before_stale_file() {
        use std::os::unix::process::ExitStatusExt;
        let directory = tempfile::tempdir().expect("directory");
        let socket = directory.path().join("stale");
        std::fs::write(&socket, b"").expect("stale file");
        assert!(wait_for_socket(&socket, Duration::from_secs(1), || Ok(Some(ExitStatus::from_raw(256)))).await.is_err());
        assert_eq!(wait_for_socket(&socket, Duration::from_secs(1), || Err("probe failed".into())).await, Err("probe failed".into()));
    }
}
