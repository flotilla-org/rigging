// OpenSSH process/forward lifecycle seeded from drydock-transport b076dbea.
use crate::{
    SshListener, SshSession, Target,
    process::{SetupGuard, StderrTail, validate_host_key},
};
use async_trait::async_trait;
use rigging_stream::ByteStream;
use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
    process::{Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    net::{UnixListener, UnixStream},
    process::Command,
    sync::{Mutex, oneshot, watch},
};

/// One owned ControlMaster for one destination. Reuse this object (or an Arc)
/// across consumers instead of constructing another session for each channel.
/// Cached local forwards live until session drop, one per distinct remote path.
pub struct OpenSsh {
    control: PathBuf,
    destination: String,
    timeout: Duration,
    ended: watch::Receiver<bool>,
    _stop: oneshot::Sender<()>,
    next: AtomicU64,
    forwards: Mutex<HashMap<PathBuf, PathBuf>>,
}
impl OpenSsh {
    pub async fn connect(target: Target, timeout: Duration) -> io::Result<Self> {
        if timeout.is_zero() {
            return Err(invalid("SSH timeout must be nonzero"));
        }
        let dir = tempfile::Builder::new().prefix("rig-ssh-").tempdir_in("/tmp")?;
        let control = dir.path().join("master");
        let mut command = Command::new("ssh");
        let destination = match target {
            Target::Ambient { destination } => {
                validate_destination(&destination)?;
                destination
            }
            Target::Pinned { host, port, user, host_key, identity_file } => {
                validate_destination(&host)?;
                validate_destination(&user)?;
                if host.contains('@') || user.contains('@') || port == 0 {
                    return Err(invalid("invalid pinned SSH destination"));
                }
                validate_host_key(&host_key)?;
                // OpenSSH ignores a nonexistent -i path and may try default
                // identities instead. Fail here to preserve exact identity policy.
                if !tokio::fs::metadata(&identity_file).await?.is_file() {
                    return Err(invalid("SSH identity must be a regular file"));
                }
                let _identity = tokio::fs::File::open(&identity_file).await?;
                let known_hosts = dir.path().join("known_hosts");
                tokio::fs::write(&known_hosts, format!("rigging-target {host_key}\n")).await?;
                command
                    .args([
                        "-F",
                        "/dev/null",
                        "-o",
                        "IdentitiesOnly=yes",
                        "-o",
                        "IdentityAgent=none",
                        "-o",
                        "StrictHostKeyChecking=yes",
                        "-o",
                        "GlobalKnownHostsFile=/dev/null",
                        "-o",
                        "HostKeyAlias=rigging-target",
                    ])
                    .arg("-o")
                    .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
                    .arg("-i")
                    .arg(identity_file)
                    .arg("-p")
                    .arg(port.to_string())
                    .arg("-l")
                    .arg(user);
                host
            }
        };
        let mut child = command
            .args([
                "-T",
                "-n",
                "-N",
                "-M",
                "-o",
                "ControlPersist=no",
                "-o",
                "ForkAfterAuthentication=no",
                "-o",
                "BatchMode=yes",
                "-o",
                "ExitOnForwardFailure=yes",
                "-o",
                "LogLevel=ERROR",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=3",
            ])
            .arg("-o")
            .arg(format!("ConnectTimeout={}", timeout.as_secs().saturating_add(u64::from(timeout.subsec_nanos() != 0))))
            .arg("-S")
            .arg(&control)
            .arg(&destination)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let stderr = StderrTail::drain(child.stderr.take().unwrap());
        let mut setup = SetupGuard { child: Some(child), dir: Some(dir), stderr: Some(stderr) };
        tokio::time::timeout(timeout, async {
            loop {
                if let Some(status) = setup.child.as_mut().unwrap().try_wait()? {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("SSH exited ({status}): {}", setup.stderr.as_ref().unwrap().text()),
                    ));
                }
                if control.exists() {
                    let output = mux(&control).args(["-O", "check"]).arg(&destination).output().await?;
                    if output.status.success() {
                        return Ok(());
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SSH session setup"))??;
        let mut child = setup.child.take().unwrap();
        let dir = setup.dir.take().unwrap();
        let stderr = setup.stderr.take().unwrap();
        let (notify, ended) = watch::channel(false);
        let (stop, shutdown) = oneshot::channel();
        tokio::spawn(async move {
            tokio::select! { _ = child.wait() => {}, _ = shutdown => { let _ = child.kill().await; } }
            let _ = child.wait().await;
            let _ = notify.send(true);
            drop(stderr);
            let _ = tokio::task::spawn_blocking(move || drop(dir)).await;
        });
        Ok(Self { control, destination, timeout, ended, _stop: stop, next: AtomicU64::new(0), forwards: Mutex::new(HashMap::new()) })
    }
    fn local_path(&self) -> PathBuf {
        self.control.parent().unwrap().join(format!("s{}", self.next.fetch_add(1, Ordering::Relaxed)))
    }
    fn check(&self) -> io::Result<()> {
        if *self.ended.borrow() || !self.control.exists() {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "SSH disconnected"))
        } else {
            Ok(())
        }
    }
    async fn forward(&self, flag: &str, spec: &str) -> io::Result<()> {
        self.check()?;
        let output =
            tokio::time::timeout(self.timeout, mux(&self.control).args(["-O", "forward", flag, spec]).arg(&self.destination).output())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SSH forwarding setup"))??;
        if output.status.success() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("SSH forwarding rejected: {}", String::from_utf8_lossy(&output.stderr)),
            ))
        }
    }
}
#[async_trait]
impl SshSession for OpenSsh {
    async fn exec(&self, command: &str) -> io::Result<Output> {
        self.check()?;
        mux(&self.control).arg("-T").arg(&self.destination).arg(command).output().await
    }
    async fn open_unix(&self, path: &Path) -> io::Result<ByteStream> {
        self.check()?;
        let mut forwards = self.forwards.lock().await;
        let local = if let Some(local) = forwards.get(path) {
            local.clone()
        } else {
            let local = self.local_path();
            self.forward("-L", &forward_spec(&local, path)?).await?;
            forwards.insert(path.to_owned(), local.clone());
            local
        };
        drop(forwards);
        Ok(Box::new(UnixStream::connect(local).await?))
    }
    async fn listen_unix(&self, path: &Path) -> io::Result<Box<dyn SshListener>> {
        self.check()?;
        let local = self.local_path();
        let listener = UnixListener::bind(&local)?;
        let spec = forward_spec(path, &local)?;
        // Install the cleanup guard before sending the request: cancellation may
        // happen after the master installs the forward but before acknowledgement.
        let incoming = Incoming {
            listener,
            local,
            spec: spec.clone(),
            control: self.control.clone(),
            destination: self.destination.clone(),
            ended: self.ended.clone(),
            timeout: self.timeout,
        };
        self.forward("-R", &spec).await?;
        Ok(Box::new(incoming))
    }
    async fn closed(&self) {
        let mut ended = self.ended.clone();
        let _ = ended.wait_for(|ended| *ended).await;
    }
}
struct Incoming {
    listener: UnixListener,
    local: PathBuf,
    spec: String,
    control: PathBuf,
    destination: String,
    ended: watch::Receiver<bool>,
    timeout: Duration,
}
#[async_trait]
impl SshListener for Incoming {
    async fn accept(&self) -> io::Result<ByteStream> {
        let mut ended = self.ended.clone();
        tokio::select! {
            biased;
            _ = ended.wait_for(|ended| *ended) => Err(io::Error::new(io::ErrorKind::BrokenPipe, "SSH disconnected")),
            result = self.listener.accept() => Ok(Box::new(result?.0) as ByteStream),
        }
    }
}
impl Drop for Incoming {
    fn drop(&mut self) {
        let (control, destination, spec, local, timeout) =
            (self.control.clone(), self.destination.clone(), self.spec.clone(), self.local.clone(), self.timeout);
        tokio::spawn(async move {
            let _ = tokio::time::timeout(timeout, mux(&control).args(["-O", "cancel", "-R", &spec]).arg(&destination).output()).await;
            let _ = tokio::fs::remove_file(local).await;
        });
    }
}
// Disable fallback network connections: operations must use this owned master,
// never authenticate again through ambient configuration if it has disappeared.
fn mux(control: &Path) -> Command {
    let mut command = Command::new("ssh");
    command
        .args(["-F", "/dev/null", "-o", "ProxyCommand=false", "-o", "BatchMode=yes", "-S"])
        .arg(control)
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true);
    command
}
fn validate_destination(value: &str) -> io::Result<()> {
    if value.is_empty() || value.starts_with('-') || value.chars().any(char::is_whitespace) || value.contains('\0') {
        Err(invalid("invalid SSH destination"))
    } else {
        Ok(())
    }
}
fn forward_spec(local: &Path, remote: &Path) -> io::Result<String> {
    fn path(path: &Path) -> io::Result<&str> {
        path.to_str()
            .filter(|p| p.starts_with('/') && !p.contains([':', '\n', '\r', ' ', '\t', '\0']))
            .ok_or_else(|| invalid("SSH socket paths must be absolute without separators or whitespace"))
    }
    Ok(format!("{}:{}", path(local)?, path(remote)?))
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
