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
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::{UnixListener, UnixStream},
    process::Command,
    sync::{Mutex, OnceCell, oneshot, watch},
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
    forwards: Mutex<HashMap<PathBuf, Arc<OnceCell<PathBuf>>>>,
}
impl OpenSsh {
    pub async fn connect(target: Target, timeout: Duration) -> io::Result<Self> {
        if timeout.is_zero() {
            return Err(invalid("SSH timeout must be nonzero"));
        }
        // Keep Unix socket paths under sun_path limits even with a long TMPDIR.
        let dir = tokio::task::spawn_blocking(|| tempfile::Builder::new().prefix("rig-ssh-").tempdir_in("/tmp"))
            .await
            .map_err(io::Error::other)?
            .map_err(|error| {
                io::Error::new(error.kind(), format!("creating private SSH socket directory under /tmp (short Unix socket paths): {error}"))
            })?;
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
                let host_key = validate_host_key(&host_key)?;
                // OpenSSH ignores a nonexistent -i path and may try default
                // identities instead. Fail fast here; this is not a TOCTOU
                // guarantee, because ssh reopens the file. The caller must keep
                // the configured identity path stable through authentication.
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
            let mut delay = Duration::from_millis(10);
            loop {
                if let Some(status) = setup.child.as_mut().unwrap().try_wait()? {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("SSH exited ({status}): {}", setup.stderr.as_ref().unwrap().text()),
                    ));
                }
                if tokio::fs::try_exists(&control).await? {
                    let output = mux(&control).args(["-O", "check"]).arg(&destination).output().await?;
                    if output.status.success() {
                        return Ok(());
                    }
                }
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_millis(200));
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
    fn cleanup(&self, flag: &'static str, spec: String, local: PathBuf) -> ForwardCleanup {
        ForwardCleanup {
            control: self.control.clone(),
            destination: self.destination.clone(),
            spec,
            flag,
            local,
            timeout: self.timeout,
            armed: true,
        }
    }
    fn local_path(&self) -> PathBuf {
        self.control.parent().unwrap().join(format!("s{}", self.next.fetch_add(1, Ordering::Relaxed)))
    }
    fn check(&self) -> io::Result<()> {
        if *self.ended.borrow() { Err(io::Error::new(io::ErrorKind::BrokenPipe, "SSH disconnected")) } else { Ok(()) }
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
        socket_path(path)?;
        let entry = {
            let mut forwards = self.forwards.lock().await;
            forwards.entry(path.to_owned()).or_insert_with(|| Arc::new(OnceCell::new())).clone()
        };
        // The map lock is released before setup. Only opens of the same path
        // share initialization; unrelated destinations make independent progress.
        let local = entry
            .get_or_try_init(|| async {
                let local = self.local_path();
                let mut cleanup = self.cleanup("-L", forward_spec(&local, path)?, local.clone());
                self.forward("-L", &cleanup.spec).await?;
                cleanup.armed = false;
                Ok::<_, io::Error>(local)
            })
            .await?;
        Ok(Box::new(UnixStream::connect(local).await?))
    }
    async fn listen_unix(&self, path: &Path) -> io::Result<Box<dyn SshListener>> {
        self.check()?;
        socket_path(path)?;
        let local = self.local_path();
        let listener = UnixListener::bind(&local)?;
        let spec = forward_spec(path, &local)?;
        // Install the cleanup guard before sending the request: cancellation may
        // happen after the master installs the forward but before acknowledgement.
        let incoming = Incoming { listener, _cleanup: self.cleanup("-R", spec.clone(), local), ended: self.ended.clone() };
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
    _cleanup: ForwardCleanup,
    ended: watch::Receiver<bool>,
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
// A guard is installed before setup, so cancelled first-opens also release
// forwards that the master may have installed before acknowledging the request.
struct ForwardCleanup {
    control: PathBuf,
    destination: String,
    spec: String,
    flag: &'static str,
    local: PathBuf,
    timeout: Duration,
    armed: bool,
}
impl Drop for ForwardCleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let (control, destination, spec, flag, local, timeout) =
            (self.control.clone(), self.destination.clone(), self.spec.clone(), self.flag, self.local.clone(), self.timeout);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = tokio::time::timeout(timeout, mux(&control).args(["-O", "cancel", flag, &spec]).arg(&destination).output()).await;
                let _ = tokio::fs::remove_file(local).await;
            });
        } else {
            // Drop may run after the runtime, or on a plain caller thread.
            // Keep blocking process/file cleanup off that caller thread.
            let _ = std::thread::Builder::new().name("ssh-forward-cleanup".into()).spawn(move || {
                if let Ok(mut child) = mux_command(&control)
                    .args(["-O", "cancel", flag, &spec])
                    .arg(&destination)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                {
                    let started = std::time::Instant::now();
                    loop {
                        match child.try_wait() {
                            Ok(Some(_)) | Err(_) => break,
                            Ok(None) if started.elapsed() < timeout => std::thread::sleep(Duration::from_millis(10)),
                            Ok(None) => {
                                let _ = child.kill();
                                let _ = child.wait();
                                break;
                            }
                        }
                    }
                }
                let _ = std::fs::remove_file(local);
            });
        }
    }
}
// Disable fallback network connections: operations must use this owned master,
// never authenticate again through ambient configuration if it has disappeared.
fn mux(control: &Path) -> Command {
    let mut command = Command::from(mux_command(control));
    command.kill_on_drop(true);
    command
}
fn mux_command(control: &Path) -> std::process::Command {
    let mut command = std::process::Command::new("ssh");
    command
        .args(["-F", "/dev/null", "-o", "ProxyCommand=false", "-o", "BatchMode=yes", "-S"])
        .arg(control)
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped());
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
    Ok(format!("{}:{}", socket_path(local)?, socket_path(remote)?))
}
fn socket_path(path: &Path) -> io::Result<&str> {
    path.to_str()
        .filter(|p| p.starts_with('/') && !p.contains([':', '\n', '\r', ' ', '\t', '\0']))
        .ok_or_else(|| invalid("SSH socket paths must be absolute without separators or whitespace"))
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
