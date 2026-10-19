// Seeded from drydock-transport b076dbea: bounded diagnostics and reap-before-remove.
use std::{
    collections::VecDeque,
    io,
    sync::{Arc, Mutex},
};
#[cfg(all(test, target_os = "linux"))]
use tokio::process::Command;
// Setup cancellation and failure use the same reap-before-remove order as a
// successful transport. Ownership transfers to the live monitor only on success.
pub(crate) struct SetupGuard {
    pub(crate) child: Option<tokio::process::Child>,
    pub(crate) dir: Option<tempfile::TempDir>,
    pub(crate) stderr: Option<StderrTail>,
}
impl Drop for SetupGuard {
    fn drop(&mut self) {
        let stderr = self.stderr.take();
        if let (Some(mut child), Some(dir)) = (self.child.take(), self.dir.take()) {
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    drop(stderr);
                    let _ = tokio::task::spawn_blocking(move || drop(dir)).await;
                });
            } else {
                let _ = child.start_kill();
                drop(stderr);
                // try_wait uses the OS process handle, without needing a Tokio
                // reactor. Retain the directory until the child has been reaped.
                let _ = std::thread::Builder::new().name("ssh-setup-cleanup".into()).spawn(move || {
                    while matches!(child.try_wait(), Ok(None)) {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    drop(dir);
                });
            }
        }
    }
}

const STDERR_TAIL_BYTES: usize = 8192;
pub(crate) struct StderrTail {
    bytes: Arc<Mutex<VecDeque<u8>>>,
    task: tokio::task::AbortHandle,
}
impl StderrTail {
    pub(crate) fn drain<R: tokio::io::AsyncRead + Unpin + Send + 'static>(mut reader: R) -> Self {
        let bytes = Arc::new(Mutex::new(VecDeque::with_capacity(STDERR_TAIL_BYTES)));
        let buffer = bytes.clone();
        let task = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut chunk = [0; 1024];
            while let Ok(n) = reader.read(&mut chunk).await {
                if n == 0 {
                    break;
                }
                let mut tail = buffer.lock().unwrap();
                let excess = (tail.len() + n).saturating_sub(STDERR_TAIL_BYTES);
                tail.drain(..excess);
                tail.extend(&chunk[..n]);
            }
        });
        Self { bytes, task: task.abort_handle() }
    }
    pub(crate) fn text(&self) -> String {
        let bytes: Vec<_> = self.bytes.lock().unwrap().iter().copied().collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}
impl Drop for StderrTail {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) fn validate_host_key(key: &str) -> io::Result<String> {
    let mut fields = key.split_whitespace();
    let kind = fields.next().unwrap_or_default();
    let supported = matches!(kind, "ssh-ed25519" | "ssh-rsa" | "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521");
    let blob = fields.next().unwrap_or_default();
    if !supported
        || blob.is_empty()
        || !blob.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
        || key.contains(['\n', '\r'])
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SSH reach requires a raw OpenSSH host public key, not known-hosts options or markers",
        ));
    }
    Ok(format!("{kind} {blob}"))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::time::Duration;

    // Real process boundary: cancelling a partially initialized setup must reap
    // its child before deleting the socket directory, not leave an orphan behind.
    #[tokio::test]
    async fn cancelled_setup_reaps_before_removing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_owned();
        let child = Command::new("sleep").arg("60").kill_on_drop(true).spawn().unwrap();
        let pid = child.id().unwrap();
        drop(SetupGuard { child: Some(child), dir: Some(dir), stderr: None });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while tokio::fs::try_exists(&path).await.unwrap() {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists(), "child must be reaped before its directory disappears");
    }
    // A setup guard can outlive the runtime during caller unwinding. It must
    // still kill/reap its child before removing its directory, without panicking.
    #[test]
    fn setup_drop_after_runtime_shutdown() {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let (guard, path, pid) = runtime.block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().to_owned();
            let child = Command::new("sleep").arg("60").kill_on_drop(true).spawn().unwrap();
            let pid = child.id().unwrap();
            (SetupGuard { child: Some(child), dir: Some(dir), stderr: None }, path, pid)
        });
        drop(runtime);
        drop(guard);
        let started = std::time::Instant::now();
        while path.exists() {
            assert!(started.elapsed() < Duration::from_secs(2), "setup cleanup must finish");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists(), "child must be reaped before directory removal");
    }

    // Host-key comments do not participate in pinning or the known-hosts record.
    #[test]
    fn host_key_comments_are_normalized() {
        assert_eq!(validate_host_key("ssh-ed25519 AAAA operator comment").unwrap(), "ssh-ed25519 AAAA");
    }

    // Long-lived SSH diagnostics must drain without pipe backpressure or disk
    // growth, retaining only the documented 8 KiB suffix for error reporting.
    #[tokio::test]
    async fn stderr_drain_retains_only_bounded_tail() {
        use tokio::io::AsyncWriteExt;
        let (mut writer, reader) = tokio::io::duplex(1024);
        let tail = StderrTail::drain(reader);
        let mut data = vec![b'x'; 1024 * 1024];
        data.extend_from_slice(b"last diagnostic");
        tokio::time::timeout(Duration::from_secs(2), async {
            writer.write_all(&data).await.unwrap();
            writer.shutdown().await.unwrap();
            while !tail.text().ends_with("last diagnostic") {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(tail.text().as_bytes(), &data[data.len() - 8192..]);
    }
}
