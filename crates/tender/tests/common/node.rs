//! `tender serve` processes for end-to-end tests, and an SSH destination
//! name for a test sshd.

use std::{
    env,
    fs::{self, Permissions},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{self, Output},
    thread,
    time::Duration,
};

use libc::{SIGTERM, kill};
use rigging_ssh::Target;
use tempfile::{Builder, TempDir};

use tender::{
    PublicationId,
    api::{self, BindingEntry, Instance},
    paths,
};
use tokio::{
    net::UnixStream,
    process::{Child, Command},
    time::{self, timeout},
};

use super::{control::Control, ssh_fixture::Sshd};

/// A `tender serve` process under its own TENDER_ROOT.
pub struct Node {
    pub root: TempDir,
    env: Vec<(String, String)>,
    child: Child,
    pub instance: Instance,
    pub control: Control,
}

impl Node {
    pub async fn start(config: &str) -> Self {
        Self::start_with(config, Vec::new()).await
    }

    pub async fn start_with(config: &str, env: Vec<(String, String)>) -> Self {
        let root = Builder::new().prefix("tb-").permissions(Permissions::from_mode(0o700)).tempdir().expect("root");
        fs::create_dir(root.path().join("config")).expect("config directory");
        fs::write(root.path().join("config/config.toml"), config).expect("config");
        let child = Command::new(env!("CARGO_BIN_EXE_tender"))
            .arg("serve")
            .env("TENDER_ROOT", root.path())
            .envs(env.iter().cloned())
            .kill_on_drop(true)
            .spawn()
            .expect("tender serve");
        let socket = paths::control_socket(&root.path().join("runtime"));
        eventually("daemon serves", || async { UnixStream::connect(&socket).await.is_ok() }).await;
        let control = Control::new(&socket);
        let instance = control.get(api::IDENTITY).await.expect("identity");
        Self { root, env, child, instance, control }
    }

    pub fn runtime(&self) -> PathBuf {
        self.root.path().join("runtime")
    }

    /// Run the `tender` CLI against this node; it must succeed.
    pub async fn cli(&self, args: &[&str]) -> Output {
        let output = self.run(args).await;
        assert!(output.status.success(), "tender {args:?}: {}", String::from_utf8_lossy(&output.stderr));
        output
    }

    /// Run the `tender` CLI against this node, whatever its outcome.
    pub async fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_tender"))
            .args(args)
            .env("TENDER_ROOT", self.root.path())
            .envs(self.env.iter().cloned())
            .output()
            .await
            .expect("tender CLI")
    }

    /// This node trusts `other` and follows it at its peer socket.
    pub async fn trust(&self, other: &Node) {
        let socket = other.instance.peer_socket.to_str().expect("socket path").to_owned();
        self.cli(&["trust", "add", &other.instance.key.0, "--name", "peer", "--socket", &socket]).await;
    }

    pub async fn binding(&self, id: &PublicationId) -> Option<BindingEntry> {
        let bindings: Vec<BindingEntry> = self.control.get(api::BINDINGS).await.expect("bindings");
        bindings.into_iter().find(|binding| &binding.publication == id)
    }
}

/// SIGTERM lets the daemon close its SSH sessions; a killed daemon would leave
/// their masters holding the test's output open.
impl Drop for Node {
    fn drop(&mut self) {
        let Some(pid) = self.child.id() else { return };
        // SAFETY: the child has not been reaped, so its pid is still its own.
        unsafe { kill(pid as i32, SIGTERM) };
        for _ in 0..100 {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

pub async fn eventually<F: Future<Output = bool>>(what: &str, mut check: impl FnMut() -> F) {
    timeout(Duration::from_secs(15), async {
        while !check().await {
            time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}"));
}

/// `tender-peer` names the sshd for `ssh` run with [`SshAlias::env`], as an
/// operator's ssh_config would. [`SshAlias::sever`] stands in for losing the
/// network until [`SshAlias::restore`].
pub struct SshAlias {
    pub env: Vec<(String, String)>,
    block: PathBuf,
    config: PathBuf,
}

impl SshAlias {
    pub fn new(sshd: &Sshd) -> Self {
        let Target::Pinned { port, user, host_key, identity_file, .. } = &sshd.target else { panic!("pinned fixture") };
        let directory = sshd.directory.path();
        fs::write(directory.join("known_hosts"), format!("[127.0.0.1]:{port} {host_key}\n")).expect("known hosts");
        fs::write(
            directory.join("ssh_config"),
            format!(
                "Host tender-peer\n  HostName 127.0.0.1\n  Port {port}\n  User {user}\n  IdentityFile {}\n  IdentitiesOnly yes\n  IdentityAgent none\n  UserKnownHostsFile {}\n  StrictHostKeyChecking yes\n",
                identity_file.display(),
                directory.join("known_hosts").display()
            ),
        )
        .expect("ssh config");
        let wrappers = directory.join("bin");
        fs::create_dir(&wrappers).expect("wrapper directory");
        let real = process::Command::new("sh").args(["-c", "command -v ssh"]).output().expect("which ssh");
        let real = String::from_utf8(real.stdout).expect("ssh path").trim().to_owned();
        let wrapper = format!(
            "#!/bin/sh\n[ -e {} ] && exit 255\nexec {real} -F {} \"$@\"\n",
            directory.join("block").display(),
            directory.join("ssh_config").display()
        );
        fs::write(wrappers.join("ssh"), wrapper).expect("wrapper");
        fs::set_permissions(wrappers.join("ssh"), Permissions::from_mode(0o755)).expect("executable wrapper");
        let path = format!("{}:{}", wrappers.display(), env::var("PATH").unwrap_or_default());
        let env = vec![("PATH".to_owned(), path)];
        Self { env, block: directory.join("block"), config: directory.join("ssh_config") }
    }

    /// Refuse new connections and end every session using this alias.
    #[cfg(target_os = "linux")]
    pub fn sever(&self) {
        fs::write(&self.block, b"").expect("block new connections");
        let config = self.config.to_str().expect("config path").as_bytes().to_vec();
        for entry in fs::read_dir("/proc").expect("processes").flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else { continue };
            let Ok(command) = fs::read(entry.path().join("cmdline")) else { continue };
            if command.split(|&byte| byte == 0).any(|argument| argument == config.as_slice()) {
                // SAFETY: signalling a process this test's daemon started.
                unsafe { kill(pid, SIGTERM) };
            }
        }
    }

    pub fn restore(&self) {
        fs::remove_file(&self.block).expect("allow new connections");
    }
}
