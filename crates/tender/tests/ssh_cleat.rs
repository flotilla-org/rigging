#![cfg(target_os = "linux")]

#[allow(dead_code)]
#[path = "common/control.rs"]
mod control;
#[allow(dead_code)]
#[path = "common/node.rs"]
mod node;
#[path = "common/ssh.rs"]
mod ssh_fixture;

use std::{
    env,
    fs::{self, Permissions},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Output,
    time::Duration,
};

use libc::{SIGTERM, kill};

use node::{Node, SshAlias, eventually};
use tempfile::{Builder, TempDir};
use tender::{BindingState, PublicationId, UnavailableReason, api::BindingEntry, paths};
use tokio::{
    process::Command,
    time::{sleep, timeout},
};

const SESSION: &str = "tender-proof";
const DEADLINE: Duration = Duration::from_secs(15);

struct Cleat {
    binary: PathBuf,
    root: TempDir,
}

impl Cleat {
    fn command(&self) -> Command {
        let mut command = Command::new(&self.binary);
        command.args(["--runtime-root", self.root.path().to_str().expect("runtime path"), "--server", "proof"]);
        command.env_remove("CLEAT_DAEMON").kill_on_drop(true);
        command
    }

    async fn output(&self, args: &[&str]) -> String {
        let output = timeout(DEADLINE, self.command().args(args).output()).await.expect("cleat deadline").expect("cleat command");
        assert!(output.status.success(), "cleat {args:?}: {}", String::from_utf8_lossy(&output.stderr));
        String::from_utf8(output.stdout).expect("cleat UTF8")
    }

    fn socket(&self) -> PathBuf {
        fs::read_dir(self.root.path())
            .expect("runtime directory")
            .filter_map(Result::ok)
            .map(|entry| entry.path().join("socket"))
            .find(|path| path.exists())
            .expect("cleat daemon socket")
    }

    fn client(&self) -> Command {
        let mut command = Command::new(&self.binary);
        // The connect-only client has no local daemon/session metadata.
        command.env_remove("CLEAT_DAEMON").env("HOME", self.root.path().join("empty-client"));
        command.env("XDG_RUNTIME_DIR", self.root.path().join("empty-client"));
        command.env("XDG_STATE_HOME", self.root.path().join("empty-client"));
        command.kill_on_drop(true);
        command
    }

    async fn packets(&self, socket: &str, session: &str) -> Output {
        timeout(DEADLINE, self.client().args(["packets", "--socket", socket, session]).output())
            .await
            .expect("connect-only packet deadline")
            .expect("packet client")
    }

    async fn attach(&self, socket: &str, id: &str) {
        let script = self.root.path().join(format!("{id}.sh"));
        let quote = |value: &str| format!("'{}'", value.replace('\'', "'\"'\"'"));
        fs::write(
            &script,
            format!("exec {} attach --socket {} {SESSION}\n", quote(self.binary.to_str().expect("binary path")), quote(socket)),
        )
        .expect("attach launch script");
        self.output(&[
            "launch",
            id,
            "--cmd",
            &format!("sh {}", script.display()),
            "--size",
            "80x24",
            "--no-record",
            "--env",
            &format!("HOME={}", self.root.path().join("empty-client").display()),
            "--env",
            &format!("XDG_RUNTIME_DIR={}", self.root.path().join("empty-client").display()),
            "--env",
            &format!("XDG_STATE_HOME={}", self.root.path().join("empty-client").display()),
        ])
        .await;
    }

    async fn rendered(&self, id: &str, needle: &str) {
        self.output(&["wait", id, "--text", needle, "--timeout", "10"]).await;
        assert!(self.output(&["capture", id]).await.contains(needle), "attach rendered {needle:?}");
    }
}

impl Drop for Cleat {
    fn drop(&mut self) {
        // Daemon owns only this private runtime. Clean up even after an assertion panic.
        if let Ok(entries) = fs::read_dir(self.root.path()) {
            for entry in entries.flatten() {
                if let Ok(pid) = fs::read_to_string(entry.path().join("daemon.pid"))
                    && let Ok(pid) = pid.trim().parse::<i32>()
                    && pid > 1
                {
                    unsafe { kill(pid, SIGTERM) };
                }
            }
        }
    }
}

// flotilla-org/flotilla#2562: an existing cleat service survives SSH loss. Cleat's own socket-only
// clients discover sessions, render/input, refuse a dead route, and recover
// with fresh connections without replaying old input into the living session.
#[tokio::test]
async fn cleat_survives_ssh_loss_and_fresh_client_recovers() {
    let cleat = Cleat {
        binary: env::var_os("TENDER_TEST_CLEAT").expect("provision pinned cleat with TENDER_TEST_CLEAT").into(),
        root: Builder::new().prefix("tc-").permissions(Permissions::from_mode(0o700)).tempdir().expect("private runtime"),
    };
    fs::create_dir(cleat.root.path().join("empty-client")).expect("empty client home");
    let version = cleat.output(&["version"]).await;
    eprintln!("cleat provenance: {}", version.trim());
    assert!(version.contains("00c072b207dc") && version.contains("vt ghostty"), "proof requires pinned functional cleat");
    // Disable terminal echo: evidence must come from the service's response,
    // and each input appends exactly one line to an independent no-replay log.
    let log = cleat.root.path().join("inputs");
    let script = cleat.root.path().join("service.sh");
    fs::write(&script, format!("stty -echo\nprintf 'READY\\n'\nwhile IFS= read -r line; do printf '%s\\n' \"$line\" >> '{}'; printf 'REPLY:%s\\n' \"$line\"; done\n", log.display())).expect("service script");
    cleat.output(&["launch", SESSION, "--cmd", &format!("sh {}", script.display()), "--no-record", "--json"]).await;
    let terminal = Cleat {
        binary: cleat.binary.clone(),
        root: Builder::new().prefix("tt-").permissions(Permissions::from_mode(0o700)).tempdir().expect("private terminal harness"),
    };
    fs::create_dir(terminal.root.path().join("empty-client")).expect("empty attach client home");
    let service_socket = cleat.socket();
    // The far daemon publishes cleat's own socket from configuration; the near
    // one pairs with it over SSH and binds it, as a client machine would.
    let sshd = ssh_fixture::Sshd::start().await;
    let alias = SshAlias::new(&sshd);
    let far = Node::start(&format!(
        "[[publication]]\nscope = \"vessel/proof\"\nname = \"cleat/default\"\nlabel = \"cleat\"\ndisplay = \"Proof cleat daemon\"\nendpoint = \"{}\"\n",
        service_socket.display()
    ))
    .await;
    let near = Node::start_with("", alias.env.clone()).await;
    let remote = format!("env TENDER_ROOT={} {}", far.root.path().display(), env!("CARGO_BIN_EXE_tender"));
    near.cli(&["trust", "pair", "tender-peer", "--remote-tender", &remote, "--expect-fingerprint", &far.instance.fingerprint.0]).await;
    let id = PublicationId::new("vessel/proof", "cleat/default");
    let state = |binding: Option<BindingEntry>| binding.map(|binding| binding.state);
    eventually("the near daemon binds the cleat publication", || async {
        matches!(state(near.binding(&id).await), Some(BindingState::Available { .. }))
    })
    .await;
    let binding = paths::binding_path(&near.runtime(), &id).to_str().expect("binding path").to_owned();
    let packet = cleat.packets(&binding, SESSION).await;
    assert!(packet.status.success(), "directory/session/render: {}", String::from_utf8_lossy(&packet.stderr));
    assert!(String::from_utf8_lossy(&packet.stdout).contains("mode_changes=initial"));
    let missing = cleat.packets(&binding, "absent-session").await;
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("not present in packet directory"));
    terminal.attach(&binding, "client-before").await;
    terminal.rendered("client-before", "READY").await;
    terminal.output(&["send", "client-before", "before"]).await;
    terminal.rendered("client-before", "REPLY:before").await;
    let before = cleat.output(&["capture", SESSION]).await;
    assert_eq!(fs::read_to_string(&log).expect("input log"), "before\n");

    // Lose only SSH; the existing daemon/session and its screen stay alive.
    alias.sever();
    timeout(DEADLINE, async {
        loop {
            let state = timeout(DEADLINE, terminal.command().args(["inspect", "client-before", "--json"]).output())
                .await
                .expect("inspection deadline")
                .expect("inspection");
            if !state.status.success() {
                assert!(
                    String::from_utf8_lossy(&state.stderr).contains("missing session client-before"),
                    "unexpected inspect failure: {}",
                    String::from_utf8_lossy(&state.stderr)
                );
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("old attach exits without reconnect");
    eventually("the Binding reports the lost route", || async {
        matches!(state(near.binding(&id).await), Some(BindingState::Unavailable { reason: UnavailableReason::RouteUnavailable, .. }))
    })
    .await;
    assert_eq!(cleat.output(&["capture", SESSION]).await, before, "cleat screen survives SSH loss");
    let unavailable = cleat.packets(&binding, SESSION).await;
    assert!(!unavailable.status.success(), "socket-only client must refuse an unavailable route");
    assert!(Path::new(&binding).exists(), "the Binding keeps its Local Endpoint through route loss");

    alias.restore();
    eventually("a fresh SSH forward restores the Binding", || async {
        matches!(state(near.binding(&id).await), Some(BindingState::Available { .. }))
    })
    .await;
    assert!(cleat.packets(&binding, SESSION).await.status.success(), "fresh packet client discovers living session");
    terminal.attach(&binding, "client-after").await;
    terminal.rendered("client-after", "REPLY:before").await;
    assert_eq!(fs::read_to_string(&log).expect("no replay log"), "before\n", "fresh initial render does not replay old input");
    terminal.output(&["send", "client-after", "after"]).await;
    terminal.rendered("client-after", "REPLY:after").await;
    assert_eq!(fs::read_to_string(&log).expect("input log"), "before\nafter\n", "each input delivered exactly once");
    assert!(
        fs::read_dir(cleat.root.path().join("empty-client")).expect("client home").next().is_none(),
        "socket clients never create a local daemon"
    );
    assert!(
        fs::read_dir(terminal.root.path().join("empty-client")).expect("attach home").next().is_none(),
        "attach never creates local metadata"
    );
    terminal.output(&["kill", "client-after"]).await;
    cleat.output(&["kill", SESSION]).await;
}
