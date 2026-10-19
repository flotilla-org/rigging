#![cfg(unix)]
//! Backend-independent contract scenarios, lifted from drydock#12's contract.rs.
//! A future backend replaces only Fixture::session; assertions use the port.
mod common;
use rigging_ssh::{OpenSsh, SshSession, Target};
use rigging_stream::ByteStream;
use std::{io, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    task::JoinSet,
};
const BUDGET: Duration = Duration::from_secs(10);
struct Fixture {
    dir: tempfile::TempDir,
    target: Target,
    _server: tokio::process::Child,
}
impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (target, server) = common::ssh_server(dir.path()).await;
        Self { dir, target, _server: server }
    }
    async fn session(&self) -> Arc<dyn SshSession> {
        Arc::new(OpenSsh::connect(self.target.clone(), BUDGET).await.unwrap())
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}
async fn transfer(mut outgoing: ByteStream, mut incoming: ByteStream, payload: &[u8]) {
    outgoing.write_all(payload).await.unwrap();
    outgoing.shutdown().await.unwrap();
    let mut bytes = Vec::new();
    incoming.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, payload);
    // Seed contract: half-close preserves traffic in the reverse direction.
    incoming.write_all(b"reply\0\xff").await.unwrap();
    incoming.shutdown().await.unwrap();
    bytes.clear();
    outgoing.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"reply\0\xff");
}

// Named paths route independently in both directions. Empty/binary bytes and
// duplicate destinations conserve bytes and preserve half-close (drydock#12).
async fn routing(session: &dyn SshSession, fixture: &Fixture, operations: Vec<(bool, usize, Vec<u8>)>) {
    let paths = [fixture.path("a"), fixture.path("b")];
    let local = [UnixListener::bind(&paths[0]).unwrap(), UnixListener::bind(&paths[1]).unwrap()];
    let reverse_paths = [fixture.path("ra"), fixture.path("rb")];
    let reverse = [session.listen_unix(&reverse_paths[0]).await.unwrap(), session.listen_unix(&reverse_paths[1]).await.unwrap()];
    for (backwards, index, payload) in operations {
        if backwards {
            let outgoing = UnixStream::connect(&reverse_paths[index]).await.unwrap();
            transfer(Box::new(outgoing), reverse[index].accept().await.unwrap(), &payload).await;
        } else {
            let outgoing = session.open_unix(&paths[index]).await.unwrap();
            transfer(outgoing, Box::new(local[index].accept().await.unwrap().0), &payload).await;
        }
    }
}
#[tokio::test]
async fn routes_bytes_and_half_close() {
    tokio::time::timeout(BUDGET, async {
        let f = Fixture::new().await;
        let s = f.session().await;
        let operations = (0..2)
            .flat_map(|_| {
                [false, true].into_iter().flat_map(|back| {
                    (0..2).flat_map(move |i| [vec![], b"\0arbitrary\xffpayload".to_vec()].into_iter().map(move |p| (back, i, p)))
                })
            })
            .collect();
        routing(s.as_ref(), &f, operations).await;
    })
    .await
    .unwrap();
}

// Generated operation sequences cover both directions, duplicate targets and
// arbitrary binary payloads (length 0..4097 crosses buffering boundaries).
// Each step asserts routing, conservation and half-close, using a real sshd.
#[test]
fn generated_bidirectional_routes() {
    use hegel::generators as gs;
    hegel::Hegel::new(|tc: hegel::TestCase| {
        let count = tc.draw(gs::integers::<usize>().min_value(1).max_value(8));
        let operations = (0..count)
            .map(|_| {
                let back = tc.draw(gs::booleans());
                let index = tc.draw(gs::integers::<usize>().min_value(0).max_value(1));
                let len = tc.draw(gs::integers::<usize>().min_value(0).max_value(4097));
                let byte = tc.draw(gs::integers::<u8>());
                (back, index, (0..len).map(|i| byte.wrapping_add(i as u8)).collect())
            })
            .collect();
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            tokio::time::timeout(BUDGET, async {
                let f = Fixture::new().await;
                let s = f.session().await;
                routing(s.as_ref(), &f, operations).await;
            })
            .await
            .unwrap();
        });
    })
    .settings(hegel::Settings::new().test_cases(12).seed(Some(3514)))
    .run();
}

// Seed contract: concurrent opens preserve each stream's payload and route,
// including simultaneous opens to the same target in both directions.
#[tokio::test]
async fn concurrent_opens() {
    tokio::time::timeout(BUDGET, async {
        let f = Fixture::new().await;
        let s = f.session().await;
        let paths = [f.path("a"), f.path("b")];
        let local = [UnixListener::bind(&paths[0]).unwrap(), UnixListener::bind(&paths[1]).unwrap()];
        let reverse = f.path("reverse");
        let incoming = s.listen_unix(&reverse).await.unwrap();
        let mut tasks = JoinSet::new();
        for i in 0..16u8 {
            let s = s.clone();
            let path = paths[usize::from(i % 2)].clone();
            let reverse = reverse.clone();
            tasks.spawn(async move {
                let mut a = s.open_unix(&path).await.unwrap();
                a.write_all(&[i % 2, i]).await.unwrap();
                a.shutdown().await.unwrap();
                let mut b = UnixStream::connect(reverse).await.unwrap();
                b.write_all(&[i]).await.unwrap();
                b.shutdown().await.unwrap();
            });
        }
        for (index, listener) in local.iter().enumerate() {
            let mut seen = Vec::new();
            for _ in 0..8 {
                let mut bytes = Vec::new();
                listener.accept().await.unwrap().0.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes[0] as usize, index);
                seen.push(bytes[1]);
            }
            seen.sort();
            assert_eq!(seen, (0..16u8).filter(|i| usize::from(i % 2) == index).collect::<Vec<_>>());
        }
        let mut seen = Vec::new();
        for _ in 0..16 {
            let mut bytes = Vec::new();
            incoming.accept().await.unwrap().read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes.len(), 1);
            seen.push(bytes[0]);
        }
        seen.sort();
        assert_eq!(seen, (0..16).collect::<Vec<_>>());
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
    })
    .await
    .unwrap();
}

// Seed contract: a backpressured stream cannot stall other channels in either
// direction. The writer must remain blocked while bidirectional probes finish.
#[tokio::test]
async fn stall_isolation_in_both_directions() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for reverse in [false, true] {
            let f = Fixture::new().await;
            let s = f.session().await;
            let path = f.path("guest");
            let local = UnixListener::bind(&path).unwrap();
            let rp = f.path("reverse");
            let listener = s.listen_unix(&rp).await.unwrap();
            let (mut writer, _unread): (ByteStream, ByteStream) = if reverse {
                let out = UnixStream::connect(&rp).await.unwrap();
                (Box::new(out), listener.accept().await.unwrap())
            } else {
                let out = s.open_unix(&path).await.unwrap();
                (out, Box::new(local.accept().await.unwrap().0))
            };
            let writer = tokio::spawn(async move { writer.write_all(&vec![7; 16 * 1024 * 1024]).await });
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(!writer.is_finished(), "fixture must actually backpressure the raw stream");
            for _ in 0..12 {
                let out = s.open_unix(&path).await.unwrap();
                transfer(out, Box::new(local.accept().await.unwrap().0), b"control").await;
                let out = UnixStream::connect(&rp).await.unwrap();
                transfer(Box::new(out), listener.accept().await.unwrap(), b"router").await;
            }
            assert!(!writer.is_finished());
            writer.abort();
            let _ = writer.await;
        }
    })
    .await
    .unwrap();
}

// Seed contract: neither the wrong pinned host key nor a rejected identity
// yields a usable authenticated session, even if a different key is accepted.
#[tokio::test]
async fn rejects_wrong_host_or_identity() {
    for wrong_host in [false, true] {
        let f = Fixture::new().await;
        let mut target = f.target.clone();
        if let Target::Pinned { host_key, identity_file, .. } = &mut target {
            if wrong_host {
                *host_key = std::fs::read_to_string(f.path("user_key.pub")).unwrap().trim().into();
            } else {
                *identity_file = f.path("host_key");
            }
        }
        let error = OpenSsh::connect(target, BUDGET).await.err().expect("must refuse authentication");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    }
}

// Seed contract: remote forwarding rejection fails setup, and a subsequent
// valid listener succeeds; local socket creation alone is not readiness.
#[tokio::test]
async fn rejected_forward_fails_setup_and_allows_retry() {
    let f = Fixture::new().await;
    let s = f.session().await;
    let missing = f.path("missing/remote");
    assert!(s.listen_unix(&missing).await.is_err());
    let valid = f.path("valid");
    let listener = s.listen_unix(&valid).await.unwrap();
    let stream = UnixStream::connect(&valid).await.unwrap();
    tokio::time::timeout(BUDGET, transfer(Box::new(stream), listener.accept().await.unwrap(), b"retry")).await.unwrap();
}

// Exec exposes the remote exit status and keeps stdout/stderr separate. This
// single shell command covers the process delegation and binary output shape.
#[tokio::test]
async fn exec_status_and_stderr() {
    let f = Fixture::new().await;
    let s = f.session().await;
    let output = s.exec("printf 'out'; printf 'err' >&2; exit 23").await.unwrap();
    assert_eq!(output.status.code(), Some(23));
    assert_eq!(output.stdout, b"out");
    assert_eq!(output.stderr, b"err");
    assert!(s.exec("exit 0").await.unwrap().status.success());
}

// Seed contract: dropping the owner closes remote listeners and active streams;
// a listener handle must not accidentally keep the session master alive.
#[tokio::test]
async fn drop_closes_session() {
    let f = Fixture::new().await;
    let s = f.session().await;
    let path = f.path("reverse");
    let listener = s.listen_unix(&path).await.unwrap();
    let mut out = UnixStream::connect(&path).await.unwrap();
    let _incoming = listener.accept().await.unwrap();
    drop(s);
    tokio::time::timeout(BUDGET, async {
        loop {
            if UnixStream::connect(&path).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut bytes = Vec::new();
        out.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.is_empty());
        assert!(listener.accept().await.is_err());
    })
    .await
    .unwrap();
}

// Session closing wakes every observer and pending accept, and new opens fail.
#[tokio::test]
async fn closure_is_reported() {
    let f = Fixture::new().await;
    let s = f.session().await;
    let incoming = s.listen_unix(&f.path("reverse")).await.unwrap();
    // Killing the master via its existing transport simulates network/session loss.
    s.exec("kill -HUP $PPID").await.ok();
    tokio::time::timeout(BUDGET, async {
        tokio::join!(s.closed(), s.closed());
        assert!(incoming.accept().await.is_err());
        assert!(s.open_unix(&f.path("any")).await.is_err());
        assert!(s.exec("true").await.is_err());
    })
    .await
    .unwrap();
}

// Listener ownership is independent of accepted streams: dropping it cancels
// new arrivals but does not cut an existing channel off from its session.
#[tokio::test]
async fn listener_drop_preserves_accepted_stream() {
    let f = Fixture::new().await;
    let s = f.session().await;
    let path = f.path("reverse");
    let listener = s.listen_unix(&path).await.unwrap();
    let out = UnixStream::connect(&path).await.unwrap();
    let incoming = listener.accept().await.unwrap();
    drop(listener);
    tokio::time::timeout(BUDGET, async {
        while UnixStream::connect(&path).await.is_ok() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        transfer(Box::new(out), incoming, b"survives").await;
    })
    .await
    .unwrap();
}

// Invalid path syntax must never be reinterpreted as TCP forwarding syntax or
// options. Cancellation of an accept must not consume the next queued stream.
#[tokio::test]
async fn invalid_paths_and_cancelled_accept() {
    let f = Fixture::new().await;
    let s = f.session().await;
    for path in ["", "relative", "/tmp/with:colon", "/tmp/with space", "/tmp/with\nnewline", "/tmp/with\0nul"] {
        let path = std::path::Path::new(path);
        assert_eq!(s.open_unix(path).await.err().unwrap().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(s.listen_unix(path).await.err().unwrap().kind(), io::ErrorKind::InvalidInput);
    }
    let path = f.path("reverse");
    let listener = s.listen_unix(&path).await.unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(20), listener.accept()).await.is_err());
    let out = UnixStream::connect(&path).await.unwrap();
    tokio::time::timeout(BUDGET, transfer(Box::new(out), listener.accept().await.unwrap(), b"after cancel")).await.unwrap();
}

// Raw key pinning refuses known-hosts options, markers and certificate keys
// before attempting authentication, including empty and malformed material.
#[tokio::test]
async fn invalid_pins_and_missing_identity_are_rejected() {
    let f = Fixture::new().await;
    for key in [
        "",
        "@cert-authority ssh-ed25519 AAAA",
        "@revoked ssh-ed25519 AAAA",
        "ssh-ed25519-cert-v01@openssh.com AAAA",
        "ssh-ed25519",
        "ssh-ed25519 bad!",
        "ssh-ed25519 AAAA\n",
    ] {
        let mut target = f.target.clone();
        if let Target::Pinned { host_key, .. } = &mut target {
            *host_key = key.into();
        }
        assert_eq!(OpenSsh::connect(target, BUDGET).await.err().unwrap().kind(), io::ErrorKind::InvalidInput);
    }
    let mut target = f.target.clone();
    if let Target::Pinned { identity_file, .. } = &mut target {
        *identity_file = f.path("missing-key");
    }
    assert_eq!(OpenSsh::connect(target, BUDGET).await.err().unwrap().kind(), io::ErrorKind::NotFound);
    assert_eq!(OpenSsh::connect(f.target.clone(), Duration::ZERO).await.err().unwrap().kind(), io::ErrorKind::InvalidInput);
}

// Ambient destinations resolve aliases, account, identity and host trust through
// the operator's config. Run in an isolated subprocess so PATH/config injection
// cannot race other tests or touch the real operator's ~/.ssh/config.
#[tokio::test]
async fn ambient_operator_configuration() {
    if std::env::var_os("RIGGING_AMBIENT_CHILD").is_some() {
        let session = OpenSsh::connect(Target::Ambient { destination: "rigging-contract-alias".into() }, BUDGET).await.unwrap();
        let output = session.exec("printf ambient").await.unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"ambient");
        return;
    }
    let f = Fixture::new().await;
    isolated_child(&f, "ambient_operator_configuration", "").await;
}

async fn isolated_child(f: &Fixture, test: &str, shim: &str) {
    use std::os::unix::fs::PermissionsExt;
    let Target::Pinned { host, port, user, host_key, identity_file } = &f.target else { unreachable!() };
    let known_hosts = f.path("operator_known_hosts");
    std::fs::write(&known_hosts, format!("[{host}]:{port} {host_key}\n")).unwrap();
    let config = f.path("operator_config");
    std::fs::write(&config, format!("Host rigging-contract-alias\n HostName {host}\n Port {port}\n User {user}\n IdentityFile {}\n IdentitiesOnly yes\n StrictHostKeyChecking yes\n UserKnownHostsFile {}\n ForkAfterAuthentication yes\n", identity_file.display(), known_hosts.display())).unwrap();
    let bin = f.path("bin");
    std::fs::create_dir(&bin).unwrap();
    // Process boundary shim supplies an isolated operator config to the real
    // OpenSSH executable; all authentication, multiplexing and exec remain real.
    let ssh = bin.join("ssh");
    std::fs::write(&ssh, format!("#!/bin/sh\n{shim}\nexec /usr/bin/ssh -F \"$RIGGING_TEST_OPERATOR_CONFIG\" \"$@\"\n")).unwrap();
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut paths = vec![bin];
    paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    let output = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env("RIGGING_AMBIENT_CHILD", "1")
        .env("RIGGING_TEST_FIXTURE", f.dir.path())
        .env("RIGGING_TEST_OPERATOR_CONFIG", &config)
        .env("PATH", std::env::join_paths(paths).unwrap())
        .kill_on_drop(true)
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "child stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

// A stalled setup for one path must not block the first open of another path.
// The process boundary shim pauses only the slow forwarding request, while real
// OpenSSH and sshd establish and transfer data through the independent fast one.
#[tokio::test]
async fn concurrent_first_opens_are_independent() {
    if std::env::var_os("RIGGING_AMBIENT_CHILD").is_some() {
        let dir = PathBuf::from(std::env::var_os("RIGGING_TEST_FIXTURE").unwrap());
        let session: Arc<dyn SshSession> =
            Arc::new(OpenSsh::connect(Target::Ambient { destination: "rigging-contract-alias".into() }, BUDGET).await.unwrap());
        let slow_path = dir.join("slow-target");
        let fast_path = dir.join("fast-target");
        let slow_listener = UnixListener::bind(&slow_path).unwrap();
        let fast_listener = UnixListener::bind(&fast_path).unwrap();
        let slow_session = session.clone();
        let slow = tokio::spawn(async move { slow_session.open_unix(&slow_path).await });
        tokio::time::timeout(BUDGET, async {
            while !tokio::fs::try_exists(dir.join("entered")).await.unwrap() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let fast = tokio::time::timeout(Duration::from_secs(1), session.open_unix(&fast_path)).await;
        // Release the stalled process even if the assertion below fails.
        tokio::fs::write(dir.join("release"), b"").await.unwrap();
        transfer(
            fast.expect("unrelated first-open must not wait for slow setup").unwrap(),
            Box::new(fast_listener.accept().await.unwrap().0),
            b"fast",
        )
        .await;
        transfer(slow.await.unwrap().unwrap(), Box::new(slow_listener.accept().await.unwrap().0), b"slow").await;
        return;
    }
    let f = Fixture::new().await;
    isolated_child(
        &f,
        "concurrent_first_opens_are_independent",
        r#"
for argument do
    case "$argument" in
        *slow-target*)
            touch "$RIGGING_TEST_FIXTURE/entered"
            count=0
            while [ ! -f "$RIGGING_TEST_FIXTURE/release" ] && [ "$count" -lt 100 ]; do
                sleep 0.05
                count=$((count + 1))
            done
            ;;
    esac
done
"#,
    )
    .await;
}

// Public session/listener values may outlive the runtime. Dropping them then
// must not panic; best-effort cleanup still closes the remote forwarding socket.
#[test]
fn listener_drop_after_runtime_shutdown() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let (fixture, session, listener) = runtime.block_on(async {
        let f = Fixture::new().await;
        let s = f.session().await;
        let listener = s.listen_unix(&f.path("reverse")).await.unwrap();
        (f, s, listener)
    });
    drop(runtime);
    drop(listener);
    drop(session);
    let started = std::time::Instant::now();
    while std::os::unix::net::UnixStream::connect(fixture.path("reverse")).is_ok() {
        assert!(started.elapsed() < BUDGET, "remote listener must close after runtime shutdown");
        std::thread::sleep(Duration::from_millis(10));
    }
}

// Exec has no implicit deadline. A caller's timeout cancels its local client
// while leaving the shared session available for independent commands.
#[tokio::test]
async fn hanging_exec_can_be_cancelled_without_closing_session() {
    let f = Fixture::new().await;
    let s = f.session().await;
    assert!(tokio::time::timeout(Duration::from_millis(100), s.exec("sleep 2")).await.is_err());
    let output = tokio::time::timeout(Duration::from_secs(1), s.exec("printf alive")).await.unwrap().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"alive");
}

// Cached local forwards redial the remote Unix path on every connection. A new
// listener at the same remote path receives fresh streams without invalidation.
#[tokio::test]
async fn cached_forward_redials_replaced_remote_socket() {
    tokio::time::timeout(BUDGET, async {
        let f = Fixture::new().await;
        let s = f.session().await;
        let path = f.path("replaceable");
        for payload in [b"original".as_slice(), b"replacement".as_slice()] {
            let listener = UnixListener::bind(&path).unwrap();
            let out = s.open_unix(&path).await.unwrap();
            transfer(out, Box::new(listener.accept().await.unwrap().0), payload).await;
            drop(listener);
            tokio::fs::remove_file(&path).await.unwrap();
        }
    })
    .await
    .unwrap();
}
