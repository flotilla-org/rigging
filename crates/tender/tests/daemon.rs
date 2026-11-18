#![cfg(unix)]

#[path = "common/control.rs"]
mod control;

use std::{collections::BTreeSet, os::unix::fs::PermissionsExt, path::Path, time::Duration};

use control::{Control, Format};
use reqwest::Method;
use tender::{
    Availability, Error, Fingerprint, Label, PublicationId, PublishRequest, Session, Tender,
    api::{self, Instance, PublicationEntry, PublishEndpoint, TrustedInstance, TrustedMember, Untrust},
    daemon::{Daemon, Paths},
    ssh::{Identity, SshTender},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    task::JoinHandle,
    time::timeout,
};

fn root() -> tempfile::TempDir {
    tempfile::Builder::new().prefix("td-").permissions(std::fs::Permissions::from_mode(0o700)).tempdir().expect("root")
}

fn paths(root: &Path) -> Paths {
    Paths { config: root.join("config"), state: root.join("state"), runtime: root.join("runtime") }
}

/// An ordinary Unix-socket service that echoes each connection's bytes.
fn echo(path: &Path) -> JoinHandle<()> {
    let listener = UnixListener::bind(path).expect("echo listener");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    })
}

async fn echoes(mut stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin) {
    stream.write_all(b"ping").await.expect("write");
    let mut reply = [0; 4];
    timeout(Duration::from_secs(5), stream.read_exact(&mut reply)).await.expect("echo deadline").expect("echo");
    assert_eq!(&reply, b"ping");
}

fn publish_request(id: &PublicationId, endpoint: &Path) -> PublishEndpoint {
    PublishEndpoint { id: id.clone(), label: Label("echo".into()), display: "Echo".into(), endpoint: endpoint.into(), audience: None }
}

fn trusted(identity: &Identity) -> TrustedInstance {
    TrustedInstance { key: identity.public_key(), name: "peer".into(), route: None }
}

async fn eventually<F: Future<Output = bool>>(what: &str, mut check: impl FnMut() -> F) {
    timeout(Duration::from_secs(10), async {
        while !check().await {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}"));
}

async fn state_of(control: &Control, id: &PublicationId) -> Option<(Availability, u64)> {
    let entries: Vec<PublicationEntry> = control.get(api::PUBLICATIONS).await.expect("publications");
    entries
        .into_iter()
        .find(|entry| &entry.publication.id == id)
        .map(|entry| (entry.publication.availability, entry.publication.generation))
}

/// Aborted tasks release the previous daemon's store lock as they unwind; a
/// separate process releases it on exit.
async fn restart(root: &Path) -> Daemon {
    timeout(Duration::from_secs(5), async {
        loop {
            match Daemon::start(paths(root)).await {
                Ok(daemon) => return daemon,
                Err(error) if error.to_string().contains("would block") || error.to_string().contains("WouldBlock") => {
                    tokio::time::sleep(Duration::from_millis(20)).await
                }
                Err(error) => panic!("restart: {error}"),
            }
        }
    })
    .await
    .expect("previous daemon releases its store")
}

// The instance keeps one key across restarts, and the control API answers in
// JSON or CBOR as the client asks.
#[tokio::test]
async fn identity_persists_and_control_speaks_json_and_cbor() {
    let root = root();
    let daemon = Daemon::start(paths(root.path())).await.expect("daemon");
    let control = Control::new(&paths(root.path()).control_socket());
    let json: Instance = control.get(api::IDENTITY).await.expect("identity");
    let cbor: Instance = control.call::<(), _>(Method::GET, api::IDENTITY, None, Format::Cbor).await.expect("cbor identity");
    assert_eq!(json, cbor);
    assert_eq!(json.key.fingerprint(), Some(json.fingerprint.clone()));
    assert_eq!(json, daemon.instance());
    let peer = Identity::generate();
    let added: TrustedMember =
        control.call(Method::POST, api::TRUSTED, Some(&trusted(&peer)), Format::Cbor).await.expect("trust over CBOR");
    assert_eq!(added.fingerprint, peer.fingerprint());
    daemon.shutdown().await;
    let restarted = restart(root.path()).await;
    assert_eq!(restarted.instance().fingerprint, json.fingerprint);
    let members: Vec<TrustedMember> = control.get(api::TRUSTED).await.expect("trusted group");
    assert_eq!(members, vec![added], "the Trusted Group persists in configuration");
}

// A published local socket is reachable by Trusted Group members through the
// peer socket. A dead endpoint makes the publication unavailable, and it is
// published again once the endpoint answers; withdrawal is explicit.
#[tokio::test]
async fn published_endpoint_follows_its_service() {
    let root = root();
    let paths = paths(root.path());
    let daemon = Daemon::start(paths.clone()).await.expect("daemon");
    let control = Control::new(&paths.control_socket());
    let host = daemon.instance().fingerprint;
    let peer = Identity::generate();
    let _: TrustedMember = control.post(api::TRUSTED, &trusted(&peer)).await.expect("trust");
    let service = root.path().join("echo");
    let echo_task = echo(&service);
    let id = PublicationId::new("tender/test", "echo");
    let published: tender::Publication = control.post(api::PUBLISH, &publish_request(&id, &service)).await.expect("publish");
    assert_eq!((published.availability, published.audience.clone()), (Availability::Available, BTreeSet::from([peer.fingerprint()])));
    let refused: Result<tender::Publication, _> = control.post(api::PUBLISH, &publish_request(&id, &service)).await;
    assert_eq!(refused.expect_err("live incumbent").1.code, "live_publisher");
    let entries: Vec<PublicationEntry> = control.get(api::PUBLICATIONS).await.expect("publications");
    assert_eq!(entries[0].endpoint.as_deref(), Some(service.as_path()));

    let client = SshTender::new(paths.peer_socket(), host.clone(), vec![peer.clone()]).expect("peer client");
    let session = Session { caller: peer.fingerprint(), pinned_host: host, via: None };
    echoes(client.connect(&session, &id).await.expect("connect through Tender")).await;

    echo_task.abort();
    let _ = echo_task.await;
    std::fs::remove_file(&service).expect("service gone");
    eventually("dead endpoint becomes unavailable", || async {
        let _ = client.connect(&session, &id).await;
        state_of(&control, &id).await.map(|state| state.0) == Some(Availability::Unavailable)
    })
    .await;
    let _echo = echo(&service);
    eventually("recovered endpoint is published again", || async { state_of(&control, &id).await == Some((Availability::Available, 2)) })
        .await;
    echoes(client.connect(&session, &id).await.expect("connect after recovery")).await;

    let _: () = control.post(api::WITHDRAW, &id).await.expect("withdraw");
    assert_eq!(state_of(&control, &id).await, Some((Availability::Withdrawn, 2)));
    assert_eq!(client.connect(&session, &id).await.err(), Some(Error::Withdrawn));
    let again: Result<(), _> = control.post(api::WITHDRAW, &id).await;
    assert_eq!(again.expect_err("nothing to withdraw").0, http::StatusCode::NOT_FOUND);
}

// Only Trusted Group members reach the peer socket's publications; removing a
// member refuses it at once. Keys that are not keys, and the instance's own
// key, are refused.
#[tokio::test]
async fn trusted_group_admits_members_only() {
    let root = root();
    let paths = paths(root.path());
    let daemon = Daemon::start(paths.clone()).await.expect("daemon");
    let control = Control::new(&paths.control_socket());
    let host = daemon.instance().fingerprint;
    let member = Identity::generate();
    let outsider = Identity::generate();
    let _: TrustedMember = control.post(api::TRUSTED, &trusted(&member)).await.expect("trust");
    let client = SshTender::new(paths.peer_socket(), host.clone(), vec![member.clone(), outsider.clone()]).expect("client");
    let as_member = Session { caller: member.fingerprint(), pinned_host: host.clone(), via: None };
    let as_outsider = Session { caller: outsider.fingerprint(), pinned_host: host, via: None };
    assert!(client.browse(&as_member).await.is_ok());
    assert_eq!(client.browse(&as_outsider).await, Err(Error::Denied));
    let _: () = control.post(api::UNTRUST, &Untrust { fingerprint: member.fingerprint() }).await.expect("untrust");
    assert_eq!(client.browse(&as_member).await, Err(Error::Denied));
    let invalid = TrustedInstance { key: tender::PublicKey("not a key".into()), name: String::new(), route: None };
    let refused: Result<TrustedMember, _> = control.post(api::TRUSTED, &invalid).await;
    assert_eq!(refused.expect_err("invalid key").1.code, "invalid_key");
    let own = TrustedInstance { key: daemon.instance().key, name: String::new(), route: None };
    let refused: Result<TrustedMember, _> = control.post(api::TRUSTED, &own).await;
    assert_eq!(refused.expect_err("own key").1.code, "own_key");
    let missing: Result<(), _> = control.post(api::UNTRUST, &Untrust { fingerprint: Fingerprint("absent".into()) }).await;
    assert_eq!(missing.expect_err("not a member").0, http::StatusCode::NOT_FOUND);
}

// Configured publications are published at start, under the instance's host
// scope by default. A configured grant lets another instance publish into
// this one under that scope, for the Trusted Group.
#[tokio::test]
async fn configuration_publishes_endpoints_and_grants_scopes() {
    let root = root();
    let paths = paths(root.path());
    let service = root.path().join("echo");
    let _echo = echo(&service);
    let helper = Identity::generate();
    let member = Identity::generate();
    std::fs::create_dir_all(&paths.config).expect("config directory");
    std::fs::write(
        paths.config_file(),
        format!(
            "[[publication]]\nname = \"echo\"\nlabel = \"echo\"\ndisplay = \"Hand-run echo\"\nendpoint = \"{}\"\n\n[[grant]]\ngrantee = \"{}\"\nscope = \"vessel/7\"\n",
            service.display(),
            helper.fingerprint().0
        ),
    )
    .expect("config");
    std::fs::write(paths.trusted_file(), format!("[[instance]]\nkey = \"{}\"\nname = \"laptop\"\n", member.public_key().0))
        .expect("trusted");
    let daemon = Daemon::start(paths.clone()).await.expect("daemon");
    let host = daemon.instance().fingerprint;
    let control = Control::new(&paths.control_socket());
    let configured = PublicationId::new(format!("tender/{}", host.0), "echo");
    assert_eq!(state_of(&control, &configured).await, Some((Availability::Available, 1)));

    let client = SshTender::new(paths.peer_socket(), host.clone(), vec![helper.clone(), member.clone()]).expect("client");
    let as_helper = Session { caller: helper.fingerprint(), pinned_host: host.clone(), via: None };
    let request = |scope: &str| PublishRequest {
        id: PublicationId::new(scope, "cleat/default"),
        label: Label("cleat".into()),
        display: "Crew".into(),
        audience: None,
    };
    assert!(matches!(client.publish(&as_helper, request("vessel/8")).await, Err(Error::Denied)));
    let mut published = client.publish(&as_helper, request("vessel/7")).await.expect("granted publish");
    let visible = client.browse(&Session { caller: member.fingerprint(), pinned_host: host.clone(), via: None }).await.expect("browse");
    let vessel = visible.iter().find(|publication| publication.id == published.lease.id).expect("visible to the group");
    assert_eq!(vessel.audience, BTreeSet::from([member.fingerprint()]));
    let as_member = Session { caller: member.fingerprint(), pinned_host: host, via: None };
    let stream = client.connect(&as_member, &published.lease.id).await.expect("member connects");
    let mut service = timeout(Duration::from_secs(5), published.incoming.recv()).await.expect("accept deadline").expect("accepted");
    let pump = tokio::spawn(async move {
        let (mut reader, mut writer) = tokio::io::split(&mut service);
        let _ = tokio::io::copy(&mut reader, &mut writer).await;
    });
    echoes(stream).await;
    pump.abort();
}

// A Trusted Group that cannot be saved is not applied either: the member
// stays refused, the file keeps its last content, and the answer is 503.
#[tokio::test]
async fn unsaved_trust_change_is_rolled_back() {
    let root = root();
    let paths = paths(root.path());
    let daemon = Daemon::start(paths.clone()).await.expect("daemon");
    let control = Control::new(&paths.control_socket());
    let member = Identity::generate();
    std::fs::set_permissions(&paths.config, std::fs::Permissions::from_mode(0o500)).expect("read-only configuration");
    let refused: Result<TrustedMember, _> = control.post(api::TRUSTED, &trusted(&member)).await;
    std::fs::set_permissions(&paths.config, std::fs::Permissions::from_mode(0o700)).expect("writable again");
    let (status, body) = refused.expect_err("save fails");
    assert_eq!((status, body.code.as_str()), (http::StatusCode::SERVICE_UNAVAILABLE, "storage"));
    let members: Vec<TrustedMember> = control.get(api::TRUSTED).await.expect("trusted group");
    assert!(members.is_empty());
    assert!(!paths.trusted_file().exists());
    let client = SshTender::new(paths.peer_socket(), daemon.instance().fingerprint, vec![member.clone()]).expect("client");
    let session = Session { caller: member.fingerprint(), pinned_host: daemon.instance().fingerprint, via: None };
    assert_eq!(client.browse(&session).await, Err(Error::Denied));
}

// Sockets never depend on the directory the daemon starts in.
#[test]
fn relative_root_is_refused() {
    struct Env(&'static str);
    impl rigging_process::EnvVars for Env {
        fn get(&self, key: &str) -> Option<String> {
            match key {
                "TENDER_ROOT" => Some(self.0.into()),
                "HOME" => Some("/home/test".into()),
                _ => None,
            }
        }
    }
    assert!(Paths::from_env(&Env("relative/root")).is_err());
    let paths = Paths::from_env(&Env("/absolute")).expect("absolute root");
    assert_eq!(paths, Paths { config: "/absolute/config".into(), state: "/absolute/state".into(), runtime: "/absolute/runtime".into() });
}

// The binary serves until SIGTERM, from TENDER_ROOT alone.
#[tokio::test]
async fn binary_serves_until_terminated() {
    let root = root();
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_tender"))
        .arg("serve")
        .env("TENDER_ROOT", root.path())
        .env_remove("XDG_RUNTIME_DIR")
        .kill_on_drop(true)
        .spawn()
        .expect("tender serve");
    let socket = root.path().join("runtime/control");
    eventually("control socket", || async { UnixStream::connect(&socket).await.is_ok() }).await;
    let instance: Instance = Control::new(&socket).get(api::IDENTITY).await.expect("identity");
    assert_eq!(instance.peer_socket, root.path().join("runtime/peer"));
    // SAFETY: the child is still running, so its pid has not been reused.
    unsafe { libc::kill(child.id().expect("pid") as i32, libc::SIGTERM) };
    let status = timeout(Duration::from_secs(10), child.wait()).await.expect("exit deadline").expect("exit");
    assert!(status.success(), "{status}");
    assert!(!socket.exists(), "the control socket is removed on exit");
}
