#![cfg(unix)]

#[path = "common/control.rs"]
mod control;

use std::{
    collections::BTreeSet,
    fs::{self, Permissions},
    os::unix::fs::PermissionsExt,
    path::Path,
    time::Duration,
};

use control::{Control, Format};
use http::StatusCode;
use libc::{SIGTERM, kill};
use reqwest::Method;
use rigging_process::EnvVars;
use tempfile::{Builder, TempDir};
use tender::{
    Availability, Error, Fingerprint, Label, PublicKey, Publication, PublicationId, PublishRequest, Scope, Session, Tender,
    api::{self, Instance, PublicationList, PublishEndpoint, TrustedInstance, TrustedMember, Untrust},
    daemon::{Daemon, Paths},
    paths::binding_path,
    ssh::{Identity, SshTender},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy, split},
    net::{UnixListener, UnixStream},
    process::Command,
    spawn,
    task::JoinHandle,
    time::{sleep, timeout},
};

fn root() -> TempDir {
    Builder::new().prefix("td-").permissions(Permissions::from_mode(0o700)).tempdir().expect("root")
}

fn paths(root: &Path) -> Paths {
    Paths { config: root.join("config"), state: root.join("state"), runtime: root.join("runtime") }
}

/// An ordinary Unix-socket service that echoes each connection's bytes.
fn echo(path: &Path) -> JoinHandle<()> {
    let listener = UnixListener::bind(path).expect("echo listener");
    spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
            spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = copy(&mut reader, &mut writer).await;
            });
        }
    })
}

async fn echoes(mut stream: impl AsyncRead + AsyncWrite + Unpin) {
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
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}"));
}

async fn state_of(control: &Control, id: &PublicationId) -> Option<(Availability, u64)> {
    let list: PublicationList = control.get(api::PUBLICATIONS).await.expect("publications");
    list.publications
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
                    sleep(Duration::from_millis(20)).await
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
    let id = PublicationId::new("vessel/test", "echo");
    let published: Publication = control.post(api::PUBLISH, &publish_request(&id, &service)).await.expect("publish");
    let group = BTreeSet::from([peer.fingerprint(), host.clone()]);
    assert_eq!((published.availability, published.audience.clone()), (Availability::Available, group));
    let refused: Result<Publication, _> = control.post(api::PUBLISH, &publish_request(&id, &root.path().join("other"))).await;
    assert_eq!(refused.expect_err("live incumbent").1.code, "live_publisher");
    // A later publication makes the Binder reconcile; the refused socket
    // must not have reached it.
    let unrelated = PublicationId::new("vessel/test", "unrelated");
    let _: Publication = control.post(api::PUBLISH, &publish_request(&unrelated, &service)).await.expect("publish");
    let binding = |id| fs::read_link(binding_path(&paths.runtime, id)).ok();
    eventually("the later publication is bound", || async { binding(&unrelated) == Some(service.clone()) }).await;
    assert_eq!(binding(&id), Some(service.clone()), "the incumbent's Binding still reaches its socket");
    let list: PublicationList = control.get(api::PUBLICATIONS).await.expect("publications");
    let entry = list.publications.iter().find(|entry| entry.publication.id == id).expect("listed");
    assert_eq!(entry.endpoint.as_deref(), Some(service.as_path()));

    let client = SshTender::new(paths.peer_socket(), host.clone(), vec![peer.clone()]).expect("peer client");
    let session = Session { caller: peer.fingerprint(), pinned_host: host, via: None };
    echoes(client.connect(&session, &id).await.expect("connect through Tender")).await;

    echo_task.abort();
    let _ = echo_task.await;
    fs::remove_file(&service).expect("service gone");
    eventually("dead endpoint becomes unavailable", || async {
        let _ = client.connect(&session, &id).await;
        state_of(&control, &id).await.map(|state| state.0) == Some(Availability::Unavailable)
    })
    .await;
    let _echo = echo(&service);
    eventually("recovered endpoint is published again", || async {
        state_of(&control, &id)
            .await
            .is_some_and(|(availability, generation)| availability == Availability::Available && generation > published.generation)
    })
    .await;
    let (_, recovered) = state_of(&control, &id).await.expect("listed");
    echoes(client.connect(&session, &id).await.expect("connect after recovery")).await;

    let _: () = control.post(api::WITHDRAW, &id).await.expect("withdraw");
    assert_eq!(state_of(&control, &id).await, Some((Availability::Withdrawn, recovered)));
    assert_eq!(client.connect(&session, &id).await.err(), Some(Error::Withdrawn));
    let _: () = control.post(api::WITHDRAW, &id).await.expect("withdrawing again changes nothing");
    let unknown: Result<(), _> = control.post(api::WITHDRAW, &PublicationId::new("vessel/test", "never")).await;
    assert_eq!(unknown.expect_err("never published").0, StatusCode::NOT_FOUND);
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
    let invalid = TrustedInstance { key: PublicKey("not a key".into()), name: String::new(), route: None };
    let refused: Result<TrustedMember, _> = control.post(api::TRUSTED, &invalid).await;
    assert_eq!(refused.expect_err("invalid key").1.code, "invalid_key");
    let own = TrustedInstance { key: daemon.instance().key, name: String::new(), route: None };
    let refused: Result<TrustedMember, _> = control.post(api::TRUSTED, &own).await;
    assert_eq!(refused.expect_err("own key").1.code, "own_key");
    let missing: Result<(), _> = control.post(api::UNTRUST, &Untrust { fingerprint: Fingerprint("absent".into()) }).await;
    assert_eq!(missing.expect_err("not a member").0, StatusCode::NOT_FOUND);
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
    fs::create_dir_all(&paths.config).expect("config directory");
    fs::write(
        paths.config_file(),
        format!(
            "[[publication]]\nname = \"echo\"\nlabel = \"echo\"\ndisplay = \"Hand-run echo\"\nendpoint = \"{}\"\n\n[[grant]]\ngrantee = \"{}\"\nscope = \"vessel/7\"\n",
            service.display(),
            helper.fingerprint().0
        ),
    )
    .expect("config");
    fs::write(paths.trusted_file(), format!("[[instance]]\nkey = \"{}\"\nname = \"laptop\"\n", member.public_key().0)).expect("trusted");
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
    assert_eq!(vessel.audience, BTreeSet::from([member.fingerprint(), host.clone()]));
    let as_member = Session { caller: member.fingerprint(), pinned_host: host, via: None };
    let stream = client.connect(&as_member, &published.lease.id).await.expect("member connects");
    let mut service = timeout(Duration::from_secs(5), published.incoming.recv()).await.expect("accept deadline").expect("accepted");
    let pump = spawn(async move {
        let (mut reader, mut writer) = split(&mut service);
        let _ = copy(&mut reader, &mut writer).await;
    });
    echoes(stream).await;
    pump.abort();

    // An own publication taken over by the helper is reported, not withdrawn
    // on the helper's behalf, however often it is asked.
    let taken = PublicationId::new("vessel/7", "taken");
    let dead = publish_request(&taken, &root.path().join("absent"));
    let own: Publication = control.post(api::PUBLISH, &dead).await.expect("publish a dead endpoint");
    assert_eq!(own.availability, Availability::Unavailable);
    let request = PublishRequest { id: taken.clone(), ..request("vessel/7") };
    let _helper_lease = client.publish(&as_helper, request).await.expect("helper takes over");
    let refused: Result<(), _> = control.post(api::WITHDRAW, &taken).await;
    assert_eq!(refused.expect_err("taken over").1.code, "denied");
    let again: Result<(), _> = control.post(api::WITHDRAW, &taken).await;
    assert_eq!(again.expect_err("still not ours").1.code, "denied");
    let (availability, generation) = state_of(&control, &taken).await.expect("still listed");
    assert_eq!(availability, Availability::Available);
    assert!(generation > own.generation);
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
    fs::set_permissions(&paths.config, Permissions::from_mode(0o500)).expect("read-only configuration");
    let refused: Result<TrustedMember, _> = control.post(api::TRUSTED, &trusted(&member)).await;
    fs::set_permissions(&paths.config, Permissions::from_mode(0o700)).expect("writable again");
    let (status, body) = refused.expect_err("save fails");
    assert_eq!((status, body.code.as_str()), (StatusCode::SERVICE_UNAVAILABLE, "storage"));
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
    impl EnvVars for Env {
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
    let mut child = Command::new(env!("CARGO_BIN_EXE_tender"))
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
    unsafe { kill(child.id().expect("pid") as i32, SIGTERM) };
    let status = timeout(Duration::from_secs(10), child.wait()).await.expect("exit deadline").expect("exit");
    assert!(status.success(), "{status}");
    assert!(!socket.exists(), "the control socket is removed on exit");
}

// A restart publishes the configured endpoints again and withdraws the rest:
// API publications do not persist, and neither does an entry since removed
// from the configuration. The listing's epoch tells publishers to republish.
#[tokio::test]
async fn restart_resumes_configuration_and_withdraws_the_rest() {
    let root = root();
    let paths = paths(root.path());
    let service = root.path().join("echo");
    let _echo = echo(&service);
    let entry = |name: &str| format!("[[publication]]\nname = \"{name}\"\nlabel = \"echo\"\nendpoint = \"{}\"\n", service.display());
    fs::create_dir_all(&paths.config).expect("config directory");
    fs::write(paths.config_file(), format!("{}\n{}", entry("kept"), entry("dropped"))).expect("config");
    let daemon = Daemon::start(paths.clone()).await.expect("daemon");
    let scope = Scope::instance(&daemon.instance().fingerprint).0;
    let (kept, dropped) = (PublicationId::new(scope.clone(), "kept"), PublicationId::new(scope, "dropped"));
    let control = Control::new(&paths.control_socket());
    let api = PublicationId::new("vessel/1", "api");
    let _: Publication = control.post(api::PUBLISH, &publish_request(&api, &service)).await.expect("publish");
    let before: PublicationList = control.get(api::PUBLICATIONS).await.expect("publications");
    daemon.shutdown().await;

    fs::write(paths.config_file(), entry("kept")).expect("config without the dropped entry");
    let _daemon = restart(root.path()).await;
    let after: PublicationList = control.get(api::PUBLICATIONS).await.expect("publications");
    assert_ne!(after.epoch, before.epoch);
    assert_eq!(state_of(&control, &kept).await.map(|state| state.0), Some(Availability::Available));
    assert_eq!(state_of(&control, &dropped).await.map(|state| state.0), Some(Availability::Withdrawn));
    assert_eq!(state_of(&control, &api).await.map(|state| state.0), Some(Availability::Withdrawn));
}

// An endpoint is published by absolute path only: a relative one would
// resolve against the daemon's working directory.
#[tokio::test]
async fn relative_endpoint_is_refused() {
    let root = root();
    let paths = paths(root.path());
    let _daemon = Daemon::start(paths.clone()).await.expect("daemon");
    let control = Control::new(&paths.control_socket());
    let request = publish_request(&PublicationId::new("vessel/1", "echo"), Path::new("echo.sock"));
    let refused: Result<Publication, _> = control.post(api::PUBLISH, &request).await;
    let (status, error) = refused.expect_err("relative endpoint");
    assert_eq!((status, error.code.as_str()), (StatusCode::BAD_REQUEST, "relative_endpoint"));
}

// A publication whose endpoint does not answer is never announced as
// available; it becomes available once the endpoint answers.
#[tokio::test]
async fn dead_endpoint_is_never_announced_available() {
    let root = root();
    let paths = paths(root.path());
    let daemon = Daemon::start(paths.clone()).await.expect("daemon");
    let host = daemon.instance().fingerprint;
    let control = Control::new(&paths.control_socket());
    let peer = Identity::generate();
    let _: TrustedMember = control.post(api::TRUSTED, &trusted(&peer)).await.expect("trust");
    let client = SshTender::new(paths.peer_socket(), host.clone(), vec![peer.clone()]).expect("peer client");
    let mut watch = client.watch(&Session { caller: peer.fingerprint(), pinned_host: host, via: None }).await.expect("watch");
    let service = root.path().join("late");
    let id = PublicationId::new("vessel/1", "late");
    let published: Publication = control.post(api::PUBLISH, &publish_request(&id, &service)).await.expect("publish");
    assert_eq!(published.availability, Availability::Unavailable);
    let announced = |snapshot: &[Publication]| {
        snapshot.iter().any(|publication| publication.id == id && publication.availability == Availability::Available)
    };
    while let Ok(Some(snapshot)) = timeout(Duration::from_millis(300), watch.recv()).await {
        assert!(!announced(&snapshot), "announced before its endpoint answered");
    }
    let _echo = echo(&service);
    timeout(Duration::from_secs(10), async { while !announced(&watch.recv().await.expect("watch")) {} })
        .await
        .expect("available once the endpoint answers");
}

// A service that is briefly away, as when it restarts, does not make its
// publication flap: the stream that found it gone waits for it.
#[tokio::test]
async fn brief_endpoint_outage_keeps_the_publication() {
    let root = root();
    let paths = paths(root.path());
    let daemon = Daemon::start(paths.clone()).await.expect("daemon");
    let host = daemon.instance().fingerprint;
    let control = Control::new(&paths.control_socket());
    let peer = Identity::generate();
    let _: TrustedMember = control.post(api::TRUSTED, &trusted(&peer)).await.expect("trust");
    let service = root.path().join("echo");
    let first = echo(&service);
    let id = PublicationId::new("vessel/1", "echo");
    let published: Publication = control.post(api::PUBLISH, &publish_request(&id, &service)).await.expect("publish");
    first.abort();
    let _ = first.await;
    fs::remove_file(&service).expect("service away");
    let returning = spawn({
        let service = service.clone();
        async move {
            sleep(Duration::from_millis(100)).await;
            let _ = echo(&service).await;
        }
    });
    let client = SshTender::new(paths.peer_socket(), host.clone(), vec![peer.clone()]).expect("peer client");
    let session = Session { caller: peer.fingerprint(), pinned_host: host, via: None };
    echoes(client.connect(&session, &id).await.expect("connect")).await;
    returning.abort();
    assert_eq!(state_of(&control, &id).await, Some((Availability::Available, published.generation)));
}
