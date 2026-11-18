#![cfg(unix)]

// Shared with tests/daemon.rs, which uses the rest of it.
#[allow(dead_code)]
#[path = "common/control.rs"]
mod control;
#[path = "common/node.rs"]
mod node;
#[path = "common/ssh.rs"]
mod ssh_fixture;

use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::Path,
    time::Duration,
};
#[cfg(target_os = "linux")]
use std::{fs::Permissions, os::unix::fs::PermissionsExt};

use node::{Node, eventually};
#[cfg(target_os = "linux")]
use serde_json::from_slice;
use tender::{
    BindingState, Label, PublicationId, PublishRequest, Route, Scope, Session, Tender, UnavailableReason,
    api::{self, BindingEntry, Diagnostics, PeerState},
    paths::{self, binding_path},
    ssh::{Identity, SshTender},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy, split},
    net::{UnixListener, UnixStream},
    process::Command,
    spawn,
    task::JoinHandle,
    time::timeout,
};

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

async fn round_trip(path: &Path, message: &[u8]) -> bool {
    let Ok(mut stream) = UnixStream::connect(path).await else { return false };
    if stream.write_all(message).await.is_err() {
        return false;
    }
    let mut reply = vec![0; message.len()];
    matches!(timeout(Duration::from_secs(5), stream.read_exact(&mut reply)).await, Ok(Ok(_))) && reply == message
}

/// A connection the Binding, which must be there, refuses: no connection at
/// all, or one closed at once without a byte.
async fn refused_promptly(path: &Path) -> bool {
    if fs::symlink_metadata(path).is_err() {
        return false;
    }
    let Ok(mut stream) = UnixStream::connect(path).await else { return true };
    let _ = stream.write_all(b"x").await;
    let mut bytes = Vec::new();
    matches!(timeout(Duration::from_secs(2), stream.read_to_end(&mut bytes)).await, Ok(Ok(0)) | Ok(Err(_)))
}

// Two daemons on one machine with paired keys: a publication on one is bound
// on the other at the computed path, reaches an ordinary Unix-socket service,
// turns unavailable when withdrawn, follows a granted takeover in place, and
// an instance outside the Trusted Group is refused.
#[tokio::test]
async fn bindings_follow_publications_between_paired_daemons() {
    let helper = Identity::generate();
    let a = Node::start(&format!("[[grant]]\ngrantee = \"{}\"\nscope = \"vessel/7\"\n", helper.fingerprint().0)).await;
    let b = Node::start("").await;
    a.trust(&b).await;
    b.trust(&a).await;

    let service = a.root.path().join("echo.sock");
    let _echo = echo(&service);
    let id = PublicationId::new("vessel/7", "echo/main");
    a.cli(&["publish", "vessel/7", "echo/main", "--label", "echo", "--display", "Echo", "--endpoint", service.to_str().expect("path")])
        .await;

    // The Binding appears on B at the path any client computes.
    let path = paths::binding_path(&b.runtime(), &id);
    let computed = b.cli(&["path", "vessel/7", "echo/main"]).await;
    assert_eq!(String::from_utf8(computed.stdout).expect("path").trim(), path.to_str().expect("path"));
    eventually("B binds A's publication", || async {
        b.binding(&id).await.is_some_and(|binding| matches!(binding.state, BindingState::Available { .. }))
    })
    .await;
    let binding = b.binding(&id).await.expect("binding");
    assert_eq!((binding.local_endpoint.as_path(), &binding.label), (path.as_path(), &Label("echo".into())));
    assert_eq!(binding.state, BindingState::Available { route: Route { instance: a.instance.fingerprint.clone(), via: None } });
    assert!(round_trip(&path, b"through the binding").await, "the echo service answers through B's Binding");

    // On its own machine the Binding is a link to the socket itself.
    let own = paths::binding_path(&a.runtime(), &id);
    eventually("A binds its own publication", || async { fs::read_link(&own).ok() == Some(service.clone()) }).await;
    let inode = fs::symlink_metadata(&path).expect("binding socket").ino();

    // Withdrawal turns the Binding unavailable, and connects fail promptly.
    a.cli(&["withdraw", "vessel/7", "echo/main"]).await;
    eventually("withdrawal reaches B", || async {
        b.binding(&id)
            .await
            .is_some_and(|binding| matches!(binding.state, BindingState::Unavailable { reason: UnavailableReason::Withdrawn, .. }))
    })
    .await;
    assert!(refused_promptly(&path).await, "an unavailable Binding refuses or closes at once");
    eventually("A's own link gives way to a refusing listener", || async {
        fs::symlink_metadata(&own).is_ok_and(|metadata| metadata.file_type().is_socket())
    })
    .await;
    assert!(refused_promptly(&own).await, "the withdrawn service is not reachable through its old link");

    // A helper granted the scope takes over; B's Binding follows in place.
    let client = SshTender::new(a.instance.peer_socket.clone(), a.instance.fingerprint.clone(), vec![helper.clone()]).expect("helper");
    let session = Session { caller: helper.fingerprint(), pinned_host: a.instance.fingerprint.clone(), via: None };
    let request = PublishRequest { id: id.clone(), label: Label("echo".into()), display: "Echo, taken over".into(), audience: None };
    let mut published = client.publish(&session, request).await.expect("granted takeover");
    let serving = spawn(async move {
        while let Some(mut stream) = published.incoming.recv().await {
            spawn(async move {
                let (mut reader, mut writer) = split(&mut stream);
                let _ = copy(&mut reader, &mut writer).await;
            });
        }
    });
    eventually("B follows the takeover", || async {
        b.binding(&id)
            .await
            .is_some_and(|binding| matches!(binding.state, BindingState::Available { .. }) && binding.display == "Echo, taken over")
    })
    .await;
    assert_eq!(fs::symlink_metadata(&path).expect("binding socket").ino(), inode, "the Binding is not recreated");
    assert!(round_trip(&path, b"to the new publisher").await);
    serving.abort();

    // An instance outside A's Trusted Group follows A but is refused.
    let outsider = Node::start("").await;
    outsider.trust(&a).await;
    eventually("A refuses the outsider", || async {
        let diagnostics: Diagnostics = outsider.control.get(api::DIAGNOSTICS).await.expect("diagnostics");
        diagnostics.peers.iter().any(|peer| matches!(&peer.state, PeerState::Unreachable { reason } if reason.contains("Denied")))
    })
    .await;
    assert!(outsider.binding(&id).await.is_none());
    assert!(!paths::binding_path(&outsider.runtime(), &id).exists());
}

// A Binding follows its identity from one instance to another, as a vessel
// does when it moves host: when the first publisher's copy is withdrawn, the
// Binding takes the route through the second, keeping its Local Endpoint.
#[tokio::test]
async fn binding_moves_between_instances_publishing_one_identity() {
    let first = Node::start("").await;
    let second = Node::start("").await;
    let viewer = Node::start("").await;
    for host in [&first, &second] {
        host.trust(&viewer).await;
        viewer.trust(host).await;
    }
    let id = PublicationId::new("vessel/9", "http/5173");
    let publish = |node: &Node, service: &Path| {
        let args =
            ["publish", "vessel/9", "http/5173", "--label", "http", "--endpoint", service.to_str().expect("path")].map(str::to_owned);
        let root = node.root.path().to_owned();
        async move {
            let output = Command::new(env!("CARGO_BIN_EXE_tender")).args(&args).env("TENDER_ROOT", &root).output().await.expect("CLI");
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        }
    };
    let old = first.root.path().join("old.sock");
    let new = second.root.path().join("new.sock");
    let _old = echo(&old);
    let _new = echo(&new);
    publish(&first, &old).await;
    let path = paths::binding_path(&viewer.runtime(), &id);
    let carried_by = |node: &Node| {
        let instance = node.instance.fingerprint.clone();
        move |binding: Option<BindingEntry>| {
            binding.is_some_and(|binding| matches!(binding.state, BindingState::Available { route } if route.instance == instance))
        }
    };
    eventually("viewer binds the first host's copy", || async { carried_by(&first)(viewer.binding(&id).await) }).await;
    let inode = fs::symlink_metadata(&path).expect("binding").ino();
    publish(&second, &new).await;
    first.cli(&["withdraw", "vessel/9", "http/5173"]).await;
    eventually("viewer follows the identity to the second host", || async { carried_by(&second)(viewer.binding(&id).await) }).await;
    assert_eq!(fs::symlink_metadata(&path).expect("binding").ino(), inode);
    assert!(round_trip(&path, b"moved").await);
}

// Pairing exchanges keys over a working SSH destination once the far
// instance's fingerprint is confirmed: each side trusts the other's key and
// follows the other through an SSH forward to its peer socket. A wrapper on
// PATH stands in for the operator's ssh_config, pointing the destination at a
// loopback sshd, which both sides use to reach each other.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn pairing_over_ssh_binds_through_a_forward() {
    let sshd = ssh_fixture::Sshd::start().await;
    let alias = node::SshAlias::new(&sshd);
    let far = Node::start_with("", alias.env.clone()).await;
    let near = Node::start_with("", alias.env.clone()).await;
    let remote = format!("env TENDER_ROOT={} {}", far.root.path().display(), env!("CARGO_BIN_EXE_tender"));
    let pair =
        ["trust", "pair", "tender-peer", "--name", "far", "--as-name", "near", "--return", "tender-peer", "--remote-tender", &remote];
    let unconfirmed = near.run(&pair).await;
    assert!(!unconfirmed.status.success(), "no terminal and no expected fingerprint");
    assert!(String::from_utf8_lossy(&unconfirmed.stderr).contains(&far.instance.fingerprint.0), "the fingerprint is shown");
    let wrong = near.run(&[&pair[..], &["--expect-fingerprint", &near.instance.fingerprint.0]].concat()).await;
    assert!(!wrong.status.success(), "a different instance answered");
    // A far side that refuses to trust this one leaves this one trusting
    // nothing either.
    let refusing = near.root.path().join("refusing-tender");
    fs::write(&refusing, format!("#!/bin/sh\ncase \"$*\" in *accept*) echo refused >&2; exit 1;; esac\nexec {remote} \"$@\"\n"))
        .expect("refusing tender");
    fs::set_permissions(&refusing, Permissions::from_mode(0o700)).expect("executable");
    let expect = ["--expect-fingerprint", &far.instance.fingerprint.0];
    let refused = near.run(&[&pair[..pair.len() - 1], &[refusing.to_str().expect("path")], &expect[..]].concat()).await;
    assert!(!refused.status.success(), "the far side refused");
    for node in [&far, &near] {
        let members: Vec<api::TrustedMember> = node.control.get(api::TRUSTED).await.expect("group");
        assert!(members.is_empty(), "nothing trusted unconfirmed or refused");
    }
    near.cli(&[&pair[..], &["--expect-fingerprint", &far.instance.fingerprint.0]].concat()).await;
    let far_members = far.cli(&["--json", "trust", "list"]).await;
    let far_members: Vec<api::TrustedMember> = from_slice(&far_members.stdout).expect("far's group");
    assert_eq!(
        (far_members.len(), &far_members[0].fingerprint, far_members[0].instance.name.as_str()),
        (1, &near.instance.fingerprint, "near")
    );
    let back = far_members[0].instance.route.clone().expect("a route back");
    assert_eq!((back.ssh.as_deref(), back.socket.as_path()), (Some("tender-peer"), near.instance.peer_socket.as_path()));
    let near_members: Vec<api::TrustedMember> = near.control.get(api::TRUSTED).await.expect("near's group");
    let route = near_members[0].instance.route.clone().expect("route to far");
    assert_eq!((route.ssh.as_deref(), route.socket.as_path()), (Some("tender-peer"), far.instance.peer_socket.as_path()));

    let service = far.root.path().join("echo.sock");
    let _echo = echo(&service);
    far.cli(&["publish", "vessel/3", "cleat/default", "--label", "cleat", "--endpoint", service.to_str().expect("path")]).await;
    let id = PublicationId::new("vessel/3", "cleat/default");
    eventually("near binds far's publication over SSH", || async {
        near.binding(&id).await.is_some_and(|binding| matches!(binding.state, BindingState::Available { .. }))
    })
    .await;
    let path = paths::binding_path(&near.runtime(), &id);
    assert!(round_trip(&path, b"over ssh").await);
    let near_service = near.root.path().join("echo.sock");
    let _near_echo = echo(&near_service);
    near.cli(&["publish", "vessel/3", "http", "--label", "http", "--endpoint", near_service.to_str().expect("path")]).await;
    let back = PublicationId::new("vessel/3", "http");
    eventually("far binds near's publication over SSH too", || async {
        round_trip(&paths::binding_path(&far.runtime(), &back), b"the other way").await
    })
    .await;

    // Losing SSH makes the Binding unavailable in place; a fresh forward
    // restores it once SSH works again.
    alias.sever();
    eventually("the route loss reaches the Binding", || async {
        near.binding(&id)
            .await
            .is_some_and(|binding| matches!(binding.state, BindingState::Unavailable { reason: UnavailableReason::RouteUnavailable, .. }))
    })
    .await;
    assert!(refused_promptly(&path).await);
    alias.restore();
    eventually("a fresh forward restores the Binding", || async {
        near.binding(&id).await.is_some_and(|binding| matches!(binding.state, BindingState::Available { .. }))
    })
    .await;
    assert!(round_trip(&path, b"after the outage").await);
}

// Accepting a key already trusted with a route keeps the route, so pairing
// in the other direction does not stop this side following the peer.
#[tokio::test]
async fn accepting_a_member_keeps_its_route() {
    let near = Node::start("").await;
    let far = Node::start("").await;
    near.trust(&far).await;
    near.cli(&["trust", "accept", &far.instance.key.0, "--name", "far"]).await;
    let members: Vec<api::TrustedMember> = near.control.get(api::TRUSTED).await.expect("group");
    let route = members[0].instance.route.as_ref().map(|route| route.socket.as_path());
    assert_eq!((members.len(), members[0].instance.name.as_str(), route), (1, "far", Some(far.instance.peer_socket.as_path())));
}

// Changing a member's route restarts its follower: a member trusted at a
// wrong socket is unreachable until its route is corrected.
#[tokio::test]
async fn corrected_route_restarts_following() {
    let host = Node::start("").await;
    let viewer = Node::start("").await;
    host.trust(&viewer).await;
    let wrong = viewer.root.path().join("nowhere");
    viewer.cli(&["trust", "add", &host.instance.key.0, "--socket", wrong.to_str().expect("path")]).await;
    eventually("the wrong route is unreachable", || async {
        let diagnostics: Diagnostics = viewer.control.get(api::DIAGNOSTICS).await.expect("diagnostics");
        diagnostics.peers.iter().any(|peer| matches!(peer.state, PeerState::Unreachable { .. }))
    })
    .await;
    let service = host.root.path().join("echo.sock");
    let _echo = echo(&service);
    host.cli(&["publish", "vessel/5", "echo", "--label", "echo", "--endpoint", service.to_str().expect("path")]).await;
    viewer.trust(&host).await;
    let id = PublicationId::new("vessel/5", "echo");
    eventually("the corrected route is followed", || async {
        viewer.binding(&id).await.is_some_and(|binding| matches!(binding.state, BindingState::Available { .. }))
    })
    .await;
    assert!(round_trip(&paths::binding_path(&viewer.runtime(), &id), b"rerouted").await);
}

// A withdrawn publication's Binding stays for its grace, then goes, on the
// publishing instance and on the one following it; publishing the identity
// again brings it back at the same path.
#[tokio::test]
async fn withdrawn_bindings_end_after_their_grace() {
    let a = Node::start("binding_grace_seconds = 1\n").await;
    let b = Node::start("binding_grace_seconds = 1\n").await;
    a.trust(&b).await;
    b.trust(&a).await;
    let service = a.root.path().join("echo.sock");
    let _echo = echo(&service);
    let endpoint = service.to_str().expect("path");
    let id = PublicationId::new("vessel/4", "echo");
    a.cli(&["publish", "vessel/4", "echo", "--label", "echo", "--endpoint", endpoint]).await;
    let (path, own) = (binding_path(&b.runtime(), &id), binding_path(&a.runtime(), &id));
    eventually("B binds it", || async { round_trip(&path, b"before").await }).await;
    a.cli(&["withdraw", "vessel/4", "echo"]).await;
    eventually("withdrawal reaches B", || async {
        b.binding(&id)
            .await
            .is_some_and(|binding| matches!(binding.state, BindingState::Unavailable { reason: UnavailableReason::Withdrawn, .. }))
    })
    .await;
    assert!(refused_promptly(&path).await, "during its grace the Binding refuses");
    eventually("the grace ends the Bindings", || async {
        b.binding(&id).await.is_none() && a.binding(&id).await.is_none() && !path.exists() && fs::symlink_metadata(&own).is_err()
    })
    .await;
    a.cli(&["publish", "vessel/4", "echo", "--label", "echo", "--endpoint", endpoint]).await;
    eventually("publishing again binds it again at the same path", || async { round_trip(&path, b"after").await }).await;
}

// A `tender/<fingerprint>` scope is followed from that instance alone: a
// helper's instance scope published into A is bound neither on A nor on B,
// while A's own instance scope is.
#[tokio::test]
async fn instance_scopes_are_followed_from_their_instance_only() {
    let helper = Identity::generate();
    let helper_scope = Scope::instance(&helper.fingerprint()).0;
    let a = Node::start(&format!("[[grant]]\ngrantee = \"{}\"\nscope = \"{helper_scope}\"\n", helper.fingerprint().0)).await;
    let b = Node::start("").await;
    a.trust(&b).await;
    b.trust(&a).await;
    let client = SshTender::new(a.instance.peer_socket.clone(), a.instance.fingerprint.clone(), vec![helper.clone()]).expect("helper");
    let session = Session { caller: helper.fingerprint(), pinned_host: a.instance.fingerprint.clone(), via: None };
    let helpers = PublicationId::new(helper_scope, "terminal");
    let request = PublishRequest { id: helpers.clone(), label: Label("echo".into()), display: String::new(), audience: None };
    let _published = client.publish(&session, request).await.expect("the helper publishes its own instance scope");
    let service = a.root.path().join("echo.sock");
    let _echo = echo(&service);
    let own_scope = Scope::instance(&a.instance.fingerprint).0;
    a.cli(&["publish", &own_scope, "terminal", "--label", "echo", "--endpoint", service.to_str().expect("path")]).await;
    let own = PublicationId::new(own_scope, "terminal");
    eventually("B binds A's own instance scope", || async { b.binding(&own).await.is_some() }).await;
    eventually("A binds its own", || async { a.binding(&own).await.is_some() }).await;
    assert!(a.binding(&helpers).await.is_none() && b.binding(&helpers).await.is_none(), "not from the instance it names");
    assert!(!binding_path(&b.runtime(), &helpers).exists());
}

// A viewer that publishes an identity itself carries it on its own copy,
// even while another instance's copy is live.
#[tokio::test]
async fn own_copy_is_chosen_first() {
    let host = Node::start("").await;
    let viewer = Node::start("").await;
    host.trust(&viewer).await;
    viewer.trust(&host).await;
    let (remote, local) = (host.root.path().join("remote.sock"), viewer.root.path().join("local.sock"));
    let (_remote, _local) = (echo(&remote), echo(&local));
    let id = PublicationId::new("vessel/5", "http");
    host.cli(&["publish", "vessel/5", "http", "--label", "http", "--endpoint", remote.to_str().expect("path")]).await;
    let path = binding_path(&viewer.runtime(), &id);
    eventually("the viewer binds the host's copy", || async { round_trip(&path, b"remote").await }).await;
    viewer.cli(&["publish", "vessel/5", "http", "--label", "http", "--endpoint", local.to_str().expect("path")]).await;
    eventually("the viewer's own copy carries it", || async { fs::read_link(&path).ok() == Some(local.clone()) }).await;
}

// A relative --endpoint is the caller's: the CLI makes it absolute, so the
// own Binding's link reaches the socket rather than dangling.
#[tokio::test]
async fn relative_endpoint_is_the_callers() {
    let node = Node::start("").await;
    let service = node.root.path().join("echo.sock");
    let _echo = echo(&service);
    let published = Command::new(env!("CARGO_BIN_EXE_tender"))
        .args(["publish", "vessel/6", "echo", "--label", "echo", "--endpoint", "echo.sock"])
        .env("TENDER_ROOT", node.root.path())
        .current_dir(node.root.path())
        .output()
        .await
        .expect("CLI");
    assert!(published.status.success(), "{}", String::from_utf8_lossy(&published.stderr));
    let path = binding_path(&node.runtime(), &PublicationId::new("vessel/6", "echo"));
    eventually("the own Binding links to the socket", || async { fs::read_link(&path).ok() == Some(service.clone()) }).await;
    assert!(round_trip(&path, b"relative").await);
}

// `tender path` warns when the computed path cannot be a Unix socket path.
#[tokio::test]
async fn path_warns_when_too_long_for_a_socket() {
    let path = |root: String| async move {
        Command::new(env!("CARGO_BIN_EXE_tender")).args(["path", "vessel/1", "x"]).env("TENDER_ROOT", root).output().await.expect("CLI")
    };
    let short = path("/r".into()).await;
    assert!(short.status.success() && short.stderr.is_empty());
    let deep = path(format!("/{}", "d".repeat(80))).await;
    assert!(deep.status.success());
    assert!(String::from_utf8_lossy(&deep.stderr).contains("longer than a Unix socket path"));
}
