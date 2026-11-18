use std::{collections::BTreeSet, time::Duration};

use tender::{
    Availability, BindingState, ByteStream, Error, Fingerprint, Grant, Label, PublicationId, PublishRequest, Route, Scope, Session, Tender,
    UnavailableReason, memory::MemoryTender,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc::UnboundedReceiver,
    time::timeout,
};

#[cfg(unix)]
#[path = "common/links.rs"]
mod links;
#[cfg(unix)]
use links::Links;

// Scenarios use only Tender and host controls. A transport adapter can run
// the same suite by providing a new rig without duplicating expectations.
trait HostControls {
    fn grant(&self, grant: Grant);
    fn allow_browse(&self, caller: Fingerprint);
    fn allow_connect(&self, caller: Fingerprint);
    fn trust_intermediary(&self, relay: Fingerprint);
    fn set_trusted_group(&self, group: BTreeSet<Fingerprint>);
    fn revoke(&self, grantee: &Fingerprint, scope: &Scope);
    fn advance_to(&self, now: u64);
    fn restart(&self);
}

impl HostControls for MemoryTender {
    fn grant(&self, grant: Grant) {
        self.grant(grant).expect("host policy");
    }
    fn allow_browse(&self, caller: Fingerprint) {
        self.allow_browse(caller).expect("host policy");
    }
    fn allow_connect(&self, caller: Fingerprint) {
        self.allow_connect(caller).expect("host policy");
    }
    fn trust_intermediary(&self, relay: Fingerprint) {
        self.trust_intermediary(relay).expect("host policy");
    }
    fn set_trusted_group(&self, group: BTreeSet<Fingerprint>) {
        self.set_trusted_group(group).expect("host policy");
    }
    fn revoke(&self, grantee: &Fingerprint, scope: &Scope) {
        self.revoke(grantee, scope).expect("host policy");
    }
    fn advance_to(&self, now: u64) {
        self.advance_to(now).expect("host policy");
    }
    fn restart(&self) {
        self.restart().expect("host policy");
    }
}

struct Rig {
    tender: Box<dyn Tender>,
    host: Box<dyn HostControls>,
    host_id: Fingerprint,
    #[cfg(unix)]
    _server: Option<(Vec<tender::ssh::Server>, tempfile::TempDir)>,
}

fn memory() -> Rig {
    let host_id = fp("host-key");
    let host = MemoryTender::new(host_id.clone());
    Rig {
        tender: Box::new(host.clone()),
        host: Box::new(host),
        host_id,
        #[cfg(unix)]
        _server: None,
    }
}

fn fp(value: &str) -> Fingerprint {
    #[cfg(unix)]
    {
        identity(value).fingerprint()
    }
    #[cfg(not(unix))]
    {
        Fingerprint(value.into())
    }
}
#[cfg(unix)]
fn identity(label: &str) -> tender::ssh::Identity {
    use sha2::{Digest, Sha256};
    tender::ssh::Identity::from_secret(Sha256::digest(label.as_bytes()).into())
}

#[cfg(unix)]
async fn local_adapter() -> Rig {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::Builder::new().permissions(std::fs::Permissions::from_mode(0o700)).tempdir().expect("private directory");
    let host_identity = identity("host-key");
    let host_id = host_identity.fingerprint();
    let host = MemoryTender::new(host_id.clone());
    let endpoint = directory.path().join("tender");
    let server = tender::ssh::Server::bind(endpoint.clone(), host_identity, host.clone()).expect("Tender listener");
    let adapter = tender::ssh::SshTender::new(endpoint, host_id.clone(), CALLERS.into_iter().map(identity).collect()).expect("adapter");
    Rig { tender: Box::new(adapter), host: Box::new(host), host_id, _server: Some((vec![server], directory)) }
}

#[cfg(unix)]
const CALLERS: [&str; 16] = [
    "host-key",
    "host-user",
    "laptop",
    "container-key",
    "parent",
    "outsider",
    "owner",
    "consumer",
    "contender",
    "first-helper",
    "second-helper",
    "kept",
    "removed",
    "roaming-key",
    "home-client",
    "relay-key",
];

// Every caller reaches the host through the same dialer: directly, or through
// a relay its session names. The host trusts `relay-key` but not `impostor`;
// both relays admit every caller and forward to the host.
#[cfg(unix)]
async fn relayed_adapter() -> Rig {
    use std::{os::unix::fs::PermissionsExt, sync::Arc};
    let directory = tempfile::Builder::new().permissions(std::fs::Permissions::from_mode(0o700)).tempdir().expect("private directory");
    let host_identity = identity("host-key");
    let host_id = host_identity.fingerprint();
    let host = MemoryTender::new(host_id.clone());
    let relays = ["relay-key", "impostor"];
    let mut paths = std::collections::BTreeMap::from([(host_id.clone(), directory.path().join("host"))]);
    for relay in relays {
        paths.insert(fp(relay), directory.path().join(relay));
    }
    let links = Arc::new(Links { paths: Arc::new(paths), next: std::collections::BTreeMap::from([(host_id.clone(), host_id.clone())]) });
    let mut servers = vec![tender::ssh::Server::bind(links.paths[&host_id].clone(), host_identity, host.clone()).expect("host listener")];
    for relay in relays {
        let policy = MemoryTender::new(fp(relay));
        for caller in CALLERS {
            policy.allow_connect(fp(caller)).expect("relay policy");
        }
        let server = tender::ssh::Server::bind(links.paths[&fp(relay)].clone(), identity(relay), policy).expect("relay listener");
        server.route_relays(links.clone());
        servers.push(server);
    }
    let adapter = tender::ssh::SshTender::with_dial(links, host_id.clone(), CALLERS.into_iter().map(identity).collect()).expect("adapter");
    Rig { tender: Box::new(adapter), host: Box::new(host), host_id, _server: Some((servers, directory)) }
}

fn id(scope: &str, name: &str) -> PublicationId {
    PublicationId::new(scope, name)
}
fn set(values: &[&str]) -> BTreeSet<Fingerprint> {
    values.iter().map(|value| fp(value)).collect()
}
fn session(caller: &str, host: &Fingerprint) -> Session {
    Session { caller: fp(caller), pinned_host: host.clone(), via: None }
}
fn request(scope: &str, name: &str, audience: &[&str]) -> PublishRequest {
    PublishRequest { id: id(scope, name), label: Label("echo".into()), display: name.into(), audience: Some(set(audience)) }
}
fn grant(rig: &Rig, grantee: &str, scope: &str, audience: &[&str], expires_at: u64) {
    rig.host.grant(Grant { grantee: fp(grantee), scope: Scope(scope.into()), audience_ceiling: set(audience), expires_at });
}
fn reader(rig: &Rig, name: &str) -> Session {
    rig.host.allow_browse(fp(name));
    rig.host.allow_connect(fp(name));
    session(name, &rig.host_id)
}
fn available(rig: &Rig, via: Option<&str>) -> BindingState {
    BindingState::Available { route: Route { instance: rig.host_id.clone(), via: via.map(fp) } }
}
fn unavailable(rig: &Rig, reason: UnavailableReason) -> BindingState {
    BindingState::Unavailable { reason, route: Some(Route { instance: rig.host_id.clone(), via: None }) }
}

async fn round_trip(rig: &Rig, client: &Session, id: &PublicationId, incoming: &mut UnboundedReceiver<ByteStream>) {
    let mut stream = rig.tender.connect(client, id).await.expect("connect");
    let mut service = incoming.recv().await.expect("service channel");
    stream.write_all(b"ordered bytes").await.expect("request write");
    stream.shutdown().await.expect("client half close");
    let mut request = Vec::new();
    service.read_to_end(&mut request).await.expect("service read");
    assert_eq!(request, b"ordered bytes");
    service.write_all(b"response").await.expect("response write");
    service.shutdown().await.expect("service half close");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("client read");
    assert_eq!(response, b"response");
}

// A Binding keeps its Local Endpoint while its publication comes and goes,
// reporting the route while available and the reason while not.
async fn existing_service_on_ssh_host(rig: Rig) {
    let publisher = session("host-user", &rig.host_id);
    let client = reader(&rig, "laptop");
    grant(&rig, "host-user", "services", &["laptop"], 100);
    let mut published = rig.tender.publish(&publisher, request("services", "cleat", &["laptop"])).await.expect("publish existing endpoint");
    let mut watch = rig.tender.watch(&client).await.expect("watch");
    assert_eq!(watch.recv().await.expect("snapshot")[0].availability, Availability::Available);
    let binding = rig.tender.bind(&client, &published.lease.id).await.expect("bind");
    assert_eq!(binding.state, available(&rig, None));
    round_trip(&rig, &client, &published.lease.id, &mut published.incoming).await;
    rig.tender.disconnect(&publisher, &published.lease).await.expect("disconnect");
    assert_eq!(watch.recv().await.expect("unavailable")[0].availability, Availability::Unavailable);
    let unavailable_binding = rig.tender.bind(&client, &published.lease.id).await.expect("rebind");
    assert_eq!(unavailable_binding.state, unavailable(&rig, UnavailableReason::PublisherUnavailable));
    assert_eq!(unavailable_binding.local_endpoint, binding.local_endpoint);
    assert!(matches!(rig.tender.open_binding(&client, &binding).await, Err(Error::Unavailable)));
    let mut republished = rig.tender.publish(&publisher, request("services", "cleat", &["laptop"])).await.expect("publish again");
    let visible = watch.recv().await.expect("new generation");
    assert_eq!(visible[0].generation, 2);
    assert_eq!(republished.lease.id, published.lease.id);
    assert_eq!(rig.tender.bind(&client, &published.lease.id).await.expect("rebind").state, available(&rig, None));
    round_trip(&rig, &client, &binding.publication, &mut republished.incoming).await;
}

async fn scoped_container_publisher(rig: Rig) {
    let helper = session("container-key", &rig.host_id);
    let parent = reader(&rig, "parent");
    let outsider = reader(&rig, "outsider");
    grant(&rig, "container-key", "container/42", &["parent"], 10);
    let mut published = rig.tender.publish(&helper, request("container/42", "api", &["parent", "outsider"])).await.expect("scoped publish");
    assert_eq!(rig.tender.browse(&parent).await.expect("browse")[0].audience, set(&["parent"]));
    assert!(rig.tender.browse(&outsider).await.expect("browse").is_empty());
    assert!(matches!(rig.tender.connect(&outsider, &published.lease.id).await, Err(Error::Denied)));
    assert!(matches!(rig.tender.bind(&outsider, &published.lease.id).await, Err(Error::Denied)));
    assert!(matches!(rig.tender.browse(&helper).await, Err(Error::Denied)));
    assert!(matches!(rig.tender.connect(&helper, &published.lease.id).await, Err(Error::Denied)));
    assert!(matches!(rig.tender.publish(&helper, request("parent", "escape", &["parent"])).await, Err(Error::Denied)));
    round_trip(&rig, &parent, &published.lease.id, &mut published.incoming).await;
}

async fn roaming_via_pinned_intermediary(rig: Rig) {
    rig.host.trust_intermediary(fp("relay-key"));
    let mut publisher = session("roaming-key", &rig.host_id);
    publisher.via = Some(fp("relay-key"));
    let mut client = reader(&rig, "home-client");
    client.via = Some(fp("relay-key"));
    grant(&rig, "roaming-key", "mobile", &["home-client"], 100);
    let mut published = rig.tender.publish(&publisher, request("mobile", "notes", &["home-client"])).await.expect("publish via relay");
    round_trip(&rig, &client, &published.lease.id, &mut published.incoming).await;
    assert_eq!(rig.tender.bind(&client, &published.lease.id).await.expect("bind via relay").state, available(&rig, Some("relay-key")));
    let relay = session("relay-key", &rig.host_id);
    assert!(matches!(rig.tender.browse(&relay).await, Err(Error::Denied)));
    assert!(matches!(rig.tender.connect(&relay, &published.lease.id).await, Err(Error::Denied)));
    let mut wrong_pin = client.clone();
    wrong_pin.pinned_host = fp("other-host");
    assert!(matches!(rig.tender.connect(&wrong_pin, &published.lease.id).await, Err(Error::IdentityMismatch)));
    let mut wrong_relay = client;
    wrong_relay.via = Some(fp("impostor"));
    assert!(matches!(rig.tender.connect(&wrong_relay, &published.lease.id).await, Err(Error::UntrustedIntermediary)));
}

// Identity is scope + name. Another publisher granted the scope takes over an
// identity whose publisher is unavailable or withdrawn; a live incumbent wins,
// and nobody without a grant for the scope can publish it.
async fn identity_is_scope_and_name(rig: Rig) {
    let owner = session("owner", &rig.host_id);
    let contender = session("contender", &rig.host_id);
    let outsider = session("outsider", &rig.host_id);
    let client = reader(&rig, "consumer");
    grant(&rig, "owner", "n", &["consumer"], 100);
    grant(&rig, "contender", "n", &["consumer"], 100);
    grant(&rig, "outsider", "elsewhere", &["consumer"], 100);
    let first = rig.tender.publish(&owner, request("n", "service", &["consumer"])).await.expect("first");
    assert_eq!(first.lease.id, id("n", "service"));
    let forged = tender::Lease { id: first.lease.id.clone(), generation: 1, publisher: fp("contender") };
    assert!(matches!(rig.tender.withdraw(&contender, &forged).await, Err(Error::Denied)));
    let missing = tender::Lease { id: id("n", "missing"), generation: 1, publisher: fp("contender") };
    assert!(matches!(rig.tender.withdraw(&contender, &missing).await, Err(Error::Denied)));
    assert!(matches!(rig.tender.publish(&owner, request("n", "service", &["consumer"])).await, Err(Error::LivePublisher)));
    assert!(matches!(rig.tender.publish(&contender, request("n", "service", &["consumer"])).await, Err(Error::LivePublisher)));
    rig.tender.disconnect(&owner, &first.lease).await.expect("owner goes away");
    assert!(matches!(rig.tender.publish(&outsider, request("n", "service", &["consumer"])).await, Err(Error::Denied)));
    let taken = rig.tender.publish(&contender, request("n", "service", &["consumer"])).await.expect("takeover");
    assert_eq!((taken.lease.id.clone(), taken.lease.generation), (first.lease.id.clone(), 2));
    let visible = rig.tender.browse(&client).await.expect("browse");
    assert_eq!((visible.len(), &visible[0].publisher, visible[0].availability), (1, &fp("contender"), Availability::Available));
    assert!(matches!(rig.tender.withdraw(&owner, &first.lease).await, Err(Error::Denied)));
    assert!(matches!(rig.tender.disconnect(&contender, &first.lease).await, Err(Error::Denied)));
    rig.tender.withdraw(&contender, &taken.lease).await.expect("withdraw");
    assert_eq!(rig.tender.browse(&client).await.expect("browse")[0].availability, Availability::Withdrawn);
    assert!(matches!(rig.tender.withdraw(&contender, &taken.lease).await, Err(Error::Withdrawn)));
    let retaken = rig.tender.publish(&owner, request("n", "service", &["consumer"])).await.expect("withdrawn identity is taken back");
    assert_eq!(retaken.lease.generation, 3);
    assert!(matches!(rig.tender.withdraw(&contender, &taken.lease).await, Err(Error::Denied)));
}

// Refusing a publisher without a grant reveals nothing about whether the
// identity exists, is live or was withdrawn.
async fn ungranted_scope_reveals_nothing(rig: Rig) {
    let owner = session("owner", &rig.host_id);
    let outsider = session("outsider", &rig.host_id);
    grant(&rig, "owner", "private", &["alice"], 100);
    grant(&rig, "outsider", "scratch", &["outsider"], 100);
    let probe = |name| request("private", name, &["outsider"]);
    assert!(matches!(rig.tender.publish(&outsider, probe("service")).await, Err(Error::Denied)));
    let published = rig.tender.publish(&owner, request("private", "service", &["alice"])).await.expect("publish");
    assert!(matches!(rig.tender.publish(&outsider, probe("service")).await, Err(Error::Denied)));
    rig.tender.withdraw(&owner, &published.lease).await.expect("withdraw");
    assert!(matches!(rig.tender.publish(&outsider, probe("service")).await, Err(Error::Denied)));
}

async fn grant_loss_and_expiry(rig: Rig) {
    let publisher = session("owner", &rig.host_id);
    let client = reader(&rig, "consumer");
    grant(&rig, "owner", "n", &["consumer"], 10);
    let mut first = rig.tender.publish(&publisher, request("n", "service", &["consumer"])).await.expect("publish");
    let mut connection = rig.tender.connect(&client, &first.lease.id).await.expect("open");
    let mut service = first.incoming.recv().await.expect("incoming");
    rig.host.advance_to(10);
    assert!(matches!(rig.tender.connect(&client, &first.lease.id).await, Err(Error::Withdrawn)));
    assert!(matches!(rig.tender.publish(&publisher, request("n", "new", &["consumer"])).await, Err(Error::GrantExpired)));
    assert!(matches!(rig.tender.publish(&publisher, request("n", "service", &["consumer"])).await, Err(Error::GrantExpired)));
    connection.write_all(b"grandfathered").await.expect("existing stream survives expiry");
    let mut bytes = [0; 13];
    service.read_exact(&mut bytes).await.expect("service sees bytes");
    assert_eq!(&bytes, b"grandfathered");

    grant(&rig, "owner", "n", &["consumer"], 20);
    let mut second = rig.tender.publish(&publisher, request("n", "service", &["consumer"])).await.expect("republish under a new grant");
    assert_eq!(second.lease.generation, 2);
    let mut connection = rig.tender.connect(&client, &second.lease.id).await.expect("open");
    let _service = second.incoming.recv().await.expect("incoming");
    rig.host.revoke(&fp("owner"), &Scope("n".into()));
    assert!(matches!(rig.tender.connect(&client, &second.lease.id).await, Err(Error::Withdrawn)));
    assert!(matches!(rig.tender.publish(&publisher, request("n", "newer", &["consumer"])).await, Err(Error::Denied)));
    let mut byte = [0];
    assert_eq!(timeout(Duration::from_secs(1), connection.read(&mut byte)).await.expect("revocation closes promptly").expect("read"), 0);
}

// A takeover keeps the Binding: streams open on the old route break with it,
// nothing is replayed, and the same Local Endpoint reaches the new publisher.
async fn takeover_keeps_binding_without_replay(rig: Rig) {
    let first_helper = session("first-helper", &rig.host_id);
    let second_helper = session("second-helper", &rig.host_id);
    let client = reader(&rig, "consumer");
    grant(&rig, "first-helper", "n", &["consumer"], 100);
    grant(&rig, "second-helper", "n", &["consumer"], 100);
    let mut first = rig.tender.publish(&first_helper, request("n", "same-name", &["consumer"])).await.expect("publish");
    let binding = rig.tender.bind(&client, &first.lease.id).await.expect("bind");
    let mut old_stream = rig.tender.open_binding(&client, &binding).await.expect("open");
    let mut old_service = first.incoming.recv().await.expect("incoming");
    old_stream.write_all(b"before").await.expect("write");
    let mut bytes = [0; 6];
    old_service.read_exact(&mut bytes).await.expect("read");
    rig.tender.disconnect(&first_helper, &first.lease).await.expect("disconnect");
    let mut byte = [0];
    assert_eq!(timeout(Duration::from_secs(1), old_stream.read(&mut byte)).await.expect("close").expect("read"), 0);
    let mut second = rig.tender.publish(&second_helper, request("n", "same-name", &["consumer"])).await.expect("takeover");
    let rebound = rig.tender.bind(&client, &first.lease.id).await.expect("rebind");
    assert_eq!((rebound.local_endpoint.as_str(), &rebound.state), (binding.local_endpoint.as_str(), &available(&rig, None)));
    let mut new_stream = rig.tender.open_binding(&client, &binding).await.expect("reopen");
    let mut new_service = second.incoming.recv().await.expect("new channel");
    assert!(timeout(Duration::from_millis(30), new_service.read(&mut byte)).await.is_err(), "no bytes replayed");
    new_stream.write_all(b"fresh").await.expect("new write");
    let mut fresh = [0; 5];
    new_service.read_exact(&mut fresh).await.expect("new read");
    assert_eq!(&fresh, b"fresh");
}

async fn restart_and_replacement(rig: Rig) {
    let original = session("first-helper", &rig.host_id);
    let replacement = session("second-helper", &rig.host_id);
    let client = reader(&rig, "consumer");
    grant(&rig, "first-helper", "n", &["consumer"], 100);
    let first = rig.tender.publish(&original, request("n", "service", &["consumer"])).await.expect("publish");
    rig.host.restart();
    assert_eq!(rig.tender.browse(&client).await.expect("browse")[0].availability, Availability::Unavailable);
    assert!(matches!(rig.tender.publish(&replacement, request("n", "service", &["consumer"])).await, Err(Error::Denied)));
    grant(&rig, "second-helper", "n", &["consumer"], 100);
    let second = rig.tender.publish(&replacement, request("n", "service", &["consumer"])).await.expect("granted replacement");
    assert_eq!(second.lease.generation, 2);
    assert!(matches!(rig.tender.disconnect(&original, &first.lease).await, Err(Error::Denied)));
}

// Each publication carries a protocol label and display text, which Tender
// never interprets; whoever publishes the identity next sets them anew.
async fn labels_and_display_are_carried(rig: Rig) {
    let first_helper = session("first-helper", &rig.host_id);
    let second_helper = session("second-helper", &rig.host_id);
    let client = reader(&rig, "consumer");
    grant(&rig, "first-helper", "vessel/7", &["consumer"], 100);
    grant(&rig, "second-helper", "vessel/7", &["consumer"], 100);
    let labelled = |label: &str, display: &str| PublishRequest {
        id: id("vessel/7", "cleat/default"),
        label: Label(label.into()),
        display: display.into(),
        audience: Some(set(&["consumer"])),
    };
    let first = rig.tender.publish(&first_helper, labelled("cleat", "Crew terminal")).await.expect("publish");
    let visible = rig.tender.browse(&client).await.expect("browse");
    assert_eq!((&visible[0].label, visible[0].display.as_str()), (&Label("cleat".into()), "Crew terminal"));
    rig.tender.withdraw(&first_helper, &first.lease).await.expect("withdraw");
    rig.tender.publish(&second_helper, labelled("agent-view", "Moved crew")).await.expect("takeover");
    let visible = rig.tender.browse(&client).await.expect("browse");
    assert_eq!((&visible[0].label, visible[0].display.as_str()), (&Label("agent-view".into()), "Moved crew"));
}

// A request naming no audience gets the host's Trusted Group, within the
// grant's ceiling, and follows the group as it changes. The host publishes
// under any scope without a grant, but never beyond its group.
async fn default_audience_is_trusted_group(rig: Rig) {
    let helper = session("owner", &rig.host_id);
    let host = session("host-key", &rig.host_id);
    let laptop = reader(&rig, "laptop");
    let outsider = reader(&rig, "outsider");
    rig.host.set_trusted_group(set(&["laptop"]));
    grant(&rig, "owner", "n", &["laptop", "outsider"], 100);
    let defaulted = PublishRequest { audience: None, ..request("n", "defaulted", &[]) };
    let mut published = rig.tender.publish(&helper, defaulted).await.expect("default audience");
    assert_eq!(rig.tender.browse(&laptop).await.expect("browse")[0].audience, set(&["laptop"]));
    assert!(rig.tender.browse(&outsider).await.expect("browse").is_empty());
    round_trip(&rig, &laptop, &published.lease.id, &mut published.incoming).await;
    rig.host.set_trusted_group(set(&["laptop", "outsider"]));
    assert_eq!(rig.tender.browse(&outsider).await.expect("browse")[0].audience, set(&["laptop", "outsider"]));
    rig.host.set_trusted_group(set(&["laptop"]));
    let own = rig.tender.publish(&host, request("tender/host", "terminal", &["laptop", "outsider"])).await.expect("host publishes");
    let visible = rig.tender.browse(&laptop).await.expect("browse");
    assert_eq!(visible.iter().find(|publication| publication.id == own.lease.id).expect("own publication").audience, set(&["laptop"]));
    assert!(rig.tender.browse(&outsider).await.expect("browse").is_empty());
}

async fn publisher_receiver_closure(rig: Rig) {
    let publisher = session("owner", &rig.host_id);
    let client = reader(&rig, "consumer");
    grant(&rig, "owner", "n", &["consumer"], 100);
    let mut watch = rig.tender.watch(&client).await.expect("watch");
    assert!(watch.recv().await.expect("initial").is_empty());
    let published = rig.tender.publish(&publisher, request("n", "service", &["consumer"])).await.expect("publish");
    assert_eq!(watch.recv().await.expect("available")[0].availability, Availability::Available);
    let id = published.lease.id.clone();
    drop(published);
    let snapshot = timeout(Duration::from_secs(1), watch.recv()).await.expect("closure update").expect("watch open");
    assert_eq!(snapshot[0].availability, Availability::Unavailable);
    assert!(matches!(rig.tender.connect(&client, &id).await, Err(Error::Unavailable)));
}

// Narrowing a grant closes removed callers' streams and reports their
// Binding as revoked; widening it again restores the same Local Endpoint.
async fn narrowed_grant_revokes_binding(rig: Rig) {
    let publisher = session("owner", &rig.host_id);
    let kept = reader(&rig, "kept");
    let removed = reader(&rig, "removed");
    grant(&rig, "owner", "n", &["kept", "removed"], 100);
    let mut published = rig.tender.publish(&publisher, request("n", "service", &["kept", "removed"])).await.expect("publish");
    let id = published.lease.id.clone();
    let mut watch = rig.tender.watch(&removed).await.expect("watch");
    assert_eq!(watch.recv().await.expect("initial").len(), 1);
    let binding = rig.tender.bind(&removed, &id).await.expect("bind");
    assert_eq!(rig.tender.bind(&kept, &id).await.expect("shared binding").local_endpoint, binding.local_endpoint);
    let mut old_stream = rig.tender.connect(&removed, &id).await.expect("old access");
    let _service = published.incoming.recv().await.expect("incoming");
    grant(&rig, "owner", "n", &["kept"], 100);
    assert!(watch.recv().await.expect("narrowed").is_empty());
    assert!(matches!(rig.tender.connect(&removed, &id).await, Err(Error::Denied)));
    assert!(matches!(rig.tender.connect(&removed, &tender::PublicationId::new("n", "missing")).await, Err(Error::Denied)));
    let revoked = rig.tender.bind(&removed, &id).await.expect("revoked binding");
    assert_eq!((revoked.local_endpoint.as_str(), &revoked.state), (binding.local_endpoint.as_str(), &BindingState::Revoked));
    assert!(matches!(rig.tender.open_binding(&removed, &binding).await, Err(Error::Denied)));
    let mut byte = [0];
    assert_eq!(timeout(Duration::from_secs(1), old_stream.read(&mut byte)).await.expect("removed stream closes").expect("read"), 0);
    round_trip(&rig, &kept, &id, &mut published.incoming).await;
    grant(&rig, "owner", "n", &["kept", "removed"], 100);
    assert_eq!(watch.recv().await.expect("widened")[0].audience, set(&["kept", "removed"]));
    assert_eq!(rig.tender.bind(&removed, &id).await.expect("restored").state, available(&rig, None));
    round_trip(&rig, &removed, &id, &mut published.incoming).await;
}

async fn backpressure_and_cancel(rig: Rig) {
    let publisher = session("owner", &rig.host_id);
    let client = reader(&rig, "consumer");
    grant(&rig, "owner", "n", &["consumer"], 100);
    let mut published = rig.tender.publish(&publisher, request("n", "service", &["consumer"])).await.expect("publish");
    let mut connection =
        rig.tender.connect_with_deadline(&client, &published.lease.id, Duration::from_secs(1)).await.expect("bounded open");
    let mut service = published.incoming.recv().await.expect("incoming");
    // Exceeds SSH channel windows and OS socket buffers as well as the
    // in-memory pipe, without assuming an adapter-specific capacity.
    assert!(
        timeout(Duration::from_millis(30), connection.write_all(&vec![7; 16_000_000])).await.is_err(),
        "bounded stream must apply backpressure"
    );
    drop(connection); // Cooperative cancellation closes this one raw channel.
    let mut buf = [0; 256];
    let mut total = 0;
    loop {
        let n = timeout(Duration::from_secs(1), service.read(&mut buf)).await.expect("cancel closes").expect("read");
        if n == 0 {
            break;
        }
        total += n;
    }
    assert!(total < 16_000_000);
}

macro_rules! contract {
    ($name:ident) => {
        mod $name {
            #[tokio::test]
            async fn run() {
                super::$name(super::memory()).await;
            }
            #[cfg(unix)]
            #[tokio::test]
            async fn local_socket() {
                super::$name(super::local_adapter().await).await;
            }
        }
    };
}

contract!(existing_service_on_ssh_host);
contract!(scoped_container_publisher);
// The direct socket rig has no relay to name, so it runs only where one exists.
mod roaming_via_pinned_intermediary {
    #[tokio::test]
    async fn run() {
        super::roaming_via_pinned_intermediary(super::memory()).await;
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn relayed() {
        super::roaming_via_pinned_intermediary(super::relayed_adapter().await).await;
    }
}
contract!(identity_is_scope_and_name);
contract!(ungranted_scope_reveals_nothing);
contract!(grant_loss_and_expiry);
contract!(takeover_keeps_binding_without_replay);
contract!(restart_and_replacement);
contract!(labels_and_display_are_carried);
contract!(default_audience_is_trusted_group);
contract!(publisher_receiver_closure);
contract!(narrowed_grant_revokes_binding);
contract!(backpressure_and_cancel);
