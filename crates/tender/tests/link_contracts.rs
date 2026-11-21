#![cfg(unix)]

//! Links and the routes learned over them. Each rule runs over the in-memory
//! byte transport and over Unix sockets, on paused Tokio time with no sleeps:
//! every wait is for an event, and the paused clock only moves when nothing is
//! left to wake, which fails the scenario instead of hanging it.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::Permissions,
    os::unix::fs::PermissionsExt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use hegel::{TestCase, generators as gs};
use sha2::{Digest, Sha256};
use tempfile::{Builder, TempDir};
use tender::{
    Availability, ByteStream, Dial, Error, Fingerprint, PublicationId, PublishRequest, Published, Route, Scope, Session, Tender, Watch,
    api::RouteStatus,
    links::{Link, Links},
    memory::MemoryTender,
    ssh::{Identity, Server, SshTender, UnixDial},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    runtime,
    sync::mpsc::UnboundedReceiver,
    time::timeout,
};

#[derive(Clone, Copy, Debug)]
enum Transport {
    Memory,
    Socket,
}

struct Instance {
    identity: Identity,
    server: Server,
    /// How another instance dials this one: the only way in, apart from links.
    dial: Arc<dyn Dial>,
}

impl Instance {
    fn fp(&self) -> Fingerprint {
        self.identity.fingerprint()
    }

    fn links(&self) -> &Links {
        self.server.links()
    }

    /// Dial `other` and hold a link to it.
    async fn link(&self, other: &Instance) -> Link {
        self.links().connect(other.dial.clone(), &other.fp()).await.expect("link")
    }

    /// The instance's own publication under its instance scope, for its
    /// Trusted Group.
    async fn publish(&self, name: &str) -> Published {
        let session = Session { caller: self.fp(), pinned_host: self.fp(), via: None };
        let request = PublishRequest { id: own_id(self, name), label: tender::Label("echo".into()), display: name.into(), audience: None };
        self.server.policy.publish(&session, request).await.expect("publish")
    }

    /// A client of `host` as this instance, over this instance's links, and
    /// its session along the learned route.
    fn client(&self, host: &Instance) -> (SshTender, Session) {
        let route = self.links().route(&host.fp()).expect("a learned route");
        let client = SshTender::with_dial(Arc::new(self.links().clone()), host.fp(), vec![self.identity.clone()]).expect("client");
        (client, Session { caller: self.fp(), pinned_host: host.fp(), via: route.via })
    }

    /// Follow `host`'s publications and connect to one: the stream reaches
    /// the publisher and carries bytes both ways. The subscription is returned
    /// open.
    async fn follow_and_connect(&self, host: &Instance, published: &mut Published) -> Watch {
        let (client, session) = self.client(host);
        let mut watch = client.subscribe(&session).await.expect("subscribe");
        let snapshot = watch.recv().await.expect("first snapshot");
        assert!(
            snapshot.iter().any(|publication| publication.id == published.lease.id && publication.availability == Availability::Available),
            "follows the publication"
        );
        let stream = client.connect(&session, &published.lease.id).await.expect("connect");
        round_trip(stream, &mut published.incoming).await;
        watch
    }
}

fn own_id(instance: &Instance, name: &str) -> PublicationId {
    PublicationId { scope: Scope::instance(&instance.fp()), name: name.into() }
}

async fn round_trip(mut stream: ByteStream, incoming: &mut UnboundedReceiver<ByteStream>) {
    let mut service = incoming.recv().await.expect("service channel");
    stream.write_all(b"ping").await.expect("caller write");
    let mut ping = [0; 4];
    service.read_exact(&mut ping).await.expect("service read");
    assert_eq!(&ping, b"ping");
    service.write_all(b"pong").await.expect("service write");
    let mut pong = [0; 4];
    stream.read_exact(&mut pong).await.expect("caller read");
    assert_eq!(&pong, b"pong");
}

struct Net {
    transport: Transport,
    directory: TempDir,
}

impl Net {
    fn new(transport: Transport) -> Self {
        Self { transport, directory: Builder::new().permissions(Permissions::from_mode(0o700)).tempdir().expect("private directory") }
    }

    fn instance(&self, name: &str) -> Instance {
        let identity = Identity::from_secret(Sha256::digest(name.as_bytes()).into());
        let policy = MemoryTender::new(identity.fingerprint());
        match self.transport {
            Transport::Memory => {
                let server = Server::in_process(identity.clone(), policy).expect("in-process server");
                let dial = server.dialer();
                Instance { identity, server, dial }
            }
            Transport::Socket => {
                let path = self.directory.path().join(name);
                let server = Server::bind(path.clone(), identity.clone(), policy).expect("listener");
                Instance { identity, server, dial: Arc::new(UnixDial(path)) }
            }
        }
    }
}

/// Each instance trusts the others as its Trusted Group, as the daemon does:
/// they browse, connect, hold links and relay to it.
fn befriend(instances: &[&Instance]) {
    for host in instances {
        let others: BTreeSet<_> = instances.iter().map(|other| other.fp()).filter(|other| other != &host.fp()).collect();
        let mut group = others.clone();
        group.insert(host.fp());
        host.server.policy.set_access(group.clone()).expect("host policy");
        host.server.policy.set_trusted_group(group).expect("host policy");
        host.server.policy.set_intermediaries(others).expect("host policy");
    }
}

/// Waits, on route change events alone, until `check` holds of `links`.
async fn settle(links: &Links, what: &str, check: impl Fn(&Links) -> bool) {
    let mut changes = links.changes();
    while !check(links) {
        changes.changed().await.unwrap_or_else(|_| panic!("{what}: the links went away"));
    }
}

async fn route_is(links: &Links, host: &Instance, expected: Option<Route>) {
    settle(links, "route", |links| links.route(&host.fp()) == expected).await;
}

fn direct(host: &Instance) -> Option<Route> {
    Some(Route { instance: host.fp(), via: None })
}

fn through(host: &Instance, relay: &Instance) -> Option<Route> {
    Some(Route { instance: host.fp(), via: Some(relay.fp()) })
}

/// Runs a scenario on paused time. Should nothing be left to wake it, the
/// paused clock jumps and the scenario fails rather than hanging.
fn run<F: Future<Output = ()>>(scenario: F) {
    runtime::Builder::new_current_thread().enable_all().start_paused(true).build().expect("runtime").block_on(async {
        timeout(Duration::from_secs(24 * 3600), scenario).await.expect("the scenario stalled: nothing was left to wake it");
    });
}

// Once a link is up, either end follows the other's publications and opens
// streams over it, whoever dialed: B never dials A. When the link closes, the
// route goes at both ends, so do subscriptions over it, and a stream to an
// instance no route reaches is unavailable.
async fn a_link_is_symmetric(transport: Transport) {
    let net = Net::new(transport);
    let (a, b) = (net.instance("a"), net.instance("b"));
    befriend(&[&a, &b]);
    let link = a.link(&b).await;
    route_is(a.links(), &b, direct(&b)).await;
    route_is(b.links(), &a, direct(&a)).await;
    let (mut from_a, mut from_b) = (a.publish("terminal").await, b.publish("terminal").await);
    let mut a_follows_b = a.follow_and_connect(&b, &mut from_b).await;
    let mut b_follows_a = b.follow_and_connect(&a, &mut from_a).await;
    assert_eq!(b.links().routes(), vec![RouteStatus { instance: a.fp(), next_hop: a.fp(), hops: 1, fallbacks: Vec::new() }]);

    let (b_client, b_session) = b.client(&a);
    drop(link);
    route_is(a.links(), &b, None).await;
    route_is(b.links(), &a, None).await;
    while a_follows_b.recv().await.is_some() {}
    while b_follows_a.recv().await.is_some() {}
    assert_eq!(b_client.connect(&b_session, &from_a.lease.id).await.err(), Some(Error::Unavailable));
}

// A has only an outbound link to B, and C only an outbound link to B: B is
// the hub, though nothing configures it as one. A and C learn routes to each
// other through B from the live links, then follow and connect to each other
// through it, each relayed stream authenticated end to end. When C's link
// closes, A's route to C is withdrawn rather than guessed, and C is unavailable.
async fn routes_reach_through_a_hub(transport: Transport) {
    let net = Net::new(transport);
    let (a, b, c) = (net.instance("a"), net.instance("b"), net.instance("c"));
    befriend(&[&a, &b, &c]);
    let _a_to_b = a.link(&b).await;
    let c_to_b = c.link(&b).await;
    route_is(a.links(), &c, through(&c, &b)).await;
    route_is(c.links(), &a, through(&a, &b)).await;
    let mut expected = vec![
        RouteStatus { instance: b.fp(), next_hop: b.fp(), hops: 1, fallbacks: Vec::new() },
        RouteStatus { instance: c.fp(), next_hop: b.fp(), hops: 2, fallbacks: Vec::new() },
    ];
    expected.sort_by(|left, right| left.instance.cmp(&right.instance));
    assert_eq!(a.links().routes(), expected);
    let (mut from_a, mut from_c) = (a.publish("terminal").await, c.publish("terminal").await);
    let mut a_follows_c = a.follow_and_connect(&c, &mut from_c).await;
    let _c_follows_a = c.follow_and_connect(&a, &mut from_a).await;

    let (a_client, a_session) = a.client(&c);
    drop(c_to_b);
    route_is(a.links(), &c, None).await;
    while a_follows_c.recv().await.is_some() {}
    assert_eq!(a_client.connect(&a_session, &from_c.lease.id).await.err(), Some(Error::Unavailable));
}

// A route keeps a fallback through every other next hop. A reaches C through
// B and through D; when the primary's link to C closes, the fallback takes
// over and A still connects to C.
async fn fallbacks_take_over(transport: Transport) {
    let net = Net::new(transport);
    let (a, b, c, d) = (net.instance("a"), net.instance("b"), net.instance("c"), net.instance("d"));
    befriend(&[&a, &b, &c, &d]);
    let _a_to_b = a.link(&b).await;
    let _a_to_d = a.link(&d).await;
    let mut b_to_c = Some(b.link(&c).await);
    let mut d_to_c = Some(d.link(&c).await);
    settle(a.links(), "both next hops", |links| {
        links.routes().iter().any(|route| route.instance == c.fp() && route.hops == 2 && route.fallbacks.len() == 1)
    })
    .await;
    let primary = a.links().routes().into_iter().find(|route| route.instance == c.fp()).expect("route to C");
    let (lost, kept) = if primary.next_hop == b.fp() { (&mut b_to_c, &d) } else { (&mut d_to_c, &b) };
    assert_eq!(primary.fallbacks, vec![kept.fp()]);
    lost.take();
    route_is(a.links(), &c, through(&c, kept)).await;
    let mut from_c = c.publish("terminal").await;
    a.follow_and_connect(&c, &mut from_c).await;
}

// Relay rules hold on learned routes as they do on supplied ones: the host
// accepts a relayed caller only from a relay it trusts, and an instance that
// may not connect cannot hold a link, so it neither learns nor offers routes.
async fn relay_rules_hold(transport: Transport) {
    let net = Net::new(transport);
    let (a, b, c) = (net.instance("a"), net.instance("b"), net.instance("c"));
    befriend(&[&a, &b, &c]);
    let _a_to_b = a.link(&b).await;
    let _c_to_b = c.link(&b).await;
    route_is(a.links(), &c, through(&c, &b)).await;
    let published = c.publish("terminal").await;
    c.server.policy.set_intermediaries(BTreeSet::new()).expect("host policy");
    let (client, session) = a.client(&c);
    assert_eq!(client.connect(&session, &published.lease.id).await.err(), Some(Error::UntrustedIntermediary));

    let outsider = net.instance("outsider");
    befriend(&[&outsider]);
    assert_eq!(outsider.links().connect(b.dial.clone(), &b.fp()).await.err(), Some(Error::Denied));
    assert!(outsider.links().routes().is_empty() && b.links().route(&outsider.fp()).is_none());
}

/// Dials through `inner` once, for the link, and refuses every later dial,
/// as a forward does once its far socket has gone.
struct Once {
    inner: Arc<dyn Dial>,
    used: AtomicBool,
}

#[async_trait::async_trait]
impl Dial for Once {
    async fn dial(&self, instance: &Fingerprint) -> std::io::Result<ByteStream> {
        if self.used.swap(true, Ordering::SeqCst) {
            return Err(std::io::ErrorKind::ConnectionRefused.into());
        }
        self.inner.dial(instance).await
    }
}

// The end that accepted a link learns at once when the dialer cannot open
// the stream it asked for: the open fails as Unavailable, not at its deadline.
async fn a_failed_reverse_open_is_refused(transport: Transport) {
    let net = Net::new(transport);
    let (a, b) = (net.instance("a"), net.instance("b"));
    befriend(&[&a, &b]);
    let dial: Arc<dyn Dial> = Arc::new(Once { inner: b.dial.clone(), used: AtomicBool::new(false) });
    let _link = a.links().connect(dial, &b.fp()).await.expect("link");
    route_is(b.links(), &a, direct(&a)).await;
    let (client, session) = b.client(&a);
    assert_eq!(client.browse(&session).await.err(), Some(Error::Unavailable));
}

macro_rules! contract {
    ($name:ident) => {
        mod $name {
            #[test]
            fn memory() {
                super::run(super::$name(super::Transport::Memory));
            }
            #[test]
            fn socket() {
                super::run(super::$name(super::Transport::Socket));
            }
        }
    };
}

contract!(a_link_is_symmetric);
contract!(routes_reach_through_a_hub);
contract!(fallbacks_take_over);
contract!(relay_rules_hold);
contract!(a_failed_reverse_open_is_refused);

/// Hops from `from` to every instance it reaches over `edges`.
fn distances(count: usize, edges: &BTreeSet<(usize, usize)>, from: usize) -> BTreeMap<usize, usize> {
    let mut found = BTreeMap::from([(from, 0)]);
    let mut queue = VecDeque::from([from]);
    while let Some(next) = queue.pop_front() {
        for other in 0..count {
            let linked = edges.contains(&(next, other)) || edges.contains(&(other, next));
            if linked && !found.contains_key(&other) {
                found.insert(other, found[&next] + 1);
                queue.push_back(other);
            }
        }
    }
    found
}

/// Every instance's routes are shortest paths over `edges`: exactly the
/// instances it reaches, each through a neighbour one hop nearer.
fn shortest(instances: &[Instance], edges: &BTreeSet<(usize, usize)>, index: usize) -> bool {
    let fingerprints: Vec<_> = instances.iter().map(Instance::fp).collect();
    let near = distances(instances.len(), edges, index);
    let routes = instances[index].links().routes();
    let reached: BTreeSet<_> = routes.iter().map(|route| route.instance.clone()).collect();
    let expected: BTreeSet<_> = near.keys().filter(|&&other| other != index).map(|&other| fingerprints[other].clone()).collect();
    reached == expected
        && routes.iter().all(|route| {
            let target = fingerprints.iter().position(|fp| fp == &route.instance).expect("a known instance");
            let hop = fingerprints.iter().position(|fp| fp == &route.next_hop).expect("a known next hop");
            let towards = distances(instances.len(), edges, hop);
            route.hops == near[&target] && near.get(&hop) == Some(&1) && towards.get(&target) == Some(&(near[&target] - 1))
        })
}

/// Waits until every instance's routes are shortest paths at once.
async fn converge(instances: &[Instance], edges: &BTreeSet<(usize, usize)>) {
    loop {
        let mut settled = true;
        for index in 0..instances.len() {
            if !shortest(instances, edges, index) {
                settled = false;
                settle(instances[index].links(), "shortest routes", |_| shortest(instances, edges, index)).await;
            }
        }
        if settled {
            return;
        }
    }
}

// Over any graph of up to five instances, with each link dialed from either
// end, every instance learns a shortest route to each instance its links
// reach and to no other; when any of the links are cut, the routes follow.
#[hegel::test]
fn routes_converge_on_shortest_paths(tc: TestCase) {
    let count = tc.draw(gs::integers::<usize>().min_value(2).max_value(5));
    let transport = if tc.draw(gs::booleans()) { Transport::Socket } else { Transport::Memory };
    let mut edges = BTreeSet::new();
    for first in 0..count {
        for second in first + 1..count {
            if tc.draw(gs::booleans()) {
                edges.insert(if tc.draw(gs::booleans()) { (first, second) } else { (second, first) });
            }
        }
    }
    let cut: BTreeSet<_> = edges.iter().filter(|_| tc.draw(gs::booleans())).copied().collect();
    run(async {
        let net = Net::new(transport);
        let instances: Vec<_> = (0..count).map(|index| net.instance(&format!("instance-{index}"))).collect();
        befriend(&instances.iter().collect::<Vec<_>>());
        let mut links = BTreeMap::new();
        for &(dialer, far) in &edges {
            links.insert((dialer, far), instances[dialer].link(&instances[far]).await);
        }
        converge(&instances, &edges).await;
        for edge in &cut {
            links.remove(edge);
        }
        converge(&instances, &edges.difference(&cut).copied().collect()).await;
    });
}
