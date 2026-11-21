//! Eager Bindings: this instance follows the publication lists of its Trusted
//! Group and keeps a Binding, at the identity's fixed path, for every
//! publication that admits it, its own included. Each member with a
//! configured route is dialed and its link held; every member is followed
//! over whatever route the links have learned to it.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, Permissions},
    io,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process,
    sync::{Arc, Mutex},
    time::Duration,
};

use rigging_ssh::Target as SshTarget;
use tokio::{
    io::copy_bidirectional,
    net::UnixListener,
    select, spawn,
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    task::JoinHandle,
    time::{Instant, sleep},
};

use crate::{
    Availability, BindingState, Dial, Fingerprint, Publication, PublicationId, Route, Session, Tender, UnavailableReason, Watch,
    api::{BindingEntry, PeerRoute, PeerState, PeerStatus, TrustedInstance},
    links::Links,
    memory::MemoryTender,
    paths,
    ssh::{Forward, Identity, SshTender, UnixDial},
    until,
};

/// How long a Binding outlives the last copy of its publication by default.
pub(super) const BINDING_GRACE: Duration = Duration::from_secs(60);
const RETRY_FIRST: Duration = Duration::from_millis(100);
const RETRY_LONGEST: Duration = Duration::from_secs(8);
const ROUTE_SETTLED: Duration = Duration::from_secs(10);

pub(super) enum Event {
    Local(Vec<Publication>),
    Trust(Vec<TrustedInstance>),
    Peer(Fingerprint, PeerUpdate),
    /// An own endpoint was recorded after its publication was announced.
    Endpoints,
}

pub(super) enum PeerUpdate {
    /// No live link leads to the member.
    NoRoute,
    Connecting,
    Connected(SshTender, Route),
    Snapshot(Vec<Publication>),
    Lost(String),
    /// How the link this instance dials to the member stands.
    Link(LinkState),
}

#[derive(Clone)]
pub(super) enum LinkState {
    Dialing,
    Up,
    Failed(String),
}

#[derive(Default)]
pub(super) struct View {
    pub bindings: Vec<BindingEntry>,
    pub peers: Vec<PeerStatus>,
}

/// The daemon's handle on its Bindings. Dropping it stops following; the
/// Local Endpoints go as the aborted tasks unwind, which a process exit may
/// cut short, so `start` clears any a previous run left.
pub(super) struct Bindings {
    events: UnboundedSender<Event>,
    view: Arc<Mutex<View>>,
    task: JoinHandle<()>,
    local: JoinHandle<()>,
}

impl Drop for Bindings {
    fn drop(&mut self) {
        self.task.abort();
        self.local.abort();
    }
}

/// Own local sockets by identity, with the generation each was published at.
/// A Binding links directly to the socket of the generation it carries.
pub(super) type Endpoints = Arc<Mutex<BTreeMap<PublicationId, (u64, PathBuf)>>>;

impl Bindings {
    pub(super) fn start(
        runtime: &Path,
        identity: Identity,
        policy: MemoryTender,
        links: Links,
        endpoints: Endpoints,
        local: Watch,
        grace: Duration,
    ) -> io::Result<Self> {
        let directory = paths::bindings_dir(runtime);
        // Bindings belong to a running daemon; a previous run's are stale.
        // The daemon has already checked that the runtime directory is this
        // user's own and private, so nobody else can plant what is removed.
        match fs::remove_dir_all(&directory) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
        fs::create_dir(&directory)?;
        fs::set_permissions(&directory, Permissions::from_mode(0o700))?;
        // Unbounded: senders are the followers and the local watch, each one
        // snapshot per change, and the Binder drains every pending event
        // before each rebind, so the backlog stays at a few snapshots.
        let (events, receiver) = unbounded_channel();
        let view = Arc::new(Mutex::new(View::default()));
        let own = identity.fingerprint();
        let binder = Binder {
            runtime: runtime.to_owned(),
            own: own.clone(),
            identity,
            policy,
            links,
            endpoints,
            grace,
            local: Vec::new(),
            peers: BTreeMap::new(),
            bound: BTreeMap::new(),
            events: events.clone(),
            view: view.clone(),
        };
        let task = spawn(binder.run(receiver));
        let forward = events.clone();
        let local = spawn(async move {
            let mut local = local;
            while let Some(snapshot) = local.recv().await {
                if forward.send(Event::Local(snapshot)).is_err() {
                    break;
                }
            }
        });
        Ok(Self { events, view, task, local })
    }

    pub(super) fn trust(&self, members: Vec<TrustedInstance>) {
        let _ = self.events.send(Event::Trust(members));
    }

    pub(super) fn endpoints_changed(&self) {
        let _ = self.events.send(Event::Endpoints);
    }

    pub(super) fn bindings(&self) -> Vec<BindingEntry> {
        self.view.lock().expect("view lock").bindings.clone()
    }

    pub(super) fn peers(&self) -> Vec<PeerStatus> {
        self.view.lock().expect("view lock").peers.clone()
    }
}

struct Binder {
    runtime: PathBuf,
    own: Fingerprint,
    identity: Identity,
    policy: MemoryTender,
    links: Links,
    endpoints: Endpoints,
    grace: Duration,
    local: Vec<Publication>,
    peers: BTreeMap<Fingerprint, Peer>,
    bound: BTreeMap<PublicationId, Bound>,
    events: UnboundedSender<Event>,
    view: Arc<Mutex<View>>,
}

struct Peer {
    name: String,
    /// The configured route, which this instance dials and holds a link over.
    route: Option<PeerRoute>,
    state: PeerState,
    link: Option<LinkState>,
    /// The follower's adapter, and the route it follows over.
    adapter: Option<(SshTender, Route)>,
    publications: Vec<Publication>,
    follower: JoinHandle<()>,
    linker: Option<JoinHandle<()>>,
}

impl Peer {
    /// While no route leads to the member, how its configured link stands.
    fn status(&self) -> PeerState {
        match (&self.state, &self.link) {
            (PeerState::NoRoute, Some(LinkState::Failed(reason))) => PeerState::Unreachable { reason: reason.clone() },
            (PeerState::NoRoute, Some(LinkState::Dialing)) => PeerState::Connecting,
            (state, _) => state.clone(),
        }
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.follower.abort();
        if let Some(linker) = &self.linker {
            linker.abort();
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Carrier {
    Local,
    Peer(Fingerprint),
}

struct Candidate<'a> {
    carrier: Carrier,
    publication: &'a Publication,
    reachable: bool,
}

impl Candidate<'_> {
    fn live(&self) -> bool {
        self.reachable && self.publication.availability == Availability::Available
    }
}

/// Which candidate carries a Binding: this instance's own copy while it is
/// live, else the current carrier while it is live, else the first live one,
/// else the current one, else the first. `None` only when no candidate admits
/// this instance any more.
fn choose(current: Option<&Carrier>, candidates: &[Candidate<'_>]) -> Option<usize> {
    let incumbent = current.and_then(|current| candidates.iter().position(|candidate| &candidate.carrier == current));
    candidates
        .iter()
        .position(|candidate| candidate.carrier == Carrier::Local && candidate.live())
        .or(incumbent.filter(|&index| candidates[index].live()))
        .or_else(|| candidates.iter().position(Candidate::live))
        .or(incumbent)
        .or((!candidates.is_empty()).then_some(0))
}

#[derive(Clone)]
enum Target {
    Refuse,
    Peer { adapter: SshTender, session: Session },
    Authority { policy: MemoryTender, session: Session },
}

enum Endpoint {
    /// The publication is this instance's own: the path is a symbolic link
    /// to its socket, with nothing in between.
    Link(PathBuf),
    Listener {
        target: Arc<Mutex<Target>>,
        task: JoinHandle<()>,
    },
}

struct Bound {
    path: PathBuf,
    carrier: Option<Carrier>,
    /// Since when every copy has been withdrawn or gone.
    ending: Option<Instant>,
    entry: BindingEntry,
    endpoint: Option<Endpoint>,
}

impl Drop for Bound {
    fn drop(&mut self) {
        if let Some(Endpoint::Listener { task, .. }) = &self.endpoint {
            task.abort();
        }
        let _ = fs::remove_file(&self.path);
    }
}

impl Binder {
    /// Rebinds after every batch of events, and when the earliest ending
    /// Binding's grace runs out.
    async fn run(mut self, mut events: UnboundedReceiver<Event>) {
        loop {
            let graces_end = self.bound.values().filter_map(|bound| bound.ending).min().map(|ending| ending + self.grace);
            select! {
                event = events.recv() => {
                    let Some(event) = event else { break };
                    self.apply(event);
                    while let Ok(event) = events.try_recv() {
                        self.apply(event);
                    }
                }
                () = until(graces_end) => {}
            }
            self.rebind();
        }
    }

    fn apply(&mut self, event: Event) {
        match event {
            Event::Local(snapshot) => self.local = snapshot,
            Event::Trust(members) => self.trust(members),
            Event::Endpoints => {}
            Event::Peer(fingerprint, update) => {
                let Some(peer) = self.peers.get_mut(&fingerprint) else { return };
                match update {
                    PeerUpdate::NoRoute => {
                        peer.adapter = None;
                        peer.state = PeerState::NoRoute;
                    }
                    PeerUpdate::Connecting => peer.state = PeerState::Connecting,
                    PeerUpdate::Connected(adapter, route) => peer.adapter = Some((adapter, route)),
                    PeerUpdate::Snapshot(publications) => {
                        peer.state = PeerState::Following { publications: publications.len() };
                        peer.publications = publications;
                    }
                    PeerUpdate::Lost(reason) => {
                        peer.adapter = None;
                        peer.state = PeerState::Unreachable { reason };
                    }
                    PeerUpdate::Link(state) => peer.link = Some(state),
                }
            }
        }
    }

    /// Follow each member, and hold a link to each with a configured route;
    /// a changed route redials its link.
    fn trust(&mut self, members: Vec<TrustedInstance>) {
        let members: BTreeMap<_, _> =
            members.into_iter().filter_map(|member| Some((member.key.fingerprint()?, member))).filter(|(fp, _)| fp != &self.own).collect();
        self.peers.retain(|fingerprint, _| members.contains_key(fingerprint));
        for (fingerprint, member) in members {
            let linker = |route: &PeerRoute| spawn(link(fingerprint.clone(), route.clone(), self.links.clone(), self.events.clone()));
            if let Some(peer) = self.peers.get_mut(&fingerprint) {
                peer.name = member.name;
                if peer.route != member.route {
                    if let Some(linker) = peer.linker.take() {
                        linker.abort();
                    }
                    peer.linker = member.route.as_ref().map(linker);
                    peer.link = None;
                    peer.route = member.route;
                }
                continue;
            }
            let linker = member.route.as_ref().map(linker);
            let follower =
                spawn(follow(fingerprint.clone(), self.identity.clone(), self.own.clone(), self.links.clone(), self.events.clone()));
            let peer = Peer {
                name: member.name,
                route: member.route,
                state: PeerState::NoRoute,
                link: None,
                adapter: None,
                publications: Vec::new(),
                follower,
                linker,
            };
            self.peers.insert(fingerprint, peer);
        }
    }

    fn rebind(&mut self) {
        let mut ids: BTreeSet<PublicationId> = self.bound.keys().cloned().collect();
        ids.extend(self.local.iter().map(|publication| publication.id.clone()));
        for peer in self.peers.values() {
            ids.extend(peer.publications.iter().map(|publication| publication.id.clone()));
        }
        for id in ids {
            self.bind(&id);
        }
        let view = View {
            bindings: self.bound.values().map(|bound| bound.entry.clone()).collect(),
            peers: self
                .peers
                .iter()
                .map(|(fingerprint, peer)| PeerStatus { fingerprint: fingerprint.clone(), name: peer.name.clone(), state: peer.status() })
                .collect(),
        };
        *self.view.lock().expect("view lock") = view;
    }

    fn bind(&mut self, id: &PublicationId) {
        // A `tender/<fingerprint>` scope is followed from that instance alone.
        let owner = id.scope.owner();
        let follows = |instance: &Fingerprint| owner.as_ref().is_none_or(|owner| owner == instance);
        let mut candidates = Vec::new();
        if let Some(publication) = self.local.iter().find(|publication| &publication.id == id).filter(|_| follows(&self.own)) {
            candidates.push(Candidate { carrier: Carrier::Local, publication, reachable: true });
        }
        for (fingerprint, peer) in self.peers.iter().filter(|(fingerprint, _)| follows(fingerprint)) {
            if let Some(publication) = peer.publications.iter().find(|publication| &publication.id == id) {
                let reachable = peer.adapter.is_some() && matches!(peer.state, PeerState::Following { .. });
                candidates.push(Candidate { carrier: Carrier::Peer(fingerprint.clone()), publication, reachable });
            }
        }
        // Withdrawn everywhere, or no copy left: a Binding stays for its grace,
        // which covers a move, and none is made for such an identity.
        let ending = candidates.iter().all(|candidate| candidate.publication.availability == Availability::Withdrawn);
        match (self.bound.get_mut(id), ending) {
            (None, true) => return,
            (Some(bound), true) => {
                if bound.ending.get_or_insert_with(Instant::now).elapsed() >= self.grace {
                    self.bound.remove(id);
                    return;
                }
            }
            (Some(bound), false) => bound.ending = None,
            (None, false) => {}
        }
        let path = paths::binding_path(&self.runtime, id);
        let current = self.bound.get(id).and_then(|bound| bound.carrier.clone());
        let chosen = choose(current.as_ref(), &candidates).map(|index| &candidates[index]);
        let (state, target, link, carrier) = match chosen {
            None => (BindingState::Revoked, Target::Refuse, None, None),
            Some(candidate) => {
                let route = match &candidate.carrier {
                    Carrier::Local => Route { instance: self.own.clone(), via: None },
                    Carrier::Peer(fingerprint) => match &self.peers[fingerprint].adapter {
                        Some((_, route)) => route.clone(),
                        None => Route { instance: fingerprint.clone(), via: None },
                    },
                };
                let session = Session { caller: self.own.clone(), pinned_host: route.instance.clone(), via: route.via.clone() };
                let state = match (candidate.reachable, candidate.publication.availability) {
                    (false, _) => BindingState::Unavailable { reason: UnavailableReason::RouteUnavailable, route: Some(route) },
                    (true, Availability::Available) => BindingState::Available { route },
                    (true, Availability::Unavailable) => {
                        BindingState::Unavailable { reason: UnavailableReason::PublisherUnavailable, route: Some(route) }
                    }
                    (true, Availability::Withdrawn) => {
                        BindingState::Unavailable { reason: UnavailableReason::Withdrawn, route: Some(route) }
                    }
                };
                let target = match (&candidate.carrier, candidate.live()) {
                    (_, false) => Target::Refuse,
                    (Carrier::Local, true) => Target::Authority { policy: self.policy.clone(), session },
                    (Carrier::Peer(fingerprint), true) => match &self.peers[fingerprint].adapter {
                        Some((adapter, _)) => Target::Peer { adapter: adapter.clone(), session },
                        None => Target::Refuse,
                    },
                };
                let own = candidate.carrier == Carrier::Local
                    && candidate.publication.publisher == self.own
                    && candidate.publication.availability != Availability::Withdrawn;
                let generation = candidate.publication.generation;
                let endpoints = self.endpoints.lock().expect("endpoints lock");
                let link = endpoints.get(id).filter(|(published, _)| own && *published == generation).map(|(_, path)| path.clone());
                (state, target, link, Some(candidate.carrier.clone()))
            }
        };
        let (label, display) = match chosen {
            Some(candidate) => (candidate.publication.label.clone(), candidate.publication.display.clone()),
            None => match self.bound.get(id) {
                Some(bound) => (bound.entry.label.clone(), bound.entry.display.clone()),
                None => return,
            },
        };
        let bound = self.bound.entry(id.clone()).or_insert_with(|| Bound {
            path: path.clone(),
            carrier: None,
            ending: None,
            entry: BindingEntry {
                publication: id.clone(),
                label: label.clone(),
                display: display.clone(),
                local_endpoint: path.clone(),
                state: state.clone(),
            },
            endpoint: None,
        });
        bound.carrier = carrier;
        bound.entry.label = label;
        bound.entry.display = display;
        bound.entry.state = state;
        if let Err(error) = place(bound, id, link, target) {
            tracing::warn!(%id, path = %bound.path.display(), %error, "cannot place Binding");
        }
    }
}

/// Make the Binding's path a link to `link`, or a listener serving `target`.
/// A listener already in place keeps serving, now toward `target`.
fn place(bound: &mut Bound, id: &PublicationId, link: Option<PathBuf>, target: Target) -> io::Result<()> {
    match (&bound.endpoint, link) {
        (Some(Endpoint::Link(current)), Some(link)) if current == &link => Ok(()),
        (_, Some(link)) => {
            let mut staging = bound.path.clone().into_os_string();
            staging.push(format!(".link-{}", process::id()));
            let staging = PathBuf::from(staging);
            let _ = fs::remove_file(&staging);
            symlink(&link, &staging)?;
            fs::rename(&staging, &bound.path)?;
            if let Some(Endpoint::Listener { task, .. }) = bound.endpoint.replace(Endpoint::Link(link)) {
                task.abort();
            }
            Ok(())
        }
        (Some(Endpoint::Listener { target: current, .. }), None) => {
            *current.lock().expect("target lock") = target;
            Ok(())
        }
        (_, None) => {
            match fs::remove_file(&bound.path) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
                _ => {}
            }
            let listener = UnixListener::bind(&bound.path)?;
            fs::set_permissions(&bound.path, Permissions::from_mode(0o600))?;
            let shared = Arc::new(Mutex::new(target));
            let task = spawn(serve(listener, id.clone(), shared.clone()));
            if let Some(Endpoint::Listener { task, .. }) = bound.endpoint.replace(Endpoint::Listener { target: shared, task }) {
                task.abort();
            }
            Ok(())
        }
    }
}

/// Each connection opens its stream into the publisher as it arrives; while
/// the Binding has no live carrier it is closed at once, with no bytes.
async fn serve(listener: UnixListener, id: PublicationId, target: Arc<Mutex<Target>>) {
    loop {
        let Ok((mut local, _)) = listener.accept().await else { break };
        let target = target.lock().expect("target lock").clone();
        let id = id.clone();
        spawn(async move {
            let remote = match target {
                Target::Refuse => return,
                Target::Peer { adapter, session } => adapter.connect(&session, &id).await,
                Target::Authority { policy, session } => policy.connect(&session, &id).await,
            };
            if let Ok(mut remote) = remote {
                let _ = copy_bidirectional(&mut local, &mut remote).await;
            }
        });
    }
}

/// Hold a link to one member over its configured route, restoring it with
/// backoff, through a fresh SSH forward where it has one, whenever it fails.
async fn link(fingerprint: Fingerprint, route: PeerRoute, links: Links, events: UnboundedSender<Event>) {
    let send = |state| events.send(Event::Peer(fingerprint.clone(), PeerUpdate::Link(state))).is_ok();
    let mut delay = RETRY_FIRST;
    loop {
        if !send(LinkState::Dialing) {
            return;
        }
        let attempt = async {
            let (socket, forward) = match &route.ssh {
                None => (route.socket.clone(), None),
                Some(destination) => {
                    let forward = Forward::start(SshTarget::Ambient { destination: destination.clone() }, &route.socket)
                        .await
                        .map_err(|error| format!("ssh {destination}: {error}"))?;
                    (forward.socket().to_owned(), Some(forward))
                }
            };
            let dial: Arc<dyn Dial> = Arc::new(UnixDial(socket));
            let link = links.connect(dial, &fingerprint).await.map_err(|error| format!("{error:?}"))?;
            Ok::<_, String>((link, forward))
        }
        .await;
        match attempt {
            Ok((mut link, _forward)) => {
                let connected = Instant::now();
                if !send(LinkState::Up) {
                    return;
                }
                link.closed().await;
                if !send(LinkState::Failed("the link closed".into())) {
                    return;
                }
                // Only a link that stayed up earns a quick retry; one that
                // drops as soon as it opens backs off like a failure, so a
                // link that keeps flapping is retried at the longest delay.
                delay = if connected.elapsed() >= ROUTE_SETTLED { RETRY_FIRST } else { (delay * 2).min(RETRY_LONGEST) };
            }
            Err(reason) => {
                if !send(LinkState::Failed(reason)) {
                    return;
                }
                delay = (delay * 2).min(RETRY_LONGEST);
            }
        }
        sleep(delay).await;
    }
}

/// Follow one member's publications over the route the links have learned
/// to it: a direct link whoever dialed it, or a next hop that relays. While
/// none leads there it waits for one; a route that fails, or a member that
/// refuses, is retried when the routes change, or with backoff.
async fn follow(fingerprint: Fingerprint, identity: Identity, own: Fingerprint, links: Links, events: UnboundedSender<Event>) {
    let send = |update| events.send(Event::Peer(fingerprint.clone(), update)).is_ok();
    let mut changes = links.changes();
    let mut delay = RETRY_FIRST;
    loop {
        changes.borrow_and_update();
        let Some(route) = links.route(&fingerprint) else {
            if !send(PeerUpdate::NoRoute) || changes.changed().await.is_err() {
                return;
            }
            continue;
        };
        if !send(PeerUpdate::Connecting) {
            return;
        }
        let session = Session { caller: own.clone(), pinned_host: fingerprint.clone(), via: route.via.clone() };
        let attempt = async {
            let dial: Arc<dyn Dial> = Arc::new(links.clone());
            let adapter = SshTender::with_dial(dial, fingerprint.clone(), vec![identity.clone()]).map_err(|error| error.to_string())?;
            let watch = adapter.subscribe(&session).await.map_err(|error| format!("{error:?}"))?;
            Ok::<_, String>((adapter, watch))
        }
        .await;
        match attempt {
            Ok((adapter, mut watch)) => {
                let connected = Instant::now();
                if !send(PeerUpdate::Connected(adapter, route)) {
                    return;
                }
                while let Some(snapshot) = watch.recv().await {
                    if !send(PeerUpdate::Snapshot(snapshot)) {
                        return;
                    }
                }
                if !send(PeerUpdate::Lost("the route closed".into())) {
                    return;
                }
                delay = if connected.elapsed() >= ROUTE_SETTLED { RETRY_FIRST } else { (delay * 2).min(RETRY_LONGEST) };
            }
            Err(reason) => {
                if !send(PeerUpdate::Lost(reason)) {
                    return;
                }
                delay = (delay * 2).min(RETRY_LONGEST);
            }
        }
        select! {
            changed = changes.changed() => if changed.is_err() { return },
            () = sleep(delay) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use hegel::{TestCase, generators as gs};

    use super::*;
    use crate::{Label, PublicationId};

    fn publication(availability: Availability) -> Publication {
        Publication {
            id: PublicationId::new("s", "n"),
            label: Label::default(),
            display: String::new(),
            publisher: Fingerprint("p".into()),
            audience: BTreeSet::new(),
            generation: 1,
            availability,
        }
    }

    /// Lets the Binder run until `done`, without moving the paused clock.
    async fn settled(what: &str, done: impl Fn() -> bool) {
        for _ in 0..1000 {
            if done() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("{what}");
    }

    // A withdrawn publication's Binding stays for its grace and goes when the
    // grace runs out, with nothing else happening.
    #[tokio::test(start_paused = true)]
    async fn an_ending_binding_goes_when_its_grace_runs_out() {
        let runtime = tempfile::Builder::new().prefix("tb-").permissions(Permissions::from_mode(0o700)).tempdir().expect("runtime");
        let identity = Identity::from_secret([1; 32]);
        let policy = MemoryTender::new(identity.fingerprint());
        let (local, own) = unbounded_channel();
        let grace = Duration::from_secs(60);
        let server = crate::ssh::Server::in_process(identity.clone(), policy.clone()).expect("server");
        let bindings =
            Bindings::start(runtime.path(), identity, policy, server.links().clone(), Endpoints::default(), own, grace).expect("bindings");
        local.send(vec![publication(Availability::Available)]).expect("binder follows");
        settled("the publication is bound", || bindings.bindings().len() == 1).await;
        local.send(vec![publication(Availability::Withdrawn)]).expect("binder follows");
        let withdrawn = |entries: Vec<BindingEntry>| matches!(entries.as_slice(), [entry] if matches!(entry.state, BindingState::Unavailable { reason: UnavailableReason::Withdrawn, .. }));
        settled("the Binding shows the withdrawal", || withdrawn(bindings.bindings())).await;

        sleep(grace - Duration::from_millis(1)).await;
        assert!(withdrawn(bindings.bindings()), "the Binding stays for its grace");
        sleep(Duration::from_millis(1)).await;
        settled("the grace ends the Binding", || bindings.bindings().is_empty()).await;
    }

    // Over any set of carriers and any current carrier: this instance's own
    // live copy is taken; otherwise a live incumbent is kept; otherwise a live
    // carrier is chosen if one exists; a Binding is left without a carrier
    // only when nothing admits this instance.
    #[hegel::test]
    fn own_copy_then_live_incumbent_win(tc: TestCase) {
        let states = [Availability::Available, Availability::Unavailable, Availability::Withdrawn];
        let count = tc.draw(gs::integers::<usize>().max_value(4));
        let records: Vec<_> =
            (0..count).map(|_| (publication(states[tc.draw(gs::integers::<usize>().max_value(2))]), tc.draw(gs::booleans()))).collect();
        let candidates: Vec<_> = records
            .iter()
            .enumerate()
            .map(|(index, (publication, reachable))| Candidate {
                carrier: if index == 0 { Carrier::Local } else { Carrier::Peer(Fingerprint(index.to_string())) },
                publication,
                reachable: *reachable,
            })
            .collect();
        let current = tc.draw(gs::integers::<usize>().max_value(5));
        let current = (current < 5).then(|| if current == 0 { Carrier::Local } else { Carrier::Peer(Fingerprint(current.to_string())) });
        let chosen = choose(current.as_ref(), &candidates);
        assert_eq!(chosen.is_none(), candidates.is_empty());
        let incumbent = candidates.iter().position(|candidate| Some(&candidate.carrier) == current.as_ref());
        if candidates.first().is_some_and(Candidate::live) {
            assert_eq!(chosen, Some(0), "the own copy, carried locally");
        } else if let Some(index) = incumbent.filter(|&index| candidates[index].live()) {
            assert_eq!(chosen, Some(index));
        } else if candidates.iter().any(Candidate::live) {
            assert!(candidates[chosen.expect("a carrier")].live());
        } else if let Some(index) = incumbent {
            assert_eq!(chosen, Some(index));
        }
    }
}
