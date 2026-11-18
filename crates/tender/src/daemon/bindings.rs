//! Eager Bindings: this instance follows the publication lists of its Trusted
//! Group and keeps a Binding, at the identity's fixed path, for every
//! publication that admits it, its own included.

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use rigging_ssh::Target as SshTarget;
use tokio::{
    net::UnixListener,
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    task::JoinHandle,
    time::{Instant, sleep},
};

use crate::{
    Availability, BindingState, Fingerprint, Publication, PublicationId, Route, Session, Tender, UnavailableReason,
    api::{BindingEntry, PeerRoute, PeerState, PeerStatus, TrustedInstance},
    memory::MemoryTender,
    paths,
    ssh::{Forward, Identity, SshTender},
};

const RETRY_FIRST: Duration = Duration::from_millis(100);
const RETRY_LONGEST: Duration = Duration::from_secs(8);
const ROUTE_SETTLED: Duration = Duration::from_secs(10);

pub(super) enum Event {
    Local(Vec<Publication>),
    Trust(Vec<TrustedInstance>),
    Peer(Fingerprint, PeerUpdate),
}

pub(super) enum PeerUpdate {
    Connecting,
    Connected(SshTender),
    Snapshot(Vec<Publication>),
    Lost(String),
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

/// Own local sockets by identity, which a Binding links to directly.
pub(super) type Endpoints = Arc<Mutex<BTreeMap<PublicationId, PathBuf>>>;

impl Bindings {
    pub(super) fn start(
        runtime: &Path,
        identity: Identity,
        policy: MemoryTender,
        endpoints: Endpoints,
        local: crate::Watch,
    ) -> io::Result<Self> {
        let directory = paths::bindings_dir(runtime);
        // Bindings belong to a running daemon; a previous run's are stale.
        // The daemon has already checked that the runtime directory is this
        // user's own and private, so nobody else can plant what is removed.
        match std::fs::remove_dir_all(&directory) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
        std::fs::create_dir(&directory)?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
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
            endpoints,
            local: Vec::new(),
            peers: BTreeMap::new(),
            bound: BTreeMap::new(),
            events: events.clone(),
            view: view.clone(),
        };
        let task = tokio::spawn(binder.run(receiver));
        let forward = events.clone();
        let local = tokio::spawn(async move {
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
    endpoints: Endpoints,
    local: Vec<Publication>,
    peers: BTreeMap<Fingerprint, Peer>,
    bound: BTreeMap<PublicationId, Bound>,
    events: UnboundedSender<Event>,
    view: Arc<Mutex<View>>,
}

struct Peer {
    name: String,
    route: Option<PeerRoute>,
    state: PeerState,
    adapter: Option<SshTender>,
    publications: Vec<Publication>,
    follower: Option<JoinHandle<()>>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(follower) = &self.follower {
            follower.abort();
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

/// Which candidate carries a Binding: the current carrier while it is live,
/// else the first live one, else the current one, else the first. `None`
/// only when no candidate admits this instance any more.
fn choose(current: Option<&Carrier>, candidates: &[Candidate<'_>]) -> Option<usize> {
    let incumbent = current.and_then(|current| candidates.iter().position(|candidate| &candidate.carrier == current));
    incumbent
        .filter(|&index| candidates[index].live())
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
    entry: BindingEntry,
    endpoint: Option<Endpoint>,
}

impl Drop for Bound {
    fn drop(&mut self) {
        if let Some(Endpoint::Listener { task, .. }) = &self.endpoint {
            task.abort();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Binder {
    async fn run(mut self, mut events: UnboundedReceiver<Event>) {
        while let Some(event) = events.recv().await {
            self.apply(event);
            while let Ok(event) = events.try_recv() {
                self.apply(event);
            }
            self.rebind();
        }
    }

    fn apply(&mut self, event: Event) {
        match event {
            Event::Local(snapshot) => self.local = snapshot,
            Event::Trust(members) => self.trust(members),
            Event::Peer(fingerprint, update) => {
                let Some(peer) = self.peers.get_mut(&fingerprint) else { return };
                match update {
                    PeerUpdate::Connecting => peer.state = PeerState::Connecting,
                    PeerUpdate::Connected(adapter) => peer.adapter = Some(adapter),
                    PeerUpdate::Snapshot(publications) => {
                        peer.state = PeerState::Following { publications: publications.len() };
                        peer.publications = publications;
                    }
                    PeerUpdate::Lost(reason) => {
                        peer.adapter = None;
                        peer.state = PeerState::Unreachable { reason };
                    }
                }
            }
        }
    }

    /// Follow each member with a route; a changed route restarts its follower.
    fn trust(&mut self, members: Vec<TrustedInstance>) {
        let members: BTreeMap<_, _> =
            members.into_iter().filter_map(|member| Some((member.key.fingerprint()?, member))).filter(|(fp, _)| fp != &self.own).collect();
        self.peers.retain(|fingerprint, peer| members.get(fingerprint).is_some_and(|member| member.route == peer.route));
        for (fingerprint, member) in members {
            if let Some(peer) = self.peers.get_mut(&fingerprint) {
                peer.name = member.name;
                continue;
            }
            let follower = member.route.clone().map(|route| {
                tokio::spawn(follow(fingerprint.clone(), route, self.identity.clone(), self.own.clone(), self.events.clone()))
            });
            let state = if follower.is_some() { PeerState::Connecting } else { PeerState::NoRoute };
            self.peers.insert(
                fingerprint,
                Peer { name: member.name, route: member.route, state, adapter: None, publications: Vec::new(), follower },
            );
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
                .map(|(fingerprint, peer)| PeerStatus {
                    fingerprint: fingerprint.clone(),
                    name: peer.name.clone(),
                    state: peer.state.clone(),
                })
                .collect(),
        };
        *self.view.lock().expect("view lock") = view;
    }

    fn bind(&mut self, id: &PublicationId) {
        let mut candidates = Vec::new();
        if let Some(publication) = self.local.iter().find(|publication| &publication.id == id) {
            candidates.push(Candidate { carrier: Carrier::Local, publication, reachable: true });
        }
        for (fingerprint, peer) in &self.peers {
            if let Some(publication) = peer.publications.iter().find(|publication| &publication.id == id) {
                let reachable = peer.adapter.is_some() && matches!(peer.state, PeerState::Following { .. });
                candidates.push(Candidate { carrier: Carrier::Peer(fingerprint.clone()), publication, reachable });
            }
        }
        let path = paths::binding_path(&self.runtime, id);
        let current = self.bound.get(id).and_then(|bound| bound.carrier.clone());
        let chosen = choose(current.as_ref(), &candidates).map(|index| &candidates[index]);
        let (state, target, link, carrier) = match chosen {
            None => (BindingState::Revoked, Target::Refuse, None, None),
            Some(candidate) => {
                let instance = match &candidate.carrier {
                    Carrier::Local => self.own.clone(),
                    Carrier::Peer(fingerprint) => fingerprint.clone(),
                };
                let route = Route { instance: instance.clone(), via: None };
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
                let session = Session { caller: self.own.clone(), pinned_host: instance, via: None };
                let target = match (&candidate.carrier, candidate.live()) {
                    (_, false) => Target::Refuse,
                    (Carrier::Local, true) => Target::Authority { policy: self.policy.clone(), session },
                    (Carrier::Peer(fingerprint), true) => match &self.peers[fingerprint].adapter {
                        Some(adapter) => Target::Peer { adapter: adapter.clone(), session },
                        None => Target::Refuse,
                    },
                };
                let own = candidate.carrier == Carrier::Local
                    && candidate.publication.publisher == self.own
                    && candidate.publication.availability != Availability::Withdrawn;
                let link = own.then(|| self.endpoints.lock().expect("endpoints lock").get(id).cloned()).flatten();
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
            staging.push(format!(".link-{}", std::process::id()));
            let staging = PathBuf::from(staging);
            let _ = std::fs::remove_file(&staging);
            std::os::unix::fs::symlink(&link, &staging)?;
            std::fs::rename(&staging, &bound.path)?;
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
            match std::fs::remove_file(&bound.path) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
                _ => {}
            }
            let listener = UnixListener::bind(&bound.path)?;
            std::fs::set_permissions(&bound.path, std::fs::Permissions::from_mode(0o600))?;
            let shared = Arc::new(Mutex::new(target));
            let task = tokio::spawn(serve(listener, id.clone(), shared.clone()));
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
        tokio::spawn(async move {
            let remote = match target {
                Target::Refuse => return,
                Target::Peer { adapter, session } => adapter.connect(&session, &id).await,
                Target::Authority { policy, session } => policy.connect(&session, &id).await,
            };
            if let Ok(mut remote) = remote {
                let _ = tokio::io::copy_bidirectional(&mut local, &mut remote).await;
            }
        });
    }
}

/// Follow one member's publications over its route, restoring the route,
/// through a fresh SSH forward where it has one, whenever it fails.
async fn follow(fingerprint: Fingerprint, route: PeerRoute, identity: Identity, own: Fingerprint, events: UnboundedSender<Event>) {
    let session = Session { caller: own, pinned_host: fingerprint.clone(), via: None };
    let send = |update| events.send(Event::Peer(fingerprint.clone(), update)).is_ok();
    let mut delay = RETRY_FIRST;
    loop {
        if !send(PeerUpdate::Connecting) {
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
            let adapter = SshTender::new(socket, fingerprint.clone(), vec![identity.clone()]).map_err(|error| error.to_string())?;
            let watch = adapter.subscribe(&session).await.map_err(|error| format!("{error:?}"))?;
            Ok::<_, String>((adapter, watch, forward))
        }
        .await;
        match attempt {
            Ok((adapter, mut watch, _forward)) => {
                let connected = Instant::now();
                if !send(PeerUpdate::Connected(adapter)) {
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
                // Only a route that stayed up earns a quick retry; one that
                // drops as soon as it opens backs off like a failure.
                delay = if connected.elapsed() >= ROUTE_SETTLED { RETRY_FIRST } else { (delay * 2).min(RETRY_LONGEST) };
            }
            Err(reason) => {
                if !send(PeerUpdate::Lost(reason)) {
                    return;
                }
                delay = (delay * 2).min(RETRY_LONGEST);
            }
        }
        sleep(delay).await;
    }
}

#[cfg(test)]
mod tests {
    use hegel::generators as gs;

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

    // Over any set of carriers and any current carrier: a live incumbent is
    // kept; otherwise a live carrier is chosen if one exists; a Binding is
    // left without a carrier only when nothing admits this instance.
    #[hegel::test]
    fn live_incumbent_wins_and_bindings_follow_live_carriers(tc: hegel::TestCase) {
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
        if let Some(index) = incumbent.filter(|&index| candidates[index].live()) {
            assert_eq!(chosen, Some(index));
        } else if candidates.iter().any(Candidate::live) {
            assert!(candidates[chosen.expect("a carrier")].live());
        } else if let Some(index) = incumbent {
            assert_eq!(chosen, Some(index));
        }
    }
}
