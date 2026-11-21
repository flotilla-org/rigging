//! Links between instances, and the routes learned over them.
//!
//! A link is one authenticated stream between two instances, held open as its
//! control stream. Once up it is symmetric: either end opens streams to the
//! other over it, whoever dialed. The dialer opens them through its own
//! [`Dial`]; the end that accepted asks the dialer for one with
//! [`Frame::Open`], and the dialer opens a fresh stream to it and hands it over
//! ([`crate::ssh`]'s `Adopt`), then serves it as it serves its own listener.
//! Every stream still authenticates end to end, so a link only carries bytes.
//! A stream opened over a link ends with it, as an SSH session's channels end
//! with the session.
//!
//! Each end tells the other, in [`Frame::Routes`], every instance it reaches
//! and by which path. A route is a live link to an instance, or a neighbour's
//! path to it through one; nothing else is a route, and an instance with none
//! is unavailable. Routes through a link go when it closes, or when its far
//! end stops listing them.

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf, split},
    spawn,
    sync::{mpsc, oneshot, watch},
    task::AbortHandle,
    time::timeout,
};

use crate::{
    ByteStream, Dial, Error, Fingerprint, Route, Router,
    api::RouteStatus,
    ssh::{Identity, MAX_RELAY_HOPS, OPEN_TIMEOUT, Request, Response, client_handshake, read_control, write_control},
};

/// The longest path a route may take, counting its last hop: a relayed
/// stream crosses at most this many instances after the caller.
const MAX_PATH: usize = MAX_RELAY_HOPS as usize;

/// One instance the sender reaches: `path` is the hops after the sender, the
/// last of them `instance` itself.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Reach {
    instance: Fingerprint,
    path: Vec<Fingerprint>,
}

/// What each end of a link writes on its control stream.
#[derive(Serialize, Deserialize)]
pub(crate) enum Frame {
    /// Every instance the sender reaches, other than itself and the receiver.
    /// It replaces the sender's previous table: leaving one out withdraws it.
    Routes(Vec<Reach>),
    /// From the end that accepted the link: open a stream to me, and hand it
    /// over as `Adopt` with this token.
    Open(u64),
}

/// This instance's live links and the routes learned over them. Clones share
/// them.
#[derive(Clone)]
pub struct Links {
    shared: Arc<Shared>,
}

struct Shared {
    own: Fingerprint,
    identity: Identity,
    table: Mutex<Table>,
    changes: watch::Sender<()>,
    /// Streams this instance serves as if its own listener accepted them: the
    /// ones it opens back to an end that asked for one.
    serve: mpsc::UnboundedSender<ByteStream>,
}

#[derive(Default)]
struct Table {
    next_link: u64,
    next_token: u64,
    links: BTreeMap<u64, Entry>,
    /// Each reachable instance's paths, one per next hop, the primary first.
    /// A path starts at the next hop and ends at the instance.
    routes: BTreeMap<Fingerprint, Vec<Vec<Fingerprint>>>,
}

struct Entry {
    peer: Fingerprint,
    /// How this end opens streams to the peer: present when it dialed the link.
    dial: Option<Arc<dyn Dial>>,
    frames: mpsc::UnboundedSender<Frame>,
    /// The peer's latest table: each instance it reaches, with its path.
    learned: BTreeMap<Fingerprint, Vec<Fingerprint>>,
    advertised: Option<Vec<Reach>>,
    /// Streams asked of the dialer and not yet handed over.
    pending: BTreeMap<u64, oneshot::Sender<ByteStream>>,
    ended: watch::Sender<bool>,
    tasks: Vec<AbortHandle>,
}

impl Drop for Entry {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        self.ended.send_replace(true);
    }
}

/// A link this instance dialed. Dropping it closes the link.
pub struct Link {
    links: Weak<Shared>,
    id: u64,
    ended: watch::Receiver<bool>,
}

impl Link {
    /// Waits until the link closes, from either end.
    pub async fn closed(&mut self) {
        let _ = self.ended.wait_for(|ended| *ended).await;
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        if let Some(shared) = self.links.upgrade() {
            Links { shared }.remove(self.id);
        }
    }
}

impl Links {
    pub(crate) fn new(identity: Identity, serve: mpsc::UnboundedSender<ByteStream>) -> Self {
        Self {
            shared: Arc::new(Shared {
                own: identity.fingerprint(),
                identity,
                table: Mutex::new(Table::default()),
                changes: watch::channel(()).0,
                serve,
            }),
        }
    }

    /// Dial `peer` and hold a link to it until the [`Link`] is dropped or
    /// either end closes it. The far end admits only an instance it lets
    /// connect, as a relay admits its upstream.
    pub async fn connect(&self, dial: Arc<dyn Dial>, peer: &Fingerprint) -> Result<Link, Error> {
        let stream = timeout(OPEN_TIMEOUT, async {
            let mut stream = dial.dial(peer).await.map_err(|_| Error::Unavailable)?;
            client_handshake(&mut stream, &self.shared.identity, peer).await?;
            write_control(&mut stream, &Request::Link).await.map_err(|_| Error::Unavailable)?;
            match read_control(&mut stream).await.map_err(|_| Error::Unavailable)? {
                Response::Open => Ok(stream),
                Response::Error(error) => Err(error),
                _ => Err(Error::Unavailable),
            }
        })
        .await
        .map_err(|_| Error::Deadline)??;
        let id = self.register(peer.clone(), Some(dial), stream);
        let ended = self.shared.table.lock().expect("links lock").links.get(&id).map(|entry| entry.ended.subscribe());
        // A link that closed as soon as it opened is already gone.
        let ended = ended.unwrap_or_else(|| watch::channel(true).1);
        Ok(Link { links: Arc::downgrade(&self.shared), id, ended })
    }

    /// Hold a link `peer` dialed, which the server has authenticated and admitted.
    pub(crate) fn accept(&self, peer: Fingerprint, stream: ByteStream) {
        self.register(peer, None, stream);
    }

    /// The stream an end asked for with `token`, which the link's dialer,
    /// `caller`, has just opened.
    pub(crate) fn adopt(&self, caller: &Fingerprint, token: u64) -> Option<oneshot::Sender<ByteStream>> {
        let mut table = self.shared.table.lock().expect("links lock");
        table.links.values_mut().filter(|entry| &entry.peer == caller).find_map(|entry| entry.pending.remove(&token))
    }

    /// How this instance reaches `host`: directly, or through the next hop of
    /// its primary route. `None` while no live link leads there.
    pub fn route(&self, host: &Fingerprint) -> Option<Route> {
        let table = self.shared.table.lock().expect("links lock");
        let next = table.routes.get(host)?.first()?.first()?.clone();
        Some(Route { instance: host.clone(), via: (&next != host).then_some(next) })
    }

    /// Every reachable instance with its next hop and fallbacks.
    pub fn routes(&self) -> Vec<RouteStatus> {
        let table = self.shared.table.lock().expect("links lock");
        table
            .routes
            .iter()
            .map(|(instance, paths)| RouteStatus {
                instance: instance.clone(),
                next_hop: paths[0][0].clone(),
                hops: paths[0].len(),
                fallbacks: paths[1..].iter().map(|path| path[0].clone()).collect(),
            })
            .collect()
    }

    /// Told whenever a route comes, goes or changes its next hop.
    pub fn changes(&self) -> watch::Receiver<()> {
        self.shared.changes.subscribe()
    }

    /// Close every link to a peer `keep` refuses.
    pub fn retain(&self, keep: impl Fn(&Fingerprint) -> bool) {
        let mut table = self.shared.table.lock().expect("links lock");
        let before = table.links.len();
        table.links.retain(|_, entry| keep(&entry.peer));
        if table.links.len() != before {
            self.changed(&mut table);
        }
    }

    fn register(&self, peer: Fingerprint, dial: Option<Arc<dyn Dial>>, stream: ByteStream) -> u64 {
        let (frames, outgoing) = mpsc::unbounded_channel();
        let (reader, writer) = split(stream);
        let mut table = self.shared.table.lock().expect("links lock");
        let id = table.next_link;
        table.next_link += 1;
        let weak = Arc::downgrade(&self.shared);
        let tasks = vec![
            spawn(write_frames(writer, outgoing, weak.clone(), id)).abort_handle(),
            spawn(read_frames(reader, weak, id)).abort_handle(),
        ];
        let ended = watch::channel(false).0;
        let entry = Entry { peer, dial, frames, learned: BTreeMap::new(), advertised: None, pending: BTreeMap::new(), ended, tasks };
        table.links.insert(id, entry);
        self.changed(&mut table);
        id
    }

    fn remove(&self, id: u64) {
        let mut table = self.shared.table.lock().expect("links lock");
        if table.links.remove(&id).is_some() {
            self.changed(&mut table);
        }
    }

    /// Take a peer's new table. Paths that would loop back here, or run
    /// past the hop bound, are not routes; a malformed table closes the link.
    fn learn(&self, id: u64, reaches: Vec<Reach>) -> Result<(), ()> {
        let mut table = self.shared.table.lock().expect("links lock");
        let Some(entry) = table.links.get_mut(&id) else { return Ok(()) };
        let mut learned = BTreeMap::new();
        for reach in reaches {
            let distinct: BTreeSet<_> = reach.path.iter().collect();
            if reach.path.last() != Some(&reach.instance) || distinct.len() != reach.path.len() || distinct.contains(&entry.peer) {
                return Err(());
            }
            if reach.path.len() < MAX_PATH && !distinct.contains(&self.shared.own) && learned.insert(reach.instance, reach.path).is_some() {
                return Err(());
            }
        }
        if entry.learned != learned {
            entry.learned = learned;
            self.changed(&mut table);
        }
        Ok(())
    }

    /// The far end asks this one, its dialer, for a stream: open one through
    /// the link's dialer and hand it over, then serve it. Only the end that
    /// accepted a link may ask.
    fn reverse(&self, id: u64, token: u64) -> Result<(), ()> {
        let (peer, dial, ended) = {
            let table = self.shared.table.lock().expect("links lock");
            let Some(entry) = table.links.get(&id) else { return Ok(()) };
            (entry.peer.clone(), entry.dial.clone().ok_or(())?, entry.ended.subscribe())
        };
        let identity = self.shared.identity.clone();
        let serve = self.shared.serve.clone();
        // A failed open reaches the asking end as its own open deadline.
        spawn(async move {
            let opened = timeout(OPEN_TIMEOUT, async {
                let mut stream = dial.dial(&peer).await.ok()?;
                client_handshake(&mut stream, &identity, &peer).await.ok()?;
                write_control(&mut stream, &Request::Adopt(token)).await.ok()?;
                matches!(read_control(&mut stream).await, Ok(Response::Open)).then_some(stream)
            })
            .await;
            if let Ok(Some(stream)) = opened {
                let _ = serve.send(Tied::stream(stream, ended));
            }
        });
        Ok(())
    }

    /// Recompute the routes, tell each peer its table where it changed, and
    /// tell watchers.
    fn changed(&self, table: &mut Table) {
        let routes = choose_routes(&table.links, &table.routes);
        let changed = routes != table.routes;
        table.routes = routes;
        for entry in table.links.values_mut() {
            let reaches = advertised(&table.routes, &entry.peer);
            if entry.advertised.as_ref() != Some(&reaches) {
                // A closed writer means the link is closing; its reader removes it.
                let _ = entry.frames.send(Frame::Routes(reaches.clone()));
                entry.advertised = Some(reaches);
            }
        }
        if changed {
            self.shared.changes.send_replace(());
        }
    }
}

/// For each instance, its shortest path through each next hop: a direct link,
/// or a peer's path with the peer in front. The shortest comes first; ties
/// keep the current next hop, then go to the lowest fingerprint.
fn choose_routes(
    links: &BTreeMap<u64, Entry>,
    current: &BTreeMap<Fingerprint, Vec<Vec<Fingerprint>>>,
) -> BTreeMap<Fingerprint, Vec<Vec<Fingerprint>>> {
    let mut candidates: BTreeMap<Fingerprint, Vec<Vec<Fingerprint>>> = BTreeMap::new();
    for entry in links.values() {
        candidates.entry(entry.peer.clone()).or_default().push(vec![entry.peer.clone()]);
        for (instance, path) in &entry.learned {
            candidates.entry(instance.clone()).or_default().push([std::slice::from_ref(&entry.peer), path].concat());
        }
    }
    for (instance, paths) in &mut candidates {
        let incumbent = current.get(instance).and_then(|paths| paths.first()).map(|path| &path[0]);
        paths.sort_by(|left, right| {
            left.len().cmp(&right.len()).then((Some(&left[0]) != incumbent).cmp(&(Some(&right[0]) != incumbent))).then(left.cmp(right))
        });
        let mut hops = BTreeSet::new();
        paths.retain(|path| hops.insert(path[0].clone()));
    }
    candidates
}

/// What to tell `peer`: for every other instance, the best path that does not
/// pass through `peer`, and is short enough for `peer` to use.
fn advertised(routes: &BTreeMap<Fingerprint, Vec<Vec<Fingerprint>>>, peer: &Fingerprint) -> Vec<Reach> {
    routes
        .iter()
        .filter(|(instance, _)| *instance != peer)
        .filter_map(|(instance, paths)| {
            let path = paths.iter().find(|path| path.len() < MAX_PATH && !path.contains(peer))?;
            Some(Reach { instance: instance.clone(), path: path.clone() })
        })
        .collect()
}

async fn write_frames(mut writer: WriteHalf<ByteStream>, mut outgoing: mpsc::UnboundedReceiver<Frame>, links: Weak<Shared>, id: u64) {
    while let Some(frame) = outgoing.recv().await {
        if let Err(error) = write_control(&mut writer, &frame).await {
            tracing::debug!(%error, "link closed while writing");
            break;
        }
    }
    if let Some(shared) = links.upgrade() {
        Links { shared }.remove(id);
    }
}

async fn read_frames(mut reader: ReadHalf<ByteStream>, links: Weak<Shared>, id: u64) {
    loop {
        let Ok(frame) = read_control::<Frame>(&mut reader).await else { break };
        let Some(shared) = links.upgrade() else { return };
        let links = Links { shared };
        let handled = match frame {
            Frame::Routes(reaches) => links.learn(id, reaches),
            Frame::Open(token) => links.reverse(id, token),
        };
        if handled.is_err() {
            tracing::debug!("link closed on a frame its peer may not send");
            break;
        }
    }
    if let Some(shared) = links.upgrade() {
        Links { shared }.remove(id);
    }
}

/// Opens a stream to a linked instance over the link, whoever dialed it: its
/// own dialer where this end dialed, else by asking the far end for one. An
/// instance with no live link is not dialed at all.
#[async_trait]
impl Dial for Links {
    async fn dial(&self, instance: &Fingerprint) -> io::Result<ByteStream> {
        let handed = {
            let mut table = self.shared.table.lock().expect("links lock");
            let outbound = table
                .links
                .values()
                .filter(|entry| &entry.peer == instance)
                .find_map(|entry| Some((entry.dial.clone()?, entry.ended.subscribe())));
            match outbound {
                Some(outbound) => Err(outbound),
                None => {
                    let token = table.next_token;
                    table.next_token += 1;
                    let entry = table
                        .links
                        .values_mut()
                        .find(|entry| &entry.peer == instance)
                        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no live link"))?;
                    let (sender, handed) = oneshot::channel();
                    entry.pending.retain(|_, waiting| !waiting.is_closed());
                    entry.pending.insert(token, sender);
                    entry.frames.send(Frame::Open(token)).map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))?;
                    Ok((handed, entry.ended.subscribe()))
                }
            }
        };
        match handed {
            Err((dial, ended)) => Ok(Tied::stream(dial.dial(instance).await?, ended)),
            Ok((handed, ended)) => {
                let stream = handed.await.map_err(|_| io::Error::new(io::ErrorKind::ConnectionAborted, "the link closed"))?;
                Ok(Tied::stream(stream, ended))
            }
        }
    }
}

impl Router for Links {
    fn next_hop(&self, host: &Fingerprint) -> Option<Fingerprint> {
        self.route(host).map(|route| route.via.unwrap_or(route.instance))
    }
}

/// A stream opened over a link, which fails once the link has closed.
struct Tied {
    stream: ByteStream,
    /// Done once the link has closed; `None` after that.
    ended: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl Tied {
    fn stream(stream: ByteStream, mut ended: watch::Receiver<bool>) -> ByteStream {
        let ended = Box::pin(async move {
            // A link whose entry has gone has closed too.
            let _ = ended.wait_for(|ended| *ended).await;
        });
        Box::new(Self { stream, ended: Some(ended) })
    }

    fn check(&mut self, context: &mut Context<'_>) -> io::Result<()> {
        if let Some(ended) = &mut self.ended
            && ended.as_mut().poll(context).is_ready()
        {
            self.ended = None;
        }
        match self.ended {
            Some(_) => Ok(()),
            None => Err(io::Error::new(io::ErrorKind::ConnectionAborted, "the link closed")),
        }
    }
}

impl AsyncRead for Tied {
    fn poll_read(mut self: Pin<&mut Self>, context: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.check(context)?;
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for Tied {
    fn poll_write(mut self: Pin<&mut Self>, context: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        self.check(context)?;
        Pin::new(&mut self.stream).poll_write(context, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check(context)?;
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(name: &str) -> Fingerprint {
        Fingerprint(name.into())
    }

    fn reach(path: &[&str]) -> Reach {
        Reach { instance: fp(path.last().expect("a path")), path: path.iter().map(|hop| fp(hop)).collect() }
    }

    /// Links whose instance holds a link accepted from `peer`, the first.
    fn linked(peer: &str) -> (Links, tokio::io::DuplexStream) {
        let links = Links::new(Identity::from_secret([7; 32]), mpsc::unbounded_channel().0);
        let (near, far) = tokio::io::duplex(1024);
        links.accept(fp(peer), Box::new(near));
        (links, far)
    }

    // A peer's path is a route only if it neither loops back through this
    // instance nor runs past the hop bound; a table that names a path not
    // ending at its instance, repeats a hop, names the peer itself or lists
    // an instance twice is malformed, and closes the link.
    #[tokio::test]
    async fn only_loop_free_bounded_paths_are_learned() {
        let (links, _far) = linked("b");
        let own = links.shared.own.0.clone();
        let long: Vec<String> = (0..MAX_PATH).map(|hop| format!("h{hop}")).collect();
        let long: Vec<&str> = long.iter().map(String::as_str).collect();
        links.learn(0, vec![reach(&["c"]), reach(&[&own, "d"]), reach(&long)]).expect("well formed");
        let reached: Vec<_> = links.routes().into_iter().map(|route| route.instance).collect();
        assert_eq!(reached, vec![fp("b"), fp("c")], "neither the loop through here nor the overlong path");
        for malformed in [
            vec![Reach { instance: fp("c"), path: vec![fp("d")] }],
            vec![reach(&["c", "c"])],
            vec![reach(&["b", "c"])],
            vec![reach(&["c"]), reach(&["d", "c"])],
        ] {
            assert!(links.learn(0, malformed).is_err());
        }
    }

    // A peer is told no path that passes through it, nor one it could not
    // extend within the hop bound; it is told the best other path instead.
    #[test]
    fn advertised_paths_avoid_their_receiver() {
        let long: Vec<_> = (0..MAX_PATH).map(|hop| fp(&format!("h{hop}"))).collect();
        let routes = BTreeMap::from([
            (fp("c"), vec![vec![fp("b"), fp("c")], vec![fp("d"), fp("e"), fp("c")]]),
            (fp("b"), vec![vec![fp("b")]]),
            (fp("x"), vec![vec![fp("b"), fp("x")]]),
            (long.last().cloned().expect("a hop"), vec![long.clone()]),
        ]);
        assert_eq!(advertised(&routes, &fp("b")), vec![reach(&["d", "e", "c"])]);
        assert_eq!(advertised(&routes, &fp("d")), vec![reach(&["b"]), reach(&["b", "c"]), reach(&["b", "x"])]);
    }
}
