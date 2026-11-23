mod bindings;
mod config;
mod control;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, DirBuilder, Permissions},
    io, mem,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Weak},
    time::Duration,
};

use libc::geteuid;
use rand_core::{OsRng, RngCore};
use rigging_http_serve::{Caller, UnixServer};
use rigging_paths::PathPolicy;
use rigging_process::EnvVars;
use tokio::{
    io::copy_bidirectional,
    net::UnixStream,
    select,
    signal::{
        ctrl_c,
        unix::{SignalKind, signal},
    },
    spawn,
    sync::{Mutex, mpsc, oneshot, watch},
    task::JoinHandle,
    time::{Instant, sleep, timeout},
};

use self::bindings::{BINDING_GRACE, Bindings, Endpoints};
pub use self::config::{Config, ConfiguredGrant, ConfiguredPublication, TrustedFile};
#[cfg(target_os = "linux")]
use crate::runtime::BootClock;
#[cfg(not(target_os = "linux"))]
use crate::runtime::ProcessClock;
use crate::{
    Availability, ByteStream, Error, Fingerprint, Grant, Label, Lease, Publication, PublicationId, PublishRequest, Scope, Session, Tender,
    api::{
        BindingEntry, Instance, PeerStatus, PublicationEntry, PublicationList, PublishEndpoint, RouteStatus, TrustedInstance, TrustedMember,
    },
    memory::MemoryTender,
    paths,
    runtime::Clock,
    ssh::{Identity, Server},
    until,
};

const ENDPOINT_TIMEOUT: Duration = Duration::from_secs(10);
/// An unavailable own publication's endpoint is first probed again after
/// this, doubling to [`RECOVERY_LONGEST`]: a local socket cannot tell the
/// daemon it answers again.
const RECOVERY_FIRST: Duration = Duration::from_millis(100);
const RECOVERY_LONGEST: Duration = Duration::from_secs(8);
/// Opens a stream tries before the endpoint counts as gone, so a service
/// restarting or briefly slow does not make its publication flap.
const OPEN_ATTEMPTS: u32 = 3;
const OPEN_RETRY: Duration = Duration::from_millis(200);

/// The account's directories. Configuration and state follow `rigging-paths`
/// (`TENDER_ROOT`, then XDG); sockets live in the runtime directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paths {
    pub config: PathBuf,
    pub state: PathBuf,
    pub runtime: PathBuf,
}

impl Paths {
    /// Configuration and state follow `rigging-paths`; the runtime directory
    /// is [`paths::runtime_dir`], which every client uses too.
    pub fn from_env(env: &dyn EnvVars) -> Result<Self, String> {
        let policy = PathPolicy::from_env("tender", env)?;
        let runtime = paths::runtime_dir(env)?;
        Ok(Self { config: policy.config_dir, state: policy.state_dir, runtime })
    }

    pub fn control_socket(&self) -> PathBuf {
        paths::control_socket(&self.runtime)
    }

    pub fn peer_socket(&self) -> PathBuf {
        paths::peer_socket(&self.runtime)
    }

    pub fn config_file(&self) -> PathBuf {
        self.config.join("config.toml")
    }

    /// Configuration, not state: people may edit it while the daemon is
    /// stopped, as they would `authorized_keys`, and the daemon rewrites it
    /// when the group changes through the control API.
    pub fn trusted_file(&self) -> PathBuf {
        self.config.join("trusted.toml")
    }
}

/// Create a directory owned by this user with mode 0700, or check an existing one.
fn private_directory(path: &Path) -> io::Result<()> {
    DirBuilder::new().recursive(true).mode(0o700).create(path)?;
    let metadata = fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no preconditions.
    if !metadata.is_dir() || metadata.uid() != unsafe { geteuid() } {
        return Err(io::Error::other(format!("{} must be a directory owned by this user", path.display())));
    }
    if metadata.mode() & 0o077 != 0 {
        fs::set_permissions(path, Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub struct Daemon {
    inner: Arc<Inner>,
    stop_control: Option<oneshot::Sender<()>>,
    control: JoinHandle<io::Result<()>>,
    maintenance: JoinHandle<()>,
}

pub(crate) struct Inner {
    paths: Paths,
    /// Changes at every start, so a publisher sees that its API
    /// publications were withdrawn and publishes them again.
    epoch: String,
    identity: Identity,
    session: Session,
    server: Server,
    state: Mutex<State>,
    endpoints: Endpoints,
    bindings: Bindings,
    /// Told when a publication is reserved because its endpoint did not
    /// answer, so maintenance starts probing it.
    reserved: watch::Sender<()>,
}

struct State {
    trusted: Vec<TrustedInstance>,
    grants: Vec<ConfiguredGrant>,
    local: BTreeMap<PublicationId, Local>,
}

/// A publication of this instance's own, from a local socket. One reserved
/// while its endpoint did not answer has no pump.
struct Local {
    lease: Lease,
    request: PublishEndpoint,
    pump: Option<JoinHandle<()>>,
}

impl Drop for Local {
    fn drop(&mut self) {
        if let Some(pump) = &self.pump {
            pump.abort();
        }
    }
}

impl Daemon {
    pub async fn start(paths: Paths) -> io::Result<Self> {
        for directory in [&paths.config, &paths.state, &paths.runtime] {
            private_directory(directory)?;
        }
        let config = Config::load(&paths.config_file())?;
        let trusted = TrustedFile::load(&paths.trusted_file())?;
        for member in &trusted.instances {
            member.key.fingerprint().ok_or_else(|| io::Error::other(format!("invalid key in trusted group: {}", member.key.0)))?;
        }
        let server = Server::open(paths.peer_socket(), &paths.state, clock()?)?;
        let identity = server.identity().clone();
        let fingerprint = identity.fingerprint();
        let session = Session { caller: fingerprint.clone(), pinned_host: fingerprint.clone(), via: None };
        let control = UnixServer::bind(paths.control_socket(), 0o600).await?;
        let state = State { trusted: trusted.instances, grants: config.grants, local: BTreeMap::new() };
        apply_trust(&server.policy, &fingerprint, &state).map_err(io::Error::other)?;
        let endpoints = Endpoints::default();
        let own = server.policy.watch(&session).await.map_err(io::Error::other)?;
        let grace = config.binding_grace_seconds.map_or(BINDING_GRACE, Duration::from_secs);
        let bindings = Bindings::start(
            &paths.runtime,
            identity.clone(),
            server.policy.clone(),
            server.links().clone(),
            endpoints.clone(),
            own,
            grace,
        )?;
        bindings.trust(state.trusted.clone());
        let mut epoch = [0; 16];
        OsRng.fill_bytes(&mut epoch);
        // Followed from before the configured publications go out, so
        // maintenance hears of any that went out reserved.
        let leases = server.policy.lease_changes();
        let (reserving, reserved) = watch::channel(());
        let inner = Arc::new(Inner {
            paths,
            epoch: epoch.iter().map(|byte| format!("{byte:02x}")).collect(),
            identity,
            session,
            server,
            state: Mutex::new(state),
            endpoints,
            bindings,
            reserved: reserving,
        });
        let (configured, relative): (Vec<_>, Vec<_>) = config
            .publications
            .into_iter()
            .map(|configured| inner.configured(configured))
            .partition(|request| request.endpoint.is_absolute());
        for request in relative {
            tracing::warn!(id = %request.id, endpoint = %request.endpoint.display(), "configured endpoint is not an absolute path");
        }
        inner.withdraw_unconfigured(&configured.iter().map(|request| request.id.clone()).collect()).await;
        for request in configured {
            if let Err(error) = inner.publish(request.clone()).await {
                tracing::warn!(id = %request.id, %error, "configured publication refused");
            }
        }
        let (stop_control, stopped) = oneshot::channel();
        let router = control::router(inner.clone());
        let control = spawn(control.serve(router, Caller::<()>::Unix, async {
            let _ = stopped.await;
        }));
        let maintenance = spawn(maintain(Arc::downgrade(&inner), leases, reserved));
        Ok(Self { inner, stop_control: Some(stop_control), control, maintenance })
    }

    pub fn instance(&self) -> Instance {
        self.inner.instance()
    }

    /// Stop serving. Publications become unavailable; the next start
    /// publishes the configured ones again and withdraws the rest.
    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop_control.take() {
            let _ = stop.send(());
        }
        let _ = (&mut self.control).await;
        self.maintenance.abort();
        let _ = (&mut self.maintenance).await;
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.maintenance.abort();
        self.control.abort();
    }
}

#[cfg(target_os = "linux")]
fn clock() -> io::Result<Arc<dyn Clock>> {
    Ok(Arc::new(BootClock::new()?))
}

#[cfg(not(target_os = "linux"))]
fn clock() -> io::Result<Arc<dyn Clock>> {
    Ok(Arc::new(ProcessClock::default()))
}

/// Trusted Group members may browse and connect, hold links here and relay
/// callers to this instance, and a request naming no audience reaches them
/// and this instance itself, whose Bindings include its own publications.
/// Configured grants admit their grantees for the same group; grants no
/// longer configured are revoked.
fn apply_trust(policy: &MemoryTender, own: &Fingerprint, state: &State) -> Result<(), Error> {
    let members: BTreeSet<Fingerprint> = state.trusted.iter().filter_map(|member| member.key.fingerprint()).collect();
    policy.set_intermediaries(members.clone())?;
    let mut group = members;
    group.insert(own.clone());
    policy.set_access(group.clone())?;
    policy.set_trusted_group(group.clone())?;
    for stale in policy.grants() {
        if !state.grants.iter().any(|grant| grant.grantee == stale.grantee && grant.scope == stale.scope) {
            policy.revoke(&stale.grantee, &stale.scope)?;
        }
    }
    for grant in &state.grants {
        policy.grant(Grant {
            grantee: grant.grantee.clone(),
            scope: grant.scope.clone(),
            audience_ceiling: group.clone(),
            expires_at: u64::MAX,
        })?;
    }
    Ok(())
}

impl Inner {
    fn apply_trust(&self, state: &State) -> Result<(), Error> {
        apply_trust(self.policy(), self.fingerprint(), state)?;
        let members: BTreeSet<_> = state.trusted.iter().filter_map(|member| member.key.fingerprint()).collect();
        self.server.links().retain(|peer| members.contains(peer));
        self.bindings.trust(state.trusted.clone());
        Ok(())
    }

    pub(crate) fn routes(&self) -> Vec<RouteStatus> {
        self.server.links().routes()
    }

    pub(crate) fn bindings(&self) -> Vec<BindingEntry> {
        self.bindings.bindings()
    }

    pub(crate) fn peers(&self) -> Vec<PeerStatus> {
        self.bindings.peers()
    }

    fn policy(&self) -> &MemoryTender {
        &self.server.policy
    }

    fn fingerprint(&self) -> &Fingerprint {
        &self.session.caller
    }

    pub(crate) fn instance(&self) -> Instance {
        Instance { key: self.identity.public_key(), fingerprint: self.fingerprint().clone(), peer_socket: self.paths.peer_socket() }
    }

    fn configured(&self, configured: ConfiguredPublication) -> PublishEndpoint {
        PublishEndpoint {
            id: PublicationId { scope: configured.scope.map_or_else(|| Scope::instance(self.fingerprint()), Scope), name: configured.name },
            label: Label(configured.label),
            display: configured.display,
            endpoint: configured.endpoint,
            audience: configured.audience,
        }
    }

    /// The endpoint is probed first, outside the state lock, so a slow
    /// endpoint never holds up other control requests. One that does not
    /// answer is reserved, unavailable, until maintenance sees it answer.
    pub(crate) async fn publish(&self, request: PublishEndpoint) -> Result<Publication, Error> {
        let live = reachable(&request.endpoint).await;
        let id = request.id.clone();
        self.publish_locked(&mut *self.state.lock().await, request, live).await?;
        self.policy().publications().into_iter().find(|publication| publication.id == id).ok_or(Error::Unavailable)
    }

    async fn publish_locked(&self, state: &mut State, request: PublishEndpoint, live: bool) -> Result<Lease, Error> {
        let claim = PublishRequest {
            id: request.id.clone(),
            label: request.label.clone(),
            display: request.display.clone(),
            audience: request.audience.clone(),
        };
        let (lease, pump) = if live {
            let published = self.policy().publish(&self.session, claim).await?;
            let lease = published.lease;
            let endpoint = request.endpoint.clone();
            (lease.clone(), Some(spawn(pump(published.incoming, endpoint, self.policy().clone(), self.session.clone(), lease))))
        } else {
            (self.policy().reserve(&self.session, claim)?, None)
        };
        // Only an accepted publication's socket reaches the Binder, so a
        // refused one never redirects the incumbent's Binding.
        self.endpoints.lock().expect("endpoints lock").insert(request.id.clone(), (lease.generation, request.endpoint.clone()));
        self.bindings.endpoints_changed();
        // Replacing an earlier Local drops it, which stops its pump; its
        // streams already open keep running on their own tasks.
        state.local.insert(request.id.clone(), Local { lease: lease.clone(), request, pump });
        if !live {
            self.reserved.send_replace(());
        }
        Ok(lease)
    }

    /// At start: the publications this instance made earlier and no longer
    /// configures are withdrawn, API ones included, which do not persist.
    async fn withdraw_unconfigured(&self, configured: &BTreeSet<PublicationId>) {
        let own = self.policy().publications().into_iter().filter(|publication| {
            &publication.publisher == self.fingerprint()
                && publication.availability != Availability::Withdrawn
                && !configured.contains(&publication.id)
        });
        for publication in own.collect::<Vec<_>>() {
            let lease = Lease { id: publication.id.clone(), generation: publication.generation, publisher: self.fingerprint().clone() };
            if let Err(error) = self.policy().withdraw(&self.session, &lease).await {
                tracing::warn!(id = %publication.id, %error, "withdrawing an earlier publication failed");
            }
        }
    }

    /// Any publication this instance published, from the API or from
    /// configuration, before or since a restart. One another publisher has
    /// taken over is reported as denied, not withdrawn on its behalf.
    pub(crate) async fn withdraw(&self, id: &PublicationId) -> Result<(), Error> {
        let mut state = self.state.lock().await;
        let current = self.policy().publications().into_iter().find(|publication| &publication.id == id);
        let Some(publication) = current else {
            state.local.remove(id);
            return Err(Error::UnknownPublication);
        };
        if &publication.publisher != self.fingerprint() {
            state.local.remove(id);
            return Err(Error::Denied);
        }
        if publication.availability != Availability::Withdrawn {
            let lease = Lease { id: id.clone(), generation: publication.generation, publisher: self.fingerprint().clone() };
            self.policy().withdraw(&self.session, &lease).await?;
        }
        state.local.remove(id);
        Ok(())
    }

    pub(crate) async fn publications(&self) -> PublicationList {
        let state = self.state.lock().await;
        let publications = self
            .policy()
            .publications()
            .into_iter()
            .map(|publication| {
                let endpoint = state
                    .local
                    .get(&publication.id)
                    .filter(|local| local.lease.generation == publication.generation)
                    .map(|local| local.request.endpoint.clone());
                PublicationEntry { publication, endpoint }
            })
            .collect();
        PublicationList { epoch: self.epoch.clone(), publications }
    }

    pub(crate) async fn trusted(&self) -> Vec<TrustedMember> {
        let state = self.state.lock().await;
        state
            .trusted
            .iter()
            .filter_map(|instance| Some(TrustedMember { fingerprint: instance.key.fingerprint()?, instance: instance.clone() }))
            .collect()
    }

    /// Adding a member already present replaces its name and route.
    pub(crate) async fn trust(&self, instance: TrustedInstance) -> Result<TrustedMember, TrustError> {
        let fingerprint = instance.key.fingerprint().ok_or(TrustError::InvalidKey)?;
        if &fingerprint == self.fingerprint() {
            return Err(TrustError::OwnKey);
        }
        let mut state = self.state.lock().await;
        let mut trusted = state.trusted.clone();
        trusted.retain(|member| member.key != instance.key);
        trusted.push(instance.clone());
        self.change_trust(&mut state, trusted)?;
        Ok(TrustedMember { fingerprint, instance })
    }

    pub(crate) async fn untrust(&self, fingerprint: &Fingerprint) -> Result<(), TrustError> {
        let mut state = self.state.lock().await;
        let mut trusted = state.trusted.clone();
        trusted.retain(|member| member.key.fingerprint().as_ref() != Some(fingerprint));
        if trusted.len() == state.trusted.len() {
            return Err(TrustError::NotMember);
        }
        self.change_trust(&mut state, trusted)
    }

    /// Apply, then persist; a failure at either step restores the previous
    /// group in the authority, and the file is only ever written whole.
    fn change_trust(&self, state: &mut State, trusted: Vec<TrustedInstance>) -> Result<(), TrustError> {
        let previous = mem::replace(&mut state.trusted, trusted);
        let applied = self
            .apply_trust(state)
            .map_err(TrustError::Tender)
            .and_then(|()| TrustedFile { instances: state.trusted.clone() }.save(&self.paths.trusted_file()).map_err(TrustError::Storage));
        if applied.is_err() {
            state.trusted = previous;
            if let Err(error) = self.apply_trust(state) {
                tracing::warn!(%error, "restoring the previous Trusted Group failed");
            }
        }
        applied
    }

    pub(crate) async fn trusted_count(&self) -> usize {
        self.state.lock().await.trusted.len()
    }

    /// Republish an own publication once its endpoint answers again, and
    /// forget one that another publisher has taken over or that has gone.
    /// The authority is read under the state lock, so a publish cannot land
    /// between the two; endpoints are probed outside it. True while an own
    /// publication is still waiting for its endpoint.
    async fn maintain(&self) -> bool {
        let mut waiting = false;
        let mut recovering = Vec::new();
        {
            let mut state = self.state.lock().await;
            let records: BTreeMap<_, _> =
                self.policy().publications().into_iter().map(|publication| (publication.id.clone(), publication)).collect();
            state.local.retain(|id, local| {
                let ours = records.get(id).filter(|record| {
                    &record.publisher == self.fingerprint()
                        && record.generation == local.lease.generation
                        && record.availability != Availability::Withdrawn
                });
                if let Some(record) = ours
                    && record.availability == Availability::Unavailable
                {
                    recovering.push((local.lease.clone(), local.request.clone()));
                }
                ours.is_some()
            });
        }
        for (lease, request) in recovering {
            if !reachable(&request.endpoint).await {
                waiting = true;
                continue;
            }
            let mut state = self.state.lock().await;
            if state.local.get(&request.id).is_none_or(|local| local.lease != lease) {
                continue;
            }
            let id = request.id.clone();
            if let Err(error) = self.publish_locked(&mut state, request, true).await {
                tracing::warn!(%id, %error, "republishing a recovered endpoint failed");
                waiting = true;
            }
        }
        waiting
    }
}

#[derive(Debug)]
pub(crate) enum TrustError {
    InvalidKey,
    OwnKey,
    NotMember,
    Storage(io::Error),
    Tender(Error),
}

/// Maintains when the authority's live leases change, which is how an own
/// publication becomes unavailable, is withdrawn or is taken over, and when
/// one is reserved without a live endpoint. While an own publication waits
/// for its endpoint, it probes the endpoint again with backoff.
async fn maintain(maintained: Weak<Inner>, mut leases: watch::Receiver<()>, mut reserved: watch::Receiver<()>) {
    let mut delay = RECOVERY_FIRST;
    let mut probe = None;
    loop {
        select! {
            changed = leases.changed() => if changed.is_err() { break },
            changed = reserved.changed() => if changed.is_err() { break },
            () = until(probe) => {}
        }
        let Some(inner) = maintained.upgrade() else { break };
        if inner.maintain().await {
            probe = Some(Instant::now() + delay);
            delay = (delay * 2).min(RECOVERY_LONGEST);
        } else {
            probe = None;
            delay = RECOVERY_FIRST;
        }
    }
}

async fn reachable(endpoint: &Path) -> bool {
    matches!(timeout(ENDPOINT_TIMEOUT, UnixStream::connect(endpoint)).await, Ok(Ok(_)))
}

/// Carry each accepted stream to the local endpoint. A failed open marks the
/// publication unavailable; maintenance publishes it again once it answers.
async fn pump(mut incoming: mpsc::UnboundedReceiver<ByteStream>, endpoint: PathBuf, policy: MemoryTender, session: Session, lease: Lease) {
    while let Some(mut stream) = incoming.recv().await {
        let endpoint = endpoint.clone();
        let policy = policy.clone();
        let session = session.clone();
        let lease = lease.clone();
        spawn(async move {
            match open(&endpoint).await {
                Some(mut service) => {
                    let _ = copy_bidirectional(&mut stream, &mut service).await;
                }
                None => {
                    let _ = policy.disconnect(&session, &lease).await;
                }
            }
        });
    }
}

async fn open(endpoint: &Path) -> Option<UnixStream> {
    for attempt in 0..OPEN_ATTEMPTS {
        if attempt > 0 {
            sleep(OPEN_RETRY * attempt).await;
        }
        if let Ok(Ok(service)) = timeout(ENDPOINT_TIMEOUT, UnixStream::connect(endpoint)).await {
            return Some(service);
        }
    }
    None
}

pub async fn serve(paths: Paths) -> io::Result<()> {
    let daemon = Daemon::start(paths).await?;
    let instance = daemon.instance();
    tracing::info!(fingerprint = %instance.fingerprint.0, peer = %instance.peer_socket.display(), "tender serving");
    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = ctrl_c() => {}
        _ = terminate.recv() => {}
    }
    daemon.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::Builder;
    use tokio::net::UnixListener;

    use super::*;
    use crate::Label;

    // A publish that lands while maintenance waits for the state lock survives
    // it: maintenance compares against the authority as of holding the lock.
    #[tokio::test]
    async fn maintenance_keeps_a_concurrent_publish() {
        let root = Builder::new().prefix("td-").permissions(Permissions::from_mode(0o700)).tempdir().expect("root");
        let paths = Paths { config: root.path().join("config"), state: root.path().join("state"), runtime: root.path().join("runtime") };
        let daemon = Daemon::start(paths).await.expect("start");
        let endpoint = root.path().join("service");
        let _listener = UnixListener::bind(&endpoint).expect("service");
        let id = PublicationId::new("vessel/scope", "service");
        let request = PublishEndpoint { id: id.clone(), label: Label("echo".into()), display: String::new(), endpoint, audience: None };
        let inner = daemon.inner.clone();
        let mut state = inner.state.lock().await;
        let maintaining = spawn({
            let inner = inner.clone();
            async move { inner.maintain().await }
        });
        sleep(Duration::from_millis(50)).await;
        inner.publish_locked(&mut state, request, true).await.expect("publish");
        drop(state);
        maintaining.await.expect("maintain");
        assert!(inner.state.lock().await.local.contains_key(&id), "maintenance dropped a publish it raced");
        daemon.shutdown().await;
    }

    // A publication reserved because its endpoint did not answer goes live
    // once the endpoint answers, with nothing else happening, within the
    // longest probe backoff.
    #[tokio::test(start_paused = true)]
    async fn reserved_publication_goes_live_once_its_endpoint_answers() {
        let root = Builder::new().prefix("td-").permissions(Permissions::from_mode(0o700)).tempdir().expect("root");
        let paths = Paths { config: root.path().join("config"), state: root.path().join("state"), runtime: root.path().join("runtime") };
        let daemon = Daemon::start(paths).await.expect("start");
        let endpoint = root.path().join("service");
        let id = PublicationId::new("vessel/scope", "service");
        let request = PublishEndpoint {
            id: id.clone(),
            label: Label("echo".into()),
            display: String::new(),
            endpoint: endpoint.clone(),
            audience: None,
        };
        let reserved = daemon.inner.publish(request).await.expect("reserve");
        assert_eq!(reserved.availability, Availability::Unavailable);
        let mut watch = daemon.inner.policy().watch(&daemon.inner.session).await.expect("watch");

        // Probes that find nothing back off to the longest delay.
        sleep(RECOVERY_LONGEST * 4).await;
        let _listener = UnixListener::bind(&endpoint).expect("service");
        let answered = Instant::now();
        let live = |snapshot: &[Publication]| {
            snapshot.iter().any(|publication| publication.id == id && publication.availability == Availability::Available)
        };
        timeout(RECOVERY_LONGEST * 2, async { while !live(&watch.recv().await.expect("watch open")) {} })
            .await
            .expect("published again once the endpoint answers");
        assert!(answered.elapsed() <= RECOVERY_LONGEST, "probed within the longest backoff, after {:?}", answered.elapsed());
        daemon.shutdown().await;
    }
}
