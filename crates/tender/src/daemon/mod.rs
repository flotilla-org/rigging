//! The `tender serve` daemon: one per OS account, publishing that account's
//! local endpoints behind a control API on its Local Endpoint.

mod bindings;
mod config;
mod control;

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use rigging_http_serve::{Caller, UnixServer};
use rigging_paths::PathPolicy;
use rigging_process::EnvVars;
use tokio::{
    net::UnixStream,
    signal::unix::{SignalKind, signal},
    sync::{Mutex, mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};

use self::bindings::{Bindings, Endpoints};
pub use self::config::{Config, ConfiguredGrant, ConfiguredPublication, TrustedFile};
use crate::{
    Availability, ByteStream, Error, Fingerprint, Grant, Label, Lease, Publication, PublicationId, PublishRequest, Session, Tender,
    api::{BindingEntry, Instance, PeerStatus, PublicationEntry, PublishEndpoint, TrustedInstance, TrustedMember},
    memory::MemoryTender,
    paths,
    runtime::Clock,
    ssh::{Identity, Server},
};

const ENDPOINT_TIMEOUT: Duration = Duration::from_secs(10);
const MAINTENANCE: Duration = Duration::from_secs(1);

/// The account's directories. Configuration and state follow `rigging-paths`
/// (`TENDER_ROOT`, then XDG); sockets live in the runtime directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paths {
    pub config: PathBuf,
    pub state: PathBuf,
    pub runtime: PathBuf,
}

impl Paths {
    /// The runtime directory follows [`paths::runtime_dir`], which clients share.
    pub fn from_env(env: &dyn EnvVars) -> Result<Self, String> {
        let runtime = paths::runtime_dir(|key| env.get_os(key))?;
        let policy = PathPolicy::from_env("tender", env)?;
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
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no preconditions.
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(io::Error::other(format!("{} must be a directory owned by this user", path.display())));
    }
    if metadata.mode() & 0o077 != 0 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
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
    identity: Identity,
    session: Session,
    server: Server,
    state: Mutex<State>,
    endpoints: Endpoints,
    bindings: Bindings,
}

struct State {
    trusted: Vec<TrustedInstance>,
    grants: Vec<ConfiguredGrant>,
    local: BTreeMap<PublicationId, Local>,
}

/// A publication of this instance's own, from a local socket.
struct Local {
    lease: Lease,
    request: PublishEndpoint,
    pump: JoinHandle<()>,
}

impl Drop for Local {
    fn drop(&mut self) {
        self.pump.abort();
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
        let bindings = Bindings::start(&paths.runtime, identity.clone(), server.policy.clone(), endpoints.clone(), own)?;
        bindings.trust(state.trusted.clone());
        let inner = Arc::new(Inner { paths, identity, session, server, state: Mutex::new(state), endpoints, bindings });
        for configured in config.publications {
            let request = inner.configured(configured);
            if let Err(error) = inner.publish(request.clone()).await {
                tracing::warn!(id = %request.id, %error, "configured publication refused");
            }
        }
        let (stop_control, stopped) = oneshot::channel();
        let router = control::router(inner.clone());
        let control = tokio::spawn(control.serve(router, Caller::<()>::Unix, async {
            let _ = stopped.await;
        }));
        let maintained = Arc::downgrade(&inner);
        let maintenance = tokio::spawn(async move {
            let mut tick = tokio::time::interval(MAINTENANCE);
            loop {
                tick.tick().await;
                let Some(inner) = maintained.upgrade() else { break };
                inner.maintain().await;
            }
        });
        Ok(Self { inner, stop_control: Some(stop_control), control, maintenance })
    }

    pub fn instance(&self) -> Instance {
        self.inner.instance()
    }

    /// Stop serving. Publications become unavailable, keeping their identities
    /// for the next start; nothing is withdrawn.
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
    Ok(Arc::new(crate::runtime::BootClock::new()?))
}

#[cfg(not(target_os = "linux"))]
fn clock() -> io::Result<Arc<dyn Clock>> {
    Ok(Arc::new(crate::runtime::ProcessClock::default()))
}

/// Trusted Group members may browse and connect, and a request naming no
/// audience reaches them and this instance itself, whose Bindings include its
/// own publications. Configured grants admit their grantees for the same
/// group; grants no longer configured are revoked.
fn apply_trust(policy: &MemoryTender, own: &Fingerprint, state: &State) -> Result<(), Error> {
    let mut group: BTreeSet<Fingerprint> = state.trusted.iter().filter_map(|member| member.key.fingerprint()).collect();
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
        self.bindings.trust(state.trusted.clone());
        Ok(())
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
            id: PublicationId::new(configured.scope.unwrap_or_else(|| format!("tender/{}", self.fingerprint().0)), configured.name),
            label: Label(configured.label),
            display: configured.display,
            endpoint: configured.endpoint,
            audience: configured.audience,
        }
    }

    /// The endpoint is probed outside the state lock, so a slow endpoint
    /// never holds up other control requests.
    pub(crate) async fn publish(&self, request: PublishEndpoint) -> Result<Publication, Error> {
        let (id, endpoint, lease) = {
            let mut state = self.state.lock().await;
            let lease = self.publish_locked(&mut state, request.clone()).await?;
            (request.id, request.endpoint, lease)
        };
        if !reachable(&endpoint).await {
            self.disconnect_if_current(&id, &lease).await;
        }
        self.policy().publications().into_iter().find(|publication| publication.id == id).ok_or(Error::Unavailable)
    }

    async fn publish_locked(&self, state: &mut State, request: PublishEndpoint) -> Result<Lease, Error> {
        // Known before the authority announces the publication, so its own
        // Binding links straight to the socket.
        self.endpoints.lock().expect("endpoints lock").insert(request.id.clone(), request.endpoint.clone());
        let published = self
            .policy()
            .publish(
                &self.session,
                PublishRequest {
                    id: request.id.clone(),
                    label: request.label.clone(),
                    display: request.display.clone(),
                    audience: request.audience.clone(),
                },
            )
            .await?;
        let lease = published.lease;
        let pump =
            tokio::spawn(pump(published.incoming, request.endpoint.clone(), self.policy().clone(), self.session.clone(), lease.clone()));
        // Replacing an earlier Local drops it, which stops its pump; its
        // streams already open keep running on their own tasks.
        state.local.insert(request.id.clone(), Local { lease: lease.clone(), request, pump });
        Ok(lease)
    }

    async fn disconnect_if_current(&self, id: &PublicationId, lease: &Lease) {
        let state = self.state.lock().await;
        if state.local.get(id).is_some_and(|local| &local.lease == lease) {
            // A failure leaves a stale or withdrawn lease, which maintenance forgets.
            if let Err(error) = self.policy().disconnect(&self.session, lease).await {
                tracing::debug!(%id, %error, "disconnecting an unreachable endpoint failed");
            }
        }
    }

    /// The daemon forgets a publication once the authority has withdrawn it,
    /// or once it turns out no longer to be this instance's. Another
    /// publisher's takeover is reported, not withdrawn on its behalf.
    pub(crate) async fn withdraw(&self, id: &PublicationId) -> Result<(), Error> {
        let mut state = self.state.lock().await;
        let lease = state.local.get(id).ok_or(Error::UnknownPublication)?.lease.clone();
        match self.policy().withdraw(&self.session, &lease).await {
            Ok(()) | Err(Error::Withdrawn) => {
                state.local.remove(id);
                Ok(())
            }
            Err(error @ (Error::Denied | Error::StaleGeneration)) => {
                state.local.remove(id);
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) async fn publications(&self) -> Vec<PublicationEntry> {
        let state = self.state.lock().await;
        self.policy()
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
            .collect()
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
        let previous = std::mem::replace(&mut state.trusted, trusted);
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
    /// between the two; endpoints are probed outside it.
    async fn maintain(&self) {
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
                continue;
            }
            let mut state = self.state.lock().await;
            if state.local.get(&request.id).is_none_or(|local| local.lease != lease) {
                continue;
            }
            let id = request.id.clone();
            if let Err(error) = self.publish_locked(&mut state, request).await {
                tracing::warn!(%id, %error, "republishing a recovered endpoint failed");
            }
        }
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
        tokio::spawn(async move {
            match timeout(ENDPOINT_TIMEOUT, UnixStream::connect(&endpoint)).await {
                Ok(Ok(mut service)) => {
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut service).await;
                }
                _ => {
                    let _ = policy.disconnect(&session, &lease).await;
                }
            }
        });
    }
}

/// Run until SIGINT or SIGTERM.
pub async fn serve(paths: Paths) -> io::Result<()> {
    let daemon = Daemon::start(paths).await?;
    let instance = daemon.instance();
    tracing::info!(fingerprint = %instance.fingerprint.0, peer = %instance.peer_socket.display(), "tender serving");
    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
    daemon.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::net::UnixListener;

    use super::*;
    use crate::Label;

    // A publish that lands while maintenance waits for the state lock survives
    // it: maintenance compares against the authority as of holding the lock.
    #[tokio::test]
    async fn maintenance_keeps_a_concurrent_publish() {
        let root = tempfile::Builder::new().prefix("td-").permissions(std::fs::Permissions::from_mode(0o700)).tempdir().expect("root");
        let paths = Paths { config: root.path().join("config"), state: root.path().join("state"), runtime: root.path().join("runtime") };
        let daemon = Daemon::start(paths).await.expect("start");
        let endpoint = root.path().join("service");
        let _listener = UnixListener::bind(&endpoint).expect("service");
        let id = PublicationId::new("scope", "service");
        let request = PublishEndpoint { id: id.clone(), label: Label("echo".into()), display: String::new(), endpoint, audience: None };
        let inner = daemon.inner.clone();
        let mut state = inner.state.lock().await;
        let maintaining = tokio::spawn({
            let inner = inner.clone();
            async move { inner.maintain().await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        inner.publish_locked(&mut state, request).await.expect("publish");
        drop(state);
        maintaining.await.expect("maintain");
        assert!(inner.state.lock().await.local.contains_key(&id), "maintenance dropped a publish it raced");
        daemon.shutdown().await;
    }
}
