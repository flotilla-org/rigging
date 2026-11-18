//! The `tender serve` daemon: one per OS account, publishing that account's
//! local endpoints behind a control API on its Local Endpoint.

mod config;
mod control;

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
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

pub use self::config::{Config, ConfiguredGrant, ConfiguredPublication, TrustedFile};
use crate::{
    Availability, ByteStream, Error, Fingerprint, Grant, Label, Lease, Publication, PublicationId, PublishRequest, Session, Tender,
    api::{Instance, PublicationEntry, PublishEndpoint, TrustedInstance, TrustedMember},
    memory::MemoryTender,
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
    /// The runtime directory is `$TENDER_ROOT/runtime`, else
    /// `$XDG_RUNTIME_DIR/tender`, else `tender-<uid>` in the temporary directory.
    pub fn from_env(env: &dyn EnvVars) -> Result<Self, String> {
        let nonempty = |value: OsString| (!value.is_empty()).then_some(value);
        let root = env.get_os("TENDER_ROOT").and_then(nonempty).map(PathBuf::from);
        // A relative root would put sockets wherever the daemon was started.
        if root.as_ref().is_some_and(|root| !root.is_absolute()) {
            return Err("TENDER_ROOT must be an absolute path".into());
        }
        let policy = PathPolicy::from_env("tender", env)?;
        let runtime = if let Some(root) = root {
            root.join("runtime")
        } else if let Some(base) = env.get_os("XDG_RUNTIME_DIR").map(PathBuf::from).filter(|path| path.is_absolute()) {
            base.join("tender")
        } else {
            // SAFETY: geteuid has no preconditions.
            std::env::temp_dir().join(format!("tender-{}", unsafe { libc::geteuid() }))
        };
        Ok(Self { config: policy.config_dir, state: policy.state_dir, runtime })
    }

    pub fn control_socket(&self) -> PathBuf {
        self.runtime.join("control")
    }

    pub fn peer_socket(&self) -> PathBuf {
        self.runtime.join("peer")
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
        let session = Session { caller: fingerprint.clone(), pinned_host: fingerprint, via: None };
        let control = UnixServer::bind(paths.control_socket(), 0o600).await?;
        let inner = Arc::new(Inner {
            paths,
            identity,
            session,
            server,
            state: Mutex::new(State { trusted: trusted.instances, grants: config.grants, local: BTreeMap::new() }),
        });
        inner.apply_trust(&*inner.state.lock().await).map_err(io::Error::other)?;
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

impl Inner {
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

    /// Trusted Group members may browse and connect, and a request naming no
    /// audience reaches them. Configured grants admit their grantees for the
    /// same group; grants no longer configured are revoked.
    fn apply_trust(&self, state: &State) -> Result<(), Error> {
        let group: BTreeSet<Fingerprint> = state.trusted.iter().filter_map(|member| member.key.fingerprint()).collect();
        let policy = self.policy();
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
            let _ = self.policy().disconnect(&self.session, lease).await;
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
    /// Endpoints are probed outside the state lock.
    async fn maintain(&self) {
        let records: BTreeMap<_, _> =
            self.policy().publications().into_iter().map(|publication| (publication.id.clone(), publication)).collect();
        let mut recovering = Vec::new();
        {
            let mut state = self.state.lock().await;
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
