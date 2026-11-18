//! In-memory host and byte transport. Policy mutation models host authority;
//! none of these controls is available to a publisher through [`Tender`].

use std::{
    collections::{BTreeMap, BTreeSet},
    io as std_io,
    sync::{Arc, Mutex, MutexGuard},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::{io, sync::mpsc, task::JoinHandle};

use crate::{
    Availability, Binding, BindingState, ByteStream, Error, Fingerprint, Grant, Label, Lease, Publication, PublicationId, PublishRequest,
    Published, Route, Scope, Session, Tender, UnavailableReason, Watch,
    runtime::{Clock, ClockReading, Store},
};

/// How long, in clock ticks (milliseconds), the authority keeps a withdrawn
/// publication before forgetting it: long enough for followers to see the
/// withdrawal, and for a vessel moving host to publish it again.
pub const WITHDRAWN_RETENTION: u64 = 60_000;

#[derive(Clone)]
pub struct MemoryTender {
    inner: Arc<Mutex<State>>,
}

struct Record {
    publication: Publication,
    requested_audience: Option<BTreeSet<Fingerprint>>,
    expires_at: u64,
    withdrawn_at: Option<u64>,
    sender: Option<mpsc::UnboundedSender<ByteStream>>,
    streams: Vec<OpenStream>,
}

struct OpenStream {
    caller: Fingerprint,
    task: JoinHandle<()>,
}

/// A stream that outlived its generation: expiry let it run to close, and a
/// republish left it on the route it opened on.
struct Lingering {
    id: PublicationId,
    publisher: Fingerprint,
    stream: OpenStream,
}

struct State {
    host: Fingerprint,
    now: u64,
    grants: BTreeMap<(Fingerprint, Scope), Grant>,
    browse: BTreeSet<Fingerprint>,
    connect: BTreeSet<Fingerprint>,
    intermediaries: BTreeSet<Fingerprint>,
    trusted_group: BTreeSet<Fingerprint>,
    records: BTreeMap<PublicationId, Record>,
    /// The highest generation issued. Every publication takes the next, so a
    /// forgotten identity published again never matches an earlier lease.
    generation: u64,
    lingering: Vec<Lingering>,
    /// Callers that have bound each identity, so losing admission reads as
    /// Revoked rather than as an identity that never existed.
    bound: BTreeSet<(Fingerprint, PublicationId)>,
    runtime: Option<Hosting>,
    failed: bool,
    watchers: Vec<(Fingerprint, mpsc::UnboundedSender<Vec<Publication>>)>,
}

impl MemoryTender {
    /// Ephemeral authority with explicit manual ticks. Deployed hosts should use
    /// [`Self::hosted`] so inactivity cannot prevent grant expiry.
    pub fn new(host: Fingerprint) -> Self {
        Self {
            inner: Arc::new(Mutex::new(State {
                host,
                now: 0,
                grants: BTreeMap::new(),
                browse: BTreeSet::new(),
                connect: BTreeSet::new(),
                intermediaries: BTreeSet::new(),
                trusted_group: BTreeSet::new(),
                records: BTreeMap::new(),
                generation: 0,
                lingering: Vec::new(),
                bound: BTreeSet::new(),
                runtime: None,
                failed: false,
                watchers: Vec::new(),
            })),
        }
    }

    /// Restore durable authority, never routes. Clock epoch changes or regression
    /// expire prior grants rather than extending their lifetime. Saves fail closed.
    pub fn hosted(host: Fingerprint, clock: Arc<dyn Clock>, store: Arc<dyn Store>) -> std_io::Result<Self> {
        let authority = Self::new(host.clone());
        let reading = clock.read()?;
        {
            let mut state = authority.inner.lock().expect("state lock");
            if let Some(bytes) = store.load()? {
                let stored = Stored::decode(&bytes)?;
                if stored.host != host {
                    return Err(std_io::Error::other("Tender store belongs to a different host identity"));
                }
                let invalid_clock = stored.clock.epoch != reading.epoch || reading.tick < stored.clock.tick;
                state.grants = stored
                    .grants
                    .into_iter()
                    .map(|mut grant| {
                        if invalid_clock {
                            grant.expires_at = 0;
                        }
                        ((grant.grantee.clone(), grant.scope.clone()), grant)
                    })
                    .collect();
                state.browse = stored.browse;
                state.connect = stored.connect;
                state.intermediaries = stored.intermediaries;
                state.trusted_group = stored.trusted_group;
                state.generation = stored.generation;
                state.records = stored
                    .records
                    .into_iter()
                    .map(|mut record| {
                        if invalid_clock {
                            record.expires_at = 0;
                        }
                        if record.publication.availability == Availability::Available {
                            record.publication.availability = Availability::Unavailable;
                        }
                        // A withdrawal from another clock epoch is long past.
                        let withdrawn_at = (record.publication.availability == Availability::Withdrawn)
                            .then(|| if invalid_clock { 0 } else { record.withdrawn_at.unwrap_or(reading.tick) });
                        (
                            record.publication.id.clone(),
                            Record {
                                publication: record.publication,
                                requested_audience: record.requested_audience,
                                expires_at: record.expires_at,
                                withdrawn_at,
                                sender: None,
                                streams: Vec::new(),
                            },
                        )
                    })
                    .collect();
            }
            state.now = reading.tick;
            state.runtime = Some(Hosting { clock, store, epoch: reading.epoch });
            state.expire();
            state.persist().map_err(std_io::Error::other)?;
        }
        Ok(authority)
    }

    fn state(&self) -> Result<MutexGuard<'_, State>, Error> {
        let mut state = self.inner.lock().expect("state lock");
        if state.failed {
            return Err(Error::Storage);
        }
        if let Some(runtime) = &state.runtime {
            let reading = match runtime.clock.read() {
                Ok(reading) => reading,
                Err(error) => {
                    tracing::warn!(%error, "Tender hosting clock failed; refusing work");
                    state.fail();
                    state.send_snapshots();
                    return Err(Error::Storage);
                }
            };
            let invalid = reading.epoch != runtime.epoch || reading.tick < state.now;
            if invalid {
                for grant in state.grants.values_mut() {
                    grant.expires_at = 0;
                }
                for record in state.records.values_mut() {
                    record.expires_at = 0;
                }
            }
            if invalid || reading.tick != state.now {
                state.now = state.now.max(reading.tick);
                state.expire();
                state.notify()?;
            } else {
                state.expire();
            }
        }
        Ok(state)
    }

    /// Admission to be forwarded through this instance: the authenticated
    /// caller needs connect authority, as for any stream it opens here.
    #[cfg(unix)]
    pub(crate) fn check_forward(&self, session: &Session) -> Result<(), Error> {
        let state = self.state()?;
        state.authenticate(session)?;
        if !state.connect.contains(&session.caller) {
            return Err(Error::Denied);
        }
        Ok(())
    }

    /// Admission for an instance that delivers a relayed caller here. Only a
    /// directly authenticated, trusted intermediary may stand in the path.
    #[cfg(unix)]
    pub(crate) fn check_intermediary(&self, session: &Session) -> Result<(), Error> {
        let state = self.state()?;
        state.authenticate(session)?;
        if session.via.is_some() || !state.intermediaries.contains(&session.caller) {
            return Err(Error::UntrustedIntermediary);
        }
        Ok(())
    }

    #[cfg(unix)]
    pub(crate) fn lease_active(&self, lease: &Lease) -> bool {
        self.state().ok().is_some_and(|state| {
            state.records.get(&lease.id).is_some_and(|record| {
                record.publication.publisher == lease.publisher
                    && record.publication.generation == lease.generation
                    && record.publication.availability == Availability::Available
            })
        })
    }

    pub fn host(&self) -> Fingerprint {
        self.inner.lock().expect("state lock").host.clone()
    }

    pub fn grant(&self, grant: Grant) -> Result<(), Error> {
        let mut state = self.state()?;
        state.grants.insert((grant.grantee.clone(), grant.scope.clone()), grant);
        state.reaudience();
        state.notify()
    }

    /// The instances acting for this host's person. A publication that names
    /// no audience gets this group, and the host's own publications cannot
    /// reach beyond it.
    pub fn set_trusted_group(&self, group: BTreeSet<Fingerprint>) -> Result<(), Error> {
        let mut state = self.state()?;
        state.trusted_group = group;
        state.reaudience();
        state.notify()
    }

    pub fn trusted_group(&self) -> BTreeSet<Fingerprint> {
        self.inner.lock().expect("state lock").trusted_group.clone()
    }

    pub fn allow_browse(&self, caller: Fingerprint) -> Result<(), Error> {
        let mut state = self.state()?;
        state.browse.insert(caller);
        state.notify()
    }
    pub fn allow_connect(&self, caller: Fingerprint) -> Result<(), Error> {
        let mut state = self.state()?;
        state.connect.insert(caller);
        state.notify()
    }
    pub fn trust_intermediary(&self, relay: Fingerprint) -> Result<(), Error> {
        let mut state = self.state()?;
        state.intermediaries.insert(relay);
        state.notify()
    }

    /// Revocation stops new connections and forcibly closes established streams.
    pub fn revoke(&self, grantee: &Fingerprint, scope: &Scope) -> Result<(), Error> {
        let mut state = self.state()?;
        state.grants.remove(&(grantee.clone(), scope.clone()));
        state.close_lingering(|lingering| &lingering.publisher == grantee && &lingering.id.scope == scope);
        let now = state.now;
        for record in state.records.values_mut() {
            if &record.publication.publisher == grantee && &record.publication.id.scope == scope {
                retire(record, true, now);
            }
        }
        state.notify()
    }

    /// Expiry retires the identity, but established streams run to close.
    pub fn advance_to(&self, now: u64) -> Result<(), Error> {
        let mut state = self.state()?;
        state.now = state.now.max(now);
        state.expire();
        state.notify()
    }

    /// Persist metadata, never routes or live publisher claims.
    pub fn restart(&self) -> Result<(), Error> {
        let mut state = self.state()?;
        state.close_lingering(|_| true);
        for record in state.records.values_mut() {
            abort_streams(record);
            if record.publication.availability == Availability::Available {
                record.publication.availability = Availability::Unavailable;
                record.sender = None;
            }
        }
        state.notify()
    }
}

fn endpoint(host: &Fingerprint, caller: &Fingerprint, id: &PublicationId) -> String {
    format!("memory:{}/{}/{id}", host.0, caller.0)
}

fn abort_streams(record: &mut Record) {
    for stream in record.streams.drain(..) {
        stream.task.abort();
    }
}

fn close_streams_of(record: &mut Record, closes: impl Fn(&OpenStream) -> bool) {
    for stream in &record.streams {
        if closes(stream) {
            stream.task.abort();
        }
    }
    record.streams.retain(|stream| !stream.task.is_finished());
}

fn retire(record: &mut Record, abort: bool, now: u64) {
    if abort {
        abort_streams(record);
    }
    if record.publication.availability != Availability::Withdrawn {
        record.publication.availability = Availability::Withdrawn;
        record.withdrawn_at = Some(now);
        record.sender = None;
    }
}

struct Hosting {
    clock: Arc<dyn Clock>,
    store: Arc<dyn Store>,
    epoch: String,
}

// Version 2 keys publications by scope and name. Future generations must
// decode both this and version 1, as `tests/fixtures/authority-v1.json` and
// `authority-v2.json` pin; wire records remain independent of storage versioning.
#[derive(Serialize, Deserialize)]
struct Stored {
    version: u32,
    host: Fingerprint,
    clock: ClockReading,
    grants: Vec<Grant>,
    browse: BTreeSet<Fingerprint>,
    connect: BTreeSet<Fingerprint>,
    intermediaries: BTreeSet<Fingerprint>,
    trusted_group: BTreeSet<Fingerprint>,
    records: Vec<StoredRecord>,
    /// At least every record's generation once decoded.
    #[serde(default)]
    generation: u64,
}
#[derive(Serialize, Deserialize)]
struct StoredRecord {
    publication: Publication,
    requested_audience: Option<BTreeSet<Fingerprint>>,
    expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    withdrawn_at: Option<u64>,
}

/// Version 1 assigned numeric identities and allowed several to share a
/// scope and name. Each name keeps its latest record, at the highest
/// generation any of them reached, so no generation is ever reissued.
/// Replacement assignments are dropped: a grant for the scope now admits a
/// takeover.
#[derive(Deserialize)]
struct StoredV1 {
    host: Fingerprint,
    clock: ClockReading,
    next_id: u64,
    grants: Vec<Grant>,
    browse: BTreeSet<Fingerprint>,
    connect: BTreeSet<Fingerprint>,
    intermediaries: BTreeSet<Fingerprint>,
    records: Vec<StoredRecordV1>,
}
#[derive(Deserialize)]
struct StoredRecordV1 {
    publication: PublicationV1,
    requested_audience: BTreeSet<Fingerprint>,
    expires_at: u64,
}
#[derive(Deserialize)]
struct PublicationV1 {
    id: u64,
    namespace: Scope,
    name: String,
    publisher: Fingerprint,
    audience: BTreeSet<Fingerprint>,
    generation: u64,
    availability: Availability,
}

impl Stored {
    fn decode(bytes: &[u8]) -> std_io::Result<Self> {
        #[derive(Deserialize)]
        struct Version {
            version: u32,
        }
        let invalid = |message: &str| std_io::Error::other(message.to_owned());
        let mut stored = match serde_json::from_slice::<Version>(bytes).map_err(std_io::Error::other)?.version {
            1 => Self::from_v1(serde_json::from_slice(bytes).map_err(std_io::Error::other)?)?,
            2 => serde_json::from_slice::<Self>(bytes).map_err(std_io::Error::other)?,
            _ => return Err(invalid("unsupported Tender store version")),
        };
        if stored.records.iter().any(|record| record.publication.generation == 0)
            || stored.records.iter().map(|record| &record.publication.id).collect::<BTreeSet<_>>().len() != stored.records.len()
        {
            return Err(invalid("invalid Tender publication identities"));
        }
        let highest = stored.records.iter().map(|record| record.publication.generation).max().unwrap_or(0);
        stored.generation = stored.generation.max(highest);
        Ok(stored)
    }

    fn from_v1(stored: StoredV1) -> std_io::Result<Self> {
        if stored.next_id == 0
            || stored
                .records
                .iter()
                .any(|record| record.publication.id == 0 || record.publication.id >= stored.next_id || record.publication.generation == 0)
            || stored.records.iter().map(|record| record.publication.id).collect::<BTreeSet<_>>().len() != stored.records.len()
        {
            return Err(std_io::Error::other("invalid Tender identity counters"));
        }
        let mut records = stored.records;
        records.sort_by_key(|record| record.publication.id);
        let mut by_identity: BTreeMap<PublicationId, StoredRecord> = BTreeMap::new();
        for record in records {
            let old = record.publication;
            let id = PublicationId { scope: old.namespace, name: old.name };
            let generation = by_identity.get(&id).map_or(old.generation, |prior| prior.publication.generation.max(old.generation));
            let publication = Publication {
                id: id.clone(),
                label: Label::default(),
                display: String::new(),
                publisher: old.publisher,
                audience: old.audience,
                generation,
                availability: old.availability,
            };
            by_identity.insert(
                id,
                StoredRecord {
                    publication,
                    requested_audience: Some(record.requested_audience),
                    expires_at: record.expires_at,
                    withdrawn_at: None,
                },
            );
        }
        Ok(Self {
            version: 2,
            host: stored.host,
            clock: stored.clock,
            grants: stored.grants,
            browse: stored.browse,
            connect: stored.connect,
            intermediaries: stored.intermediaries,
            trusted_group: BTreeSet::new(),
            records: by_identity.into_values().collect(),
            generation: 0,
        })
    }
}

impl State {
    fn fail(&mut self) {
        self.failed = true;
        self.close_lingering(|_| true);
        for record in self.records.values_mut() {
            retire(record, true, self.now);
        }
    }

    fn close_lingering(&mut self, closes: impl Fn(&Lingering) -> bool) {
        for lingering in &self.lingering {
            if closes(lingering) {
                lingering.stream.task.abort();
            }
        }
        self.lingering.retain(|lingering| !lingering.stream.task.is_finished());
    }

    /// Retire expired publications, and forget those withdrawn for longer
    /// than [`WITHDRAWN_RETENTION`]. Their streams run on to close.
    fn expire(&mut self) {
        let now = self.now;
        for record in self.records.values_mut() {
            if record.expires_at <= now {
                retire(record, false, now);
            }
        }
        let forgotten: Vec<_> = self
            .records
            .iter()
            .filter(|(_, record)| {
                record.withdrawn_at.and_then(|withdrawn| withdrawn.checked_add(WITHDRAWN_RETENTION)).is_some_and(|until| until <= now)
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in forgotten {
            let record = self.records.remove(&id).expect("record collected above");
            let publisher = record.publication.publisher;
            let carried = record.streams.into_iter().map(|stream| Lingering { id: id.clone(), publisher: publisher.clone(), stream });
            self.lingering.extend(carried);
        }
        self.lingering.retain(|lingering| !lingering.stream.task.is_finished());
    }

    fn persist(&mut self) -> Result<(), Error> {
        let Some(runtime) = &self.runtime else {
            return Ok(());
        };
        let stored = Stored {
            version: 2,
            host: self.host.clone(),
            clock: ClockReading { epoch: runtime.epoch.clone(), tick: self.now },
            grants: self.grants.values().cloned().collect(),
            browse: self.browse.clone(),
            connect: self.connect.clone(),
            intermediaries: self.intermediaries.clone(),
            trusted_group: self.trusted_group.clone(),
            records: self
                .records
                .values()
                .map(|record| StoredRecord {
                    publication: {
                        let mut publication = record.publication.clone();
                        if publication.availability == Availability::Available {
                            publication.availability = Availability::Unavailable;
                        }
                        publication
                    },
                    requested_audience: record.requested_audience.clone(),
                    expires_at: record.expires_at,
                    withdrawn_at: record.withdrawn_at,
                })
                .collect(),
            generation: self.generation,
        };
        let result = serde_json::to_vec(&stored).map_err(std_io::Error::other).and_then(|bytes| runtime.store.save(&bytes));
        if let Err(error) = result {
            tracing::warn!(%error, "Tender policy save failed; refusing work");
            self.fail();
            return Err(Error::Storage);
        }
        Ok(())
    }

    /// The host publishes under its own instance scope and vessel scopes,
    /// within its Trusted Group and without expiry; any other scope needs a
    /// grant. Only the instance it names publishes under an instance scope.
    fn ceiling(&self, publisher: &Fingerprint, scope: &Scope) -> Option<(BTreeSet<Fingerprint>, u64)> {
        if scope.owner().is_some_and(|owner| &owner != publisher) {
            return None;
        }
        if publisher == &self.host && (scope.owner().is_some() || scope.is_vessel()) {
            return Some((self.trusted_group.clone(), u64::MAX));
        }
        self.grants.get(&(publisher.clone(), scope.clone())).map(|grant| (grant.audience_ceiling.clone(), grant.expires_at))
    }

    fn audience(&self, requested: &Option<BTreeSet<Fingerprint>>, ceiling: &BTreeSet<Fingerprint>) -> BTreeSet<Fingerprint> {
        requested.as_ref().unwrap_or(&self.trusted_group).intersection(ceiling).cloned().collect()
    }

    /// Recompute every live record from its publisher's current ceiling, closing
    /// streams whose callers fall outside the narrowed audience.
    fn reaudience(&mut self) {
        let now = self.now;
        let updates: Vec<_> = self
            .records
            .iter()
            .filter(|(_, record)| record.publication.availability != Availability::Withdrawn)
            .filter_map(|(id, record)| {
                let (ceiling, expires_at) = self.ceiling(&record.publication.publisher, &id.scope)?;
                Some((id.clone(), self.audience(&record.requested_audience, &ceiling), expires_at))
            })
            .collect();
        for (id, audience, expires_at) in updates {
            let record = self.records.get_mut(&id).expect("record collected above");
            record.expires_at = expires_at;
            record.publication.audience = audience;
            let audience = record.publication.audience.clone();
            close_streams_of(record, |stream| !audience.contains(&stream.caller));
            if expires_at <= now {
                retire(record, false, now);
            }
        }
        let ceilings: Vec<_> = self.lingering.iter().map(|lingering| self.ceiling(&lingering.publisher, &lingering.id.scope)).collect();
        for (lingering, ceiling) in self.lingering.iter().zip(ceilings) {
            if !ceiling.is_some_and(|(ceiling, _)| ceiling.contains(&lingering.stream.caller)) {
                lingering.stream.task.abort();
            }
        }
        self.lingering.retain(|lingering| !lingering.stream.task.is_finished());
    }

    fn authenticate(&self, session: &Session) -> Result<(), Error> {
        if session.pinned_host != self.host {
            return Err(Error::IdentityMismatch);
        }
        if session.via.as_ref().is_some_and(|relay| !self.intermediaries.contains(relay)) {
            return Err(Error::UntrustedIntermediary);
        }
        Ok(())
    }

    fn visible(&self, caller: &Fingerprint) -> Vec<Publication> {
        self.records
            .values()
            .filter(|record| record.publication.audience.contains(caller))
            .map(|record| record.publication.clone())
            .collect()
    }

    fn notify(&mut self) -> Result<(), Error> {
        let saved = self.persist();
        self.send_snapshots();
        saved
    }

    fn send_snapshots(&mut self) {
        let snapshots: Vec<_> = self.watchers.iter().map(|(caller, _)| self.visible(caller)).collect();
        self.watchers = self
            .watchers
            .drain(..)
            .zip(snapshots)
            .filter_map(|((caller, sender), snapshot)| sender.send(snapshot).ok().map(|()| (caller, sender)))
            .collect();
    }

    fn record_for_connect(&mut self, session: &Session, id: &PublicationId) -> Result<&mut Record, Error> {
        self.authenticate(session)?;
        if !self.connect.contains(&session.caller) {
            return Err(Error::Denied);
        }
        let record = self.records.get_mut(id).ok_or(Error::Denied)?;
        if !record.publication.audience.contains(&session.caller) {
            return Err(Error::Denied);
        }
        match record.publication.availability {
            Availability::Available => Ok(record),
            Availability::Unavailable => Err(Error::Unavailable),
            Availability::Withdrawn => Err(Error::Withdrawn),
        }
    }

    fn check_lease(&self, session: &Session, lease: &Lease) -> Result<(), Error> {
        self.authenticate(session)?;
        if session.caller != lease.publisher {
            return Err(Error::Denied);
        }
        let record = self.records.get(&lease.id).ok_or(Error::Denied)?;
        if record.publication.publisher != session.caller {
            return Err(Error::Denied);
        }
        if record.publication.generation != lease.generation {
            return Err(Error::StaleGeneration);
        }
        if record.publication.availability == Availability::Withdrawn {
            return Err(Error::Withdrawn);
        }
        Ok(())
    }
}

#[async_trait]
impl Tender for MemoryTender {
    async fn publish(&self, session: &Session, request: PublishRequest) -> Result<Published, Error> {
        let mut state = self.state()?;
        state.authenticate(session)?;
        let (ceiling, expires_at) = state.ceiling(&session.caller, &request.id.scope).ok_or(Error::Denied)?;
        if expires_at <= state.now {
            return Err(Error::GrantExpired);
        }
        let audience = state.audience(&request.audience, &ceiling);
        if state.records.get(&request.id).is_some_and(|record| record.publication.availability == Availability::Available) {
            return Err(Error::LivePublisher);
        }
        let generation = state.generation.checked_add(1).ok_or(Error::Storage)?;
        state.generation = generation;
        let (sender, incoming) = mpsc::unbounded_channel();
        let closure_sender = sender.clone();
        let publication = Publication {
            id: request.id.clone(),
            label: request.label,
            display: request.display,
            publisher: session.caller.clone(),
            audience,
            generation,
            availability: Availability::Available,
        };
        // Nothing carries into the new generation. Streams the previous one
        // still has (expiry lets them run to close) stay on their old route.
        if let Some(previous) = state.records.insert(
            request.id.clone(),
            Record {
                publication,
                requested_audience: request.audience,
                expires_at,
                withdrawn_at: None,
                sender: Some(sender),
                streams: Vec::new(),
            },
        ) {
            let publisher = previous.publication.publisher;
            let carried =
                previous.streams.into_iter().map(|stream| Lingering { id: request.id.clone(), publisher: publisher.clone(), stream });
            state.lingering.extend(carried);
            state.lingering.retain(|lingering| !lingering.stream.task.is_finished());
        }
        let lease = Lease { id: request.id, generation, publisher: session.caller.clone() };
        state.notify()?;
        drop(state);
        let inner = self.inner.clone();
        let watched_lease = lease.clone();
        tokio::spawn(async move {
            closure_sender.closed().await;
            let mut state = inner.lock().expect("state lock");
            if let Some(record) = state.records.get_mut(&watched_lease.id)
                && record.publication.generation == watched_lease.generation
                && record.publication.availability == Availability::Available
            {
                record.publication.availability = Availability::Unavailable;
                record.sender = None;
                abort_streams(record);
                // No caller awaits this receiver-closure notification.
                // notify logs/latches save failure, aborts streams and updates
                // watchers, so ignoring the return cannot keep serving work.
                let _ = state.notify();
            }
        });
        Ok(Published { lease, incoming })
    }

    async fn browse(&self, session: &Session) -> Result<Vec<Publication>, Error> {
        let state = self.state()?;
        state.authenticate(session)?;
        if !state.browse.contains(&session.caller) {
            return Err(Error::Denied);
        }
        Ok(state.visible(&session.caller))
    }

    async fn watch(&self, session: &Session) -> Result<Watch, Error> {
        let mut state = self.state()?;
        state.authenticate(session)?;
        if !state.browse.contains(&session.caller) {
            return Err(Error::Denied);
        }
        let (sender, receiver) = mpsc::unbounded_channel();
        sender.send(state.visible(&session.caller)).expect("new watch receiver");
        state.watchers.push((session.caller.clone(), sender));
        Ok(receiver)
    }

    async fn connect(&self, session: &Session, id: &PublicationId) -> Result<ByteStream, Error> {
        let mut state = self.state()?;
        let record = state.record_for_connect(session, id)?;
        let sender = record.sender.as_ref().ok_or(Error::Unavailable)?;
        // Two bounded channels and a cancellable relay model per-stream flow
        // control without embedding a control frame in either raw pipe.
        let (client, mut relay_client) = io::duplex(64);
        let (service, mut relay_service) = io::duplex(64);
        sender.send(Box::new(service)).map_err(|_| Error::Unavailable)?;
        record.streams.retain(|stream| !stream.task.is_finished());
        let task = tokio::spawn(async move {
            let _ = io::copy_bidirectional(&mut relay_client, &mut relay_service).await;
        });
        record.streams.push(OpenStream { caller: session.caller.clone(), task });
        Ok(Box::new(client))
    }

    async fn bind(&self, session: &Session, id: &PublicationId) -> Result<Binding, Error> {
        let mut state = self.state()?;
        let state = &mut *state;
        state.authenticate(session)?;
        let key = (session.caller.clone(), id.clone());
        let admitted = state.connect.contains(&session.caller)
            && state.records.get(id).is_some_and(|record| record.publication.audience.contains(&session.caller));
        let route = Route { instance: state.host.clone(), via: session.via.clone() };
        if !admitted {
            return if state.bound.contains(&key) {
                Ok(Binding {
                    publication: id.clone(),
                    local_endpoint: endpoint(&state.host, &session.caller, id),
                    state: BindingState::Revoked,
                })
            } else {
                Err(Error::Denied)
            };
        }
        state.bound.insert(key);
        let binding_state = match state.records[id].publication.availability {
            Availability::Available => BindingState::Available { route },
            Availability::Unavailable => BindingState::Unavailable { reason: UnavailableReason::PublisherUnavailable, route: Some(route) },
            Availability::Withdrawn => BindingState::Unavailable { reason: UnavailableReason::Withdrawn, route: Some(route) },
        };
        Ok(Binding { publication: id.clone(), local_endpoint: endpoint(&state.host, &session.caller, id), state: binding_state })
    }

    async fn open_binding(&self, session: &Session, binding: &Binding) -> Result<ByteStream, Error> {
        self.connect(session, &binding.publication).await
    }

    async fn disconnect(&self, session: &Session, lease: &Lease) -> Result<(), Error> {
        let mut state = self.state()?;
        state.check_lease(session, lease)?;
        let record = state.records.get_mut(&lease.id).expect("validated lease");
        record.publication.availability = Availability::Unavailable;
        record.sender = None;
        abort_streams(record);
        state.notify()?;
        Ok(())
    }

    async fn withdraw(&self, session: &Session, lease: &Lease) -> Result<(), Error> {
        let mut state = self.state()?;
        state.check_lease(session, lease)?;
        let now = state.now;
        retire(state.records.get_mut(&lease.id).expect("validated lease"), true, now);
        state.notify()?;
        Ok(())
    }
}
