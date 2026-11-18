use std::{
    collections::BTreeSet,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
#[cfg(unix)]
use std::{
    fs::{self, Permissions},
    os::unix::{fs::PermissionsExt, net::UnixListener},
};

use hegel::TestCase;
use serde_json::{Value, from_slice, to_vec};
#[cfg(unix)]
use tempfile::{Builder, TempDir};
use tender::{
    Availability, Error, Fingerprint, Grant, Label, PublicationId, PublishRequest, Scope, Session, Tender,
    memory::MemoryTender,
    runtime::{Clock, ClockReading, MemoryStore, Store},
};
#[cfg(unix)]
use tender::{
    runtime::FileStore,
    ssh::{Identity, Server, SshTender},
};
#[cfg(unix)]
use tokio::task::yield_now;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    runtime,
    time::timeout,
};

struct ManualClock(Mutex<ClockReading>, AtomicBool);
impl ManualClock {
    fn new() -> Self {
        Self(Mutex::new(ClockReading { epoch: "boot-one".into(), tick: 0 }), AtomicBool::new(false))
    }
    fn set(&self, tick: u64) {
        self.0.lock().unwrap().tick = tick;
    }
}
impl Clock for ManualClock {
    fn read(&self) -> io::Result<ClockReading> {
        if self.1.load(Ordering::SeqCst) {
            return Err(io::Error::other("clock unavailable"));
        }
        Ok(self.0.lock().unwrap().clone())
    }
}

struct Rig {
    authority: MemoryTender,
    client: Box<dyn Tender>,
    clock: Arc<ManualClock>,
    store: Arc<dyn Store>,
    session: Session,
    socket: bool,
    #[cfg(unix)]
    server: Option<Server>,
    #[cfg(unix)]
    directory: TempDir,
}
impl Rig {
    fn new(socket: bool, file: bool) -> Self {
        #[cfg(unix)]
        let directory = { Builder::new().permissions(Permissions::from_mode(0o700)).tempdir().unwrap() };
        #[cfg(unix)]
        let identity = Identity::from_secret([1; 32]);
        #[cfg(unix)]
        let caller = Identity::from_secret([2; 32]);
        #[cfg(unix)]
        let session = Session { caller: caller.fingerprint(), pinned_host: identity.fingerprint(), via: None };
        #[cfg(not(unix))]
        let session = Session { caller: Fingerprint("caller".into()), pinned_host: Fingerprint("host".into()), via: None };
        let clock = Arc::new(ManualClock::new());
        #[cfg(unix)]
        let store: Arc<dyn Store> = if file {
            Arc::new(FileStore::new(directory.path().join("authority.json")).unwrap())
        } else {
            Arc::new(MemoryStore::default())
        };
        #[cfg(not(unix))]
        let store: Arc<dyn Store> = {
            let _ = file;
            Arc::new(MemoryStore::default())
        };
        let authority = MemoryTender::hosted(session.pinned_host.clone(), clock.clone(), store.clone()).unwrap();
        let mut rig = Self {
            client: Box::new(authority.clone()),
            authority,
            clock,
            store,
            session,
            socket,
            #[cfg(unix)]
            server: None,
            #[cfg(unix)]
            directory,
        };
        rig.attach();
        rig
    }
    fn attach(&mut self) {
        self.client = Box::new(self.authority.clone());
        #[cfg(unix)]
        if self.socket {
            let path = self.directory.path().join("listener");
            self.server = Some(Server::bind(path.clone(), Identity::from_secret([1; 32]), self.authority.clone()).unwrap());
            self.client = Box::new(SshTender::new(path, self.session.pinned_host.clone(), vec![Identity::from_secret([2; 32])]).unwrap());
        }
    }
    fn reload(&mut self) {
        self.authority.restart().unwrap();
        #[cfg(unix)]
        {
            self.server.take();
        }
        self.authority = MemoryTender::hosted(self.session.pinned_host.clone(), self.clock.clone(), self.store.clone()).unwrap();
        self.attach();
    }
    fn authorize(&self, expiry: u64) {
        self.authority.allow_browse(self.session.caller.clone()).unwrap();
        self.authority.allow_connect(self.session.caller.clone()).unwrap();
        self.authority
            .grant(Grant {
                grantee: self.session.caller.clone(),
                scope: Scope("n".into()),
                audience_ceiling: BTreeSet::from([self.session.caller.clone()]),
                expires_at: expiry,
            })
            .unwrap();
    }
    fn request(&self, name: &str) -> PublishRequest {
        PublishRequest {
            id: PublicationId::new("n", name),
            label: Label("echo".into()),
            display: name.into(),
            audience: Some(BTreeSet::from([self.session.caller.clone()])),
        }
    }
}

// Every new admission checks the clock at the exact expiry boundary, even
// with no publisher activity. Expiry grandfathers streams; later revocation severs them.
async fn expiry(mut rig: Rig) {
    rig.authorize(10);
    let mut published = rig.client.publish(&rig.session, rig.request("service")).await.unwrap();
    let mut held = rig.client.connect(&rig.session, &published.lease.id).await.unwrap();
    let mut service = timeout(Duration::from_secs(2), published.incoming.recv()).await.unwrap().unwrap();
    rig.clock.set(9);
    assert!(rig.client.connect(&rig.session, &published.lease.id).await.is_ok());
    rig.clock.set(10);
    assert!(matches!(rig.client.connect(&rig.session, &published.lease.id).await, Err(Error::Withdrawn)));
    assert!(matches!(rig.client.publish(&rig.session, rig.request("service")).await, Err(Error::GrantExpired)));
    held.write_all(b"after expiry").await.unwrap();
    let mut bytes = [0; 12];
    timeout(Duration::from_secs(2), service.read_exact(&mut bytes)).await.unwrap().unwrap();
    assert_eq!(&bytes, b"after expiry");
    rig.authority.revoke(&rig.session.caller, &Scope("n".into())).unwrap();
    let mut byte = [0];
    let closed = timeout(Duration::from_secs(2), held.read(&mut byte)).await.unwrap();
    assert!(matches!(closed, Ok(0)) || closed.is_err());
    rig.reload();
    assert_eq!(rig.client.browse(&rig.session).await.unwrap()[0].availability, Availability::Withdrawn);
    assert!(matches!(rig.client.publish(&rig.session, rig.request("service")).await, Err(Error::Denied)));
}

// Restart restores authority, grants, retired and reserved identities and
// their generations, but never a live route. Publishing an identity again
// changes its generation, not the identity, and no generation is reissued.
async fn restart(mut rig: Rig) {
    rig.authorize(10);
    let first = rig.client.publish(&rig.session, rig.request("service")).await.unwrap();
    let mut held = rig.client.connect(&rig.session, &first.lease.id).await.unwrap();
    let withdrawn = rig.client.publish(&rig.session, rig.request("retired")).await.unwrap();
    rig.client.withdraw(&rig.session, &withdrawn.lease).await.unwrap();
    rig.clock.set(9);
    rig.reload();
    let mut byte = [0];
    let closed = timeout(Duration::from_secs(2), held.read(&mut byte)).await.unwrap();
    assert!(matches!(closed, Ok(0)) || closed.is_err());
    let snapshot = rig.client.browse(&rig.session).await.unwrap();
    let state = |id: &PublicationId| snapshot.iter().find(|publication| &publication.id == id).unwrap().availability;
    assert_eq!(state(&first.lease.id), Availability::Unavailable);
    assert_eq!(state(&withdrawn.lease.id), Availability::Withdrawn);
    assert!(matches!(rig.client.connect(&rig.session, &first.lease.id).await, Err(Error::Unavailable)));
    let republished = rig.client.publish(&rig.session, rig.request("service")).await.unwrap();
    assert_eq!(republished.lease.id, first.lease.id);
    assert!(republished.lease.generation > withdrawn.lease.generation.max(first.lease.generation));
    let retaken = rig.client.publish(&rig.session, rig.request("retired")).await.unwrap();
    assert!(retaken.lease.generation > republished.lease.generation);
    rig.clock.set(10);
    rig.reload();
    assert!(rig.client.browse(&rig.session).await.unwrap().iter().all(|record| record.availability == Availability::Withdrawn));
    assert!(matches!(rig.client.publish(&rig.session, rig.request("service")).await, Err(Error::GrantExpired)));
}

macro_rules! contract {
    ($name:ident, $scenario:ident, $socket:expr, $file:expr) => {
        #[tokio::test]
        async fn $name() {
            $scenario(Rig::new($socket, $file)).await;
        }
    };
}
contract!(memory_expiry, expiry, false, false);
contract!(memory_restart, restart, false, false);
#[cfg(unix)]
contract!(socket_expiry, expiry, true, false);
#[cfg(unix)]
contract!(socket_restart, restart, true, false);
#[cfg(unix)]
contract!(file_expiry, expiry, false, true);
#[cfg(unix)]
contract!(file_restart, restart, false, true);
#[cfg(unix)]
contract!(socket_file_expiry, expiry, true, true);
#[cfg(unix)]
contract!(socket_file_restart, restart, true, true);

// Generated sequences cross expiry (0..=12), duplicate ticks, clock regression,
// and restart interleavings. A withdrawn publication can never regain reachability.
#[hegel::test]
fn expiry_never_resurrects(tc: TestCase) {
    use hegel::generators as gs;
    let count = tc.draw(gs::integers::<usize>().min_value(1).max_value(12));
    let steps: Vec<_> = (0..count).map(|_| (tc.draw(gs::integers::<u64>().min_value(0).max_value(12)), tc.draw(gs::booleans()))).collect();
    runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let mut rig = Rig::new(false, false);
        rig.authorize(10);
        let published = rig.client.publish(&rig.session, rig.request("service")).await.unwrap();
        let mut prior = 0;
        let mut retired = false;
        for (tick, reload) in steps {
            retired |= tick >= 10 || tick < prior;
            rig.clock.set(tick);
            if reload {
                rig.reload();
            }
            let state = rig.client.browse(&rig.session).await.unwrap()[0].availability;
            assert_eq!(state == Availability::Withdrawn, retired);
            if retired {
                assert!(matches!(rig.client.connect(&rig.session, &published.lease.id).await, Err(Error::Withdrawn)));
            }
            prior = if reload { tick } else { prior.max(tick) };
        }
    });
}

struct FailingStore;
impl Store for FailingStore {
    fn load(&self) -> io::Result<Option<Vec<u8>>> {
        Ok(None)
    }
    fn save(&self, _: &[u8]) -> io::Result<()> {
        Err(io::Error::other("disk unavailable"))
    }
}
// Missing/corrupt/failed storage never bootstraps a replacement authority.
#[test]
fn failed_initial_save_refuses_hosting() {
    assert!(MemoryTender::hosted(Fingerprint("host".into()), Arc::new(ManualClock::new()), Arc::new(FailingStore)).is_err());
}

// Keep both fixtures unchanged when adding fields. Version 1's numeric
// identities become scope and name; its replacement assignments give way to
// grants. Policy, relay trust and generations must reload from either.
#[tokio::test]
async fn stored_v1_and_v2_remain_decodable() {
    for fixture in [include_bytes!("fixtures/authority-v1.json").as_slice(), include_bytes!("fixtures/authority-v2.json")] {
        let store = Arc::new(MemoryStore::default());
        store.save(fixture).unwrap();
        let clock = Arc::new(ManualClock::new());
        clock.set(9);
        let host = Fingerprint("host".into());
        let authority = MemoryTender::hosted(host.clone(), clock.clone(), store.clone()).unwrap();
        let consumer =
            Session { caller: Fingerprint("consumer".into()), pinned_host: host.clone(), via: Some(Fingerprint("relay".into())) };
        let service = PublicationId::new("n", "service");
        let visible = authority.browse(&consumer).await.unwrap();
        assert_eq!(visible.iter().find(|publication| publication.id == service).unwrap().generation, 7);
        let publisher = Session { caller: Fingerprint("replacement".into()), pinned_host: host, via: None };
        authority
            .grant(Grant {
                grantee: publisher.caller.clone(),
                scope: Scope("n".into()),
                audience_ceiling: BTreeSet::from([consumer.caller.clone()]),
                expires_at: 10,
            })
            .unwrap();
        let request = PublishRequest {
            id: service.clone(),
            label: Label("echo".into()),
            display: "taken over".into(),
            audience: Some(BTreeSet::from([consumer.caller.clone()])),
        };
        let published = authority.publish(&publisher, request).await.unwrap();
        assert_eq!(published.lease.generation, 8);
        assert!(authority.connect(&consumer, &published.lease.id).await.is_ok());
        assert!(MemoryTender::hosted(Fingerprint("different".into()), clock, store).is_err());
    }
}

// Version 1 let several numeric identities share a scope and name. Each name
// loads as its latest record, at the highest generation any of them reached.
#[tokio::test]
async fn v1_records_sharing_a_name_collapse_without_reissuing_a_generation() {
    let mut value: Value = from_slice(include_bytes!("fixtures/authority-v1.json")).unwrap();
    value["next_id"] = 4.into();
    let mut later = value["records"][0].clone();
    later["publication"]["id"] = 3.into();
    later["publication"]["generation"] = 2.into();
    later["publication"]["publisher"] = "later".into();
    value["records"].as_array_mut().unwrap().push(later);
    let store = Arc::new(MemoryStore::default());
    store.save(&to_vec(&value).unwrap()).unwrap();
    let clock = Arc::new(ManualClock::new());
    let host = Fingerprint("host".into());
    let authority = MemoryTender::hosted(host.clone(), clock, store).unwrap();
    let consumer = Session { caller: Fingerprint("consumer".into()), pinned_host: host, via: Some(Fingerprint("relay".into())) };
    let visible = authority.browse(&consumer).await.unwrap();
    assert_eq!(visible.len(), 2);
    let service = visible.iter().find(|publication| publication.id == PublicationId::new("n", "service")).unwrap();
    assert_eq!((service.publisher.0.as_str(), service.generation), ("later", 7));
}

// Epoch replacement and rollback both expire grants on reload, including tick
// zero; no wall clock or restarted process can silently extend a deadline.
#[tokio::test]
async fn changed_epoch_and_backward_clock_expire_on_reload() {
    for changed_epoch in [false, true] {
        let mut rig = Rig::new(false, false);
        rig.authorize(100);
        let published = rig.client.publish(&rig.session, rig.request("service")).await.unwrap();
        rig.clock.set(50);
        rig.authority.browse(&rig.session).await.unwrap();
        if changed_epoch {
            rig.clock.0.lock().unwrap().epoch = "boot-two".into();
        } else {
            rig.clock.set(0);
        }
        rig.reload();
        assert_eq!(rig.client.browse(&rig.session).await.unwrap()[0].availability, Availability::Withdrawn);
        assert!(matches!(rig.client.connect(&rig.session, &published.lease.id).await, Err(Error::Withdrawn)));
        assert!(matches!(rig.client.publish(&rig.session, rig.request("service")).await, Err(Error::GrantExpired)));
    }
}

// A failed save prevents acknowledgment and all later admission, and aborts
// already-open streams. Failure injection stands in for the filesystem seam.
struct SwitchStore {
    inner: MemoryStore,
    fail: AtomicBool,
}
impl Store for SwitchStore {
    fn load(&self) -> io::Result<Option<Vec<u8>>> {
        self.inner.load()
    }
    fn save(&self, bytes: &[u8]) -> io::Result<()> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(io::Error::other("disk full"));
        }
        self.inner.save(bytes)
    }
}
#[tokio::test]
async fn storage_failure_closes_streams_and_refuses_new_work() {
    let store = Arc::new(SwitchStore { inner: MemoryStore::default(), fail: AtomicBool::new(false) });
    let mut rig = Rig::new(false, false);
    rig.authority = MemoryTender::hosted(rig.session.pinned_host.clone(), rig.clock.clone(), store.clone()).unwrap();
    rig.attach();
    rig.authorize(10);
    let mut published = rig.client.publish(&rig.session, rig.request("service")).await.unwrap();
    let mut stream = rig.client.connect(&rig.session, &published.lease.id).await.unwrap();
    let _service = published.incoming.recv().await.unwrap();
    store.fail.store(true, Ordering::SeqCst);
    assert_eq!(rig.authority.allow_connect(Fingerprint("other".into())), Err(Error::Storage));
    assert!(matches!(rig.client.publish(&rig.session, rig.request("service")).await, Err(Error::Storage)));
    assert!(matches!(rig.client.connect(&rig.session, &published.lease.id).await, Err(Error::Storage)));
    let mut byte = [0];
    assert_eq!(timeout(Duration::from_secs(2), stream.read(&mut byte)).await.unwrap().unwrap(), 0);
}

// Opening a deployed host reloads the same independent key and policy. The file
// lock refuses competing host processes and malformed stores never get replaced.
#[cfg(unix)]
#[tokio::test]
async fn durable_server_open_preserves_identity_and_refuses_competing_store() {
    let directory = Builder::new().permissions(Permissions::from_mode(0o700)).tempdir().unwrap();
    let path = directory.path().join("listener");
    let clock = Arc::new(ManualClock::new());
    let server = Server::open(path.clone(), directory.path(), clock.clone()).unwrap();
    let host = server.policy.host();
    let caller = Fingerprint("reader".into());
    server.policy.allow_browse(caller.clone()).unwrap();
    assert!(FileStore::new(directory.path().join("authority.json")).is_err());
    drop(server);
    // The aborted listener task may retain its authority until cancellation is polled.
    yield_now().await;
    // A crashed process leaves a socket inode. Its locked hosting runtime may
    // recover that dead socket, while refusing ordinary files and live sockets.
    let stale = UnixListener::bind(&path).unwrap();
    drop(stale);
    let restored = Server::open(path.clone(), directory.path(), clock.clone()).unwrap();
    assert_eq!(restored.policy.host(), host);
    assert!(restored.policy.browse(&Session { caller, pinned_host: host, via: None }).await.is_ok());
    drop(restored);
    yield_now().await;
    fs::write(directory.path().join("authority.json"), b"broken").unwrap();
    assert!(Server::open(path, directory.path(), clock).is_err());
    assert_eq!(fs::read(directory.path().join("authority.json")).unwrap(), b"broken");
}

// A reserved identity admits exactly one concurrent republish. Both adapters
// serialize admission and durable generation updates through the same authority.
async fn concurrent_reclaim(mut rig: Rig) {
    rig.authorize(100);
    let published = rig.client.publish(&rig.session, rig.request("service")).await.unwrap();
    rig.reload();
    let request = rig.request("service");
    let (one, two) = tokio::join!(rig.client.publish(&rig.session, request.clone()), rig.client.publish(&rig.session, request));
    let winner = match (one, two) {
        (Ok(winner), Err(Error::LivePublisher)) | (Err(Error::LivePublisher), Ok(winner)) => winner,
        _ => panic!("exactly one reclaim must succeed"),
    };
    assert_eq!(winner.lease.generation, published.lease.generation + 1);
    rig.reload();
    assert_eq!(rig.client.browse(&rig.session).await.unwrap()[0].generation, winner.lease.generation);
}
contract!(memory_concurrent_reclaim, concurrent_reclaim, false, false);
#[cfg(unix)]
contract!(socket_concurrent_reclaim, concurrent_reclaim, true, false);
#[cfg(unix)]
contract!(file_concurrent_reclaim, concurrent_reclaim, false, true);
#[cfg(unix)]
contract!(socket_file_concurrent_reclaim, concurrent_reclaim, true, true);

// Clock ticks cover zero and the u64 maximum. Renewal before expiry preserves
// the publication, but no issuance or renewal resurrects a retired identity.
#[tokio::test]
async fn zero_maximum_and_renewal_boundaries() {
    let rig = Rig::new(false, false);
    rig.authorize(0);
    assert!(matches!(rig.client.publish(&rig.session, rig.request("service")).await, Err(Error::GrantExpired)));
    rig.authorize(10);
    let published = rig.client.publish(&rig.session, rig.request("service")).await.unwrap();
    rig.clock.set(9);
    rig.authorize(u64::MAX);
    rig.clock.set(10);
    assert!(rig.client.connect(&rig.session, &published.lease.id).await.is_ok());
    rig.clock.set(u64::MAX);
    assert!(matches!(rig.client.connect(&rig.session, &published.lease.id).await, Err(Error::Withdrawn)));
    assert!(matches!(rig.client.publish(&rig.session, rig.request("service")).await, Err(Error::GrantExpired)));
}

// Invalid versions, counters, generations and duplicate identities cannot
// silently reuse a prior publication identity. Failed reloads leave the
// previous document untouched.
#[test]
fn corrupt_identities_and_versions_are_refused() {
    let v1: Value = from_slice(include_bytes!("fixtures/authority-v1.json")).unwrap();
    let v2: Value = from_slice(include_bytes!("fixtures/authority-v2.json")).unwrap();
    for variant in 0..6 {
        let mut value = if variant < 4 { v1.clone() } else { v2.clone() };
        match variant {
            0 => value["version"] = 3.into(),
            1 => value["next_id"] = 1.into(),
            2 => value["records"][0]["publication"]["generation"] = 0.into(),
            3 => value["records"][1]["publication"]["id"] = 1.into(),
            4 => value["records"][1]["publication"]["generation"] = 0.into(),
            _ => value["records"][1]["publication"]["id"] = value["records"][0]["publication"]["id"].clone(),
        }
        let bytes = to_vec(&value).unwrap();
        let store = Arc::new(MemoryStore::default());
        store.save(&bytes).unwrap();
        assert!(
            MemoryTender::hosted(Fingerprint("host".into()), Arc::new(ManualClock::new()), store.clone()).is_err(),
            "variant {variant}"
        );
        assert_eq!(store.load().unwrap().unwrap(), bytes);
    }
}

// A failed injected clock cannot poison the authority lock or leave streams
// alive. Restoring the clock alone does not clear the fail-closed latch.
async fn clock_failure(rig: Rig) {
    rig.authorize(100);
    let mut published = rig.client.publish(&rig.session, rig.request("service")).await.unwrap();
    let mut stream = rig.client.connect(&rig.session, &published.lease.id).await.unwrap();
    let _service = timeout(Duration::from_secs(2), published.incoming.recv()).await.unwrap().unwrap();
    rig.clock.1.store(true, Ordering::SeqCst);
    assert!(matches!(rig.client.publish(&rig.session, rig.request("service")).await, Err(Error::Storage)));
    assert!(matches!(rig.client.connect(&rig.session, &published.lease.id).await, Err(Error::Storage)));
    let mut byte = [0];
    let closed = timeout(Duration::from_secs(2), stream.read(&mut byte)).await.unwrap();
    assert!(matches!(closed, Ok(0)) || closed.is_err());
    rig.clock.1.store(false, Ordering::SeqCst);
    assert_eq!(rig.authority.allow_browse(rig.session.caller.clone()), Err(Error::Storage));
    assert_eq!(rig.client.browse(&rig.session).await, Err(Error::Storage));
}
contract!(memory_clock_failure, clock_failure, false, false);
#[cfg(unix)]
contract!(socket_clock_failure, clock_failure, true, false);
#[cfg(unix)]
contract!(file_clock_failure, clock_failure, false, true);
#[cfg(unix)]
contract!(socket_file_clock_failure, clock_failure, true, true);
