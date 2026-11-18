// async_trait's generated futures trigger Clippy 1.99's redundant must-use lint.
// Remove when async_trait or Clippy stops producing this warning.
#![allow(clippy::double_must_use)]

//! Publication and raw-stream contracts for ordinary local services.
//!
//! A transport adapter authenticates the caller and the pinned host before
//! constructing a [`Session`]. Serde derives support adapter control records;
//! the hosting runtime has its own versioned policy document, independent of
//! application resource schemas. Each connection gets a separate
//! ordered byte stream. Control and diagnostics never enter that stream.

use std::{collections::BTreeSet, fmt, io, time::Duration};

use async_trait::async_trait;
pub use rigging_stream::{ByteStream, RawStream};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

pub mod api;
#[cfg(unix)]
pub mod daemon;
pub mod memory;
pub mod runtime;
#[cfg(unix)]
pub mod ssh;

/// Fingerprint of a persisted instance key, independent of its current route.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Fingerprint(pub String);

/// An instance's Ed25519 public key in lowercase hex. A Trusted Group is a
/// list of these, much like `authorized_keys`.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PublicKey(pub String);

impl PublicKey {
    pub fn from_bytes(key: &[u8; 32]) -> Self {
        Self(key.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    /// `None` unless the key is 32 bytes of hex.
    pub fn fingerprint(&self) -> Option<Fingerprint> {
        use sha2::{Digest, Sha256};
        let bytes = self.0.as_bytes();
        if bytes.len() != 64 {
            return None;
        }
        let key: Vec<u8> = bytes
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).ok().and_then(|pair| u8::from_str_radix(pair, 16).ok()))
            .collect::<Option<_>>()?;
        Some(Fingerprint(Sha256::digest(key).iter().map(|byte| format!("{byte:02x}")).collect()))
    }
}

/// A vessel, or the publishing instance for a host endpoint. Who may publish
/// under a scope is a [`Grant`].
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Scope(pub String);

/// A publication's identity. The name is chosen by whoever asks and is opaque
/// to Tender; the publisher and its route are not part of the identity, so a
/// publisher that moves keeps its publications (flotilla#3995).
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PublicationId {
    pub scope: Scope,
    pub name: String,
}

impl PublicationId {
    pub fn new(scope: impl Into<String>, name: impl Into<String>) -> Self {
        Self { scope: Scope(scope.into()), name: name.into() }
    }
}

impl fmt::Display for PublicationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.scope.0, self.name)
    }
}

/// The protocol a publication claims to speak (`cleat`, `agent-view`, `http`,
/// …). Tender never checks it; the application's own handshake does.
#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Label(pub String);

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum Availability {
    Available,
    Unavailable,
    Withdrawn,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct Publication {
    pub id: PublicationId,
    pub label: Label,
    pub display: String,
    pub publisher: Fingerprint,
    pub audience: BTreeSet<Fingerprint>,
    pub generation: u64,
    pub availability: Availability,
}

/// The host enforces this grant, including its audience ceiling and expiry.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Grant {
    pub grantee: Fingerprint,
    #[serde(alias = "namespace")]
    pub scope: Scope,
    pub audience_ceiling: BTreeSet<Fingerprint>,
    /// Hosting clock milliseconds; the grant is invalid at this tick.
    pub expires_at: u64,
}

/// A session represents a completed, transport-independent identity handshake.
/// The pinned host is checked on every operation. A relay is a separately
/// pinned instance trusted with plaintext, never the asserted caller identity.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Session {
    pub caller: Fingerprint,
    pub pinned_host: Fingerprint,
    pub via: Option<Fingerprint>,
}

/// Publishing an identity whose publisher is unavailable or withdrawn takes it
/// over, under the caller's own grant; a live incumbent always wins.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublishRequest {
    pub id: PublicationId,
    pub label: Label,
    pub display: String,
    /// `None` is the host's Trusted Group. Either way the grant's ceiling applies.
    pub audience: Option<BTreeSet<Fingerprint>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct Lease {
    pub id: PublicationId,
    pub generation: u64,
    pub publisher: Fingerprint,
}

/// Opens one fresh ordered byte stream toward the named Tender instance. The
/// dialer only carries bytes: the handshake still authenticates whatever
/// answers, so a wrong route fails as an identity mismatch.
#[async_trait]
pub trait Dial: Send + Sync {
    async fn dial(&self, instance: &Fingerprint) -> io::Result<ByteStream>;
}

/// Routes supplied by the hosting application, which owns its links. The next
/// hop toward `host` is either `host` itself or a relay that forwards onward
/// under its own identity. Tender never stores or learns routes.
pub trait Router: Dial {
    fn next_hop(&self, host: &Fingerprint) -> Option<Fingerprint>;
}

pub struct Published {
    pub lease: Lease,
    /// One accepted raw channel per successful connect.
    pub incoming: mpsc::UnboundedReceiver<ByteStream>,
}

/// The instance carrying a Binding's streams, and the relay in between if any.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct Route {
    pub instance: Fingerprint,
    pub via: Option<Fingerprint>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableReason {
    /// The publisher went away; another may take the identity over.
    PublisherUnavailable,
    Withdrawn,
    /// No route currently reaches an instance carrying the publication.
    RouteUnavailable,
}

/// For display and diagnostics only: clients connect to the Local Endpoint
/// whatever the state, and an unavailable Binding refuses or closes promptly.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum BindingState {
    Available {
        route: Route,
    },
    Unavailable {
        reason: UnavailableReason,
        route: Option<Route>,
    },
    /// The publication's audience or grant no longer admits this machine.
    Revoked,
}

/// A Local Endpoint for a publication, keyed by its identity and the instance
/// that bound it, and shared by every local client of that instance. A
/// takeover or new route keeps the endpoint.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct Binding {
    pub publication: PublicationId,
    pub local_endpoint: String,
    pub state: BindingState,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub enum Error {
    IdentityMismatch,
    UntrustedIntermediary,
    Denied,
    GrantExpired,
    UnknownPublication,
    Unavailable,
    Withdrawn,
    LivePublisher,
    StaleGeneration,
    Deadline,
    Storage,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

/// Changes include full filtered snapshots, including Unavailable and
/// Withdrawn records. Transport implementations may coalesce intermediate
/// snapshots but must preserve the latest generation and state.
pub type Watch = mpsc::UnboundedReceiver<Vec<Publication>>;

#[async_trait]
pub trait Tender: Send + Sync {
    async fn publish(&self, session: &Session, request: PublishRequest) -> Result<Published, Error>;
    async fn browse(&self, session: &Session) -> Result<Vec<Publication>, Error>;
    async fn watch(&self, session: &Session) -> Result<Watch, Error>;
    async fn connect(&self, session: &Session, id: &PublicationId) -> Result<ByteStream, Error>;
    /// Abort a pending open at a caller-chosen bound. An established stream
    /// has no idle timeout; its owner may cancel by dropping it.
    async fn connect_with_deadline(&self, session: &Session, id: &PublicationId, deadline: Duration) -> Result<ByteStream, Error> {
        tokio::time::timeout(deadline, self.connect(session, id)).await.map_err(|_| Error::Deadline)?
    }
    /// Binding an identity again returns the same Local Endpoint with its
    /// current state; once bound, a publication that stops admitting the caller
    /// reports `Revoked` rather than disappearing.
    async fn bind(&self, session: &Session, id: &PublicationId) -> Result<Binding, Error>;
    async fn open_binding(&self, session: &Session, binding: &Binding) -> Result<ByteStream, Error>;
    async fn open_binding_with_deadline(&self, session: &Session, binding: &Binding, deadline: Duration) -> Result<ByteStream, Error> {
        tokio::time::timeout(deadline, self.open_binding(session, binding)).await.map_err(|_| Error::Deadline)?
    }
    async fn disconnect(&self, session: &Session, lease: &Lease) -> Result<(), Error>;
    async fn withdraw(&self, session: &Session, lease: &Lease) -> Result<(), Error>;
}
