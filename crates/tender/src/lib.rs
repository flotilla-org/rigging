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
pub use tender_types::{
    Availability, BindingState, Fingerprint, Label, PublicKey, Publication, PublicationId, Route, Scope, UnavailableReason, api, paths,
};
use tokio::sync::mpsc;

#[cfg(unix)]
pub mod cli;
#[cfg(unix)]
pub mod daemon;
#[cfg(unix)]
pub mod links;
pub mod memory;
pub mod runtime;
#[cfg(unix)]
pub mod ssh;

/// Sleeps until `deadline`, or forever without one: the one timer a loop
/// that wakes on events also waits on.
#[cfg(unix)]
pub(crate) async fn until(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
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

/// Routes for relaying. The next hop toward `host` is either `host` itself or
/// a relay that forwards onward under its own identity. A server relays along
/// the routes its links learn (`links::Links`) unless the hosting application
/// supplies its own. Routes are never stored.
pub trait Router: Dial {
    fn next_hop(&self, host: &Fingerprint) -> Option<Fingerprint>;
}

pub struct Published {
    pub lease: Lease,
    /// One accepted raw channel per successful connect.
    pub incoming: mpsc::UnboundedReceiver<ByteStream>,
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
    /// A Local Endpoint for one identity over this adapter's one route, to the
    /// host it is pinned to. This is a building block, not the daemon's
    /// Binding: the daemon follows its whole Trusted Group, chooses a carrier
    /// among the instances offering the identity, and owns the path clients
    /// compute. Binding an identity again returns the same Local Endpoint with
    /// its current state; once bound, a publication that stops admitting the
    /// caller reports `Revoked` rather than disappearing.
    async fn bind(&self, session: &Session, id: &PublicationId) -> Result<Binding, Error>;
    async fn open_binding(&self, session: &Session, binding: &Binding) -> Result<ByteStream, Error>;
    async fn open_binding_with_deadline(&self, session: &Session, binding: &Binding, deadline: Duration) -> Result<ByteStream, Error> {
        tokio::time::timeout(deadline, self.open_binding(session, binding)).await.map_err(|_| Error::Deadline)?
    }
    async fn disconnect(&self, session: &Session, lease: &Lease) -> Result<(), Error>;
    async fn withdraw(&self, session: &Session, lease: &Lease) -> Result<(), Error>;
}
