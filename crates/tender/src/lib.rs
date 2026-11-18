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

pub mod memory;
pub mod runtime;
#[cfg(unix)]
pub mod ssh;

/// Fingerprint of a persisted instance key, independent of its current route.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Fingerprint(pub String);

/// A vessel, or the publishing instance for a host endpoint. Who may publish
/// under a scope is a [`Grant`].
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Scope(pub String);

impl Scope {
    /// `tender/<fingerprint>`: the scope of one instance's own endpoints,
    /// published by and followed from that instance alone.
    pub fn instance(fingerprint: &Fingerprint) -> Self {
        Self(format!("tender/{}", fingerprint.0))
    }

    /// The instance whose scope this is, for a `tender/<fingerprint>` scope.
    /// Any other `tender/…` scope names no instance, and nobody publishes
    /// under it without a grant.
    pub fn owner(&self) -> Option<Fingerprint> {
        let fingerprint = self.0.strip_prefix("tender/")?;
        (!fingerprint.is_empty() && !fingerprint.contains('/')).then(|| Fingerprint(fingerprint.to_owned()))
    }

    /// A `vessel/…` scope, which whichever host holds the vessel publishes under.
    pub fn is_vessel(&self) -> bool {
        self.0.starts_with("vessel/")
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    // Only `tender/<fingerprint>` names an instance.
    #[test]
    fn instance_scopes_name_one_instance() {
        let fingerprint = Fingerprint("ab12".into());
        assert_eq!(Scope::instance(&fingerprint).owner(), Some(fingerprint));
        for other in ["tender/", "tender/a/b", "vessel/7", "tenderab12"] {
            assert_eq!(Scope(other.into()).owner(), None, "{other}");
        }
        assert!(Scope("vessel/7".into()).is_vessel() && !Scope("vessels/7".into()).is_vessel());
    }
}
