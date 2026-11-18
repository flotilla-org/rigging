//! The types a Tender client needs without Tender itself: publication
//! identity, Binding state, the control API's bodies and the rule that turns
//! an identity into its Binding's Local Endpoint. Consumers call the control
//! API with their own HTTP client.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};

pub mod api;
pub mod paths;

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
/// under a scope is the publishing instance's grant.
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
