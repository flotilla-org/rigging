//! Request and response bodies of the daemon's control API, served as JSON or
//! CBOR under `/v1` on the account's control socket.

use std::{collections::BTreeSet, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Fingerprint, Label, PublicKey, Publication, PublicationId};

pub const IDENTITY: &str = "/v1/identity";
pub const PUBLICATIONS: &str = "/v1/publications";
pub const PUBLISH: &str = "/v1/publish";
pub const WITHDRAW: &str = "/v1/withdraw";
pub const TRUSTED: &str = "/v1/trusted";
pub const UNTRUST: &str = "/v1/trusted/remove";
pub const DIAGNOSTICS: &str = "/v1/diagnostics";

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct Instance {
    pub key: PublicKey,
    pub fingerprint: Fingerprint,
    /// Where other instances reach this one on its own machine.
    pub peer_socket: PathBuf,
}

/// Publish an existing Unix socket on this machine. Tender never starts it.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct PublishEndpoint {
    pub id: PublicationId,
    pub label: Label,
    #[serde(default)]
    pub display: String,
    pub endpoint: PathBuf,
    /// `None` is this instance's Trusted Group.
    #[serde(default)]
    pub audience: Option<BTreeSet<Fingerprint>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct PublicationEntry {
    pub publication: Publication,
    /// The local socket, for publications this instance publishes itself.
    pub endpoint: Option<PathBuf>,
}

/// How this instance reaches a Trusted Group member: its peer socket, on this
/// machine or, with `ssh`, on the far side of an SSH destination.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct PeerRoute {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<String>,
    pub socket: PathBuf,
}

/// A member with no route is trusted but not followed: it may reach this
/// instance, while this one has no way to reach it.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TrustedInstance {
    pub key: PublicKey,
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<PeerRoute>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TrustedMember {
    pub fingerprint: Fingerprint,
    #[serde(flatten)]
    pub instance: TrustedInstance,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct Untrust {
    pub fingerprint: Fingerprint,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct Diagnostics {
    pub instance: Instance,
    pub publications: usize,
    pub trusted: usize,
}

/// The `{"code", "message"}` shape of every error body.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}
