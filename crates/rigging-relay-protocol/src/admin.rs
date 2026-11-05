//! Operator provisioning API. Every request carries `Authorization: Bearer <operator token>`.
//!
//! | Request | Effect |
//! | --- | --- |
//! | `POST /admin/installs/<install>` | Create the install; returns its first consumer token ([`InstallCreated`]). |
//! | `GET /admin/installs/<install>` | Describe the install ([`InstallDescription`]); no token or secret material. |
//! | `DELETE /admin/installs/<install>` | Delete the install, its credentials, sources and deliveries. |
//! | `POST /admin/installs/<install>/tokens` | Mint another consumer token ([`IssuedToken`]). |
//! | `DELETE /admin/installs/<install>/tokens/<id>` | Revoke a consumer token. |
//! | `PUT /admin/installs/<install>/sources/<source>` | Set the source's configuration ([`SourceConfig`]). |
//! | `POST /admin/installs/<install>/sources/<source>/secrets` | Add a webhook secret ([`AddSecret`], [`IssuedSecret`]). |
//! | `DELETE /admin/installs/<install>/sources/<source>/secrets/<id>` | Revoke a webhook secret. |
//!
//! Rotation is add-then-revoke: an install may hold several valid consumer tokens and several
//! secrets per source, so producers and consumers can move to new material without a window
//! in which nothing verifies. Token and secret material is returned once, when created.
use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};

use crate::source::SourceConfig;

/// Response to install creation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallCreated {
    pub install: String,
    pub consumer_token: IssuedToken,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedToken {
    pub id: String,
    pub token: String,
}

/// Optional body for adding a source secret. Without `secret`, the relay generates one.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddSecret {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

/// Minimum length of an operator-supplied webhook secret.
pub const MIN_SECRET_LEN: usize = 32;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedSecret {
    pub id: String,
    pub secret: String,
}

// Token and secret material never reaches a log through `{:?}`.
impl fmt::Debug for IssuedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedToken").field("id", &self.id).field("token", &"<redacted>").finish()
    }
}

impl fmt::Debug for AddSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddSecret").field("secret", &self.secret.as_ref().map(|_| "<redacted>")).finish()
    }
}

impl fmt::Debug for IssuedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedSecret").field("id", &self.id).field("secret", &"<redacted>").finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialInfo {
    pub id: String,
    pub created_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallDescription {
    pub install: String,
    pub created_ms: u64,
    pub consumer_tokens: Vec<CredentialInfo>,
    pub sources: BTreeMap<String, SourceDescription>,
    pub latest_cursor: u64,
    pub retained_deliveries: u64,
}

/// A source as the install knows it. A source receives deliveries once it has a
/// configuration and at least one secret.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDescription {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<SourceConfig>,
    #[serde(default)]
    pub secrets: Vec<CredentialInfo>,
}
