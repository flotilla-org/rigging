//! Per-source configuration, set with `PUT /admin/installs/<install>/sources/<source>`.
//!
//! Everything source-specific comes from here: how a delivery is verified, where its
//! event and delivery id are, which subjects it is about and which fields are copied
//! out of its body. Pointers are JSON pointers (RFC 6901) into the body; a `*` segment
//! expands over every element of an array.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceConfig {
    pub verify: Verify,
    pub event: Locator,
    pub delivery_id: Locator,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subjects: Vec<SubjectRule>,
    /// Named pointers whose values are copied into each delivery's `fields`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub lowercase_subjects: bool,
}

/// How a delivery proves it came from the source, checked against each of the source's secrets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verify {
    /// `X-Hub-Signature-256: sha256=<hex HMAC-SHA256 of the body>`.
    GithubHmac,
    /// `X-Forgejo-Signature: <hex HMAC-SHA256 of the body>`.
    ForgejoHmac,
    /// Standard Webhooks: `webhook-id`, `webhook-timestamp` and `webhook-signature`
    /// (or their `svix-` aliases), HMAC-SHA256 over `id.timestamp.body` with a
    /// `whsec_` base64 secret.
    StandardWebhooks,
    /// E2B: `e2b-signature: <unpadded base64 SHA-256 of the secret followed by the body>`.
    E2bSha256,
}

/// Where a value is found: a request header, or a pointer into the body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Locator {
    Header(String),
    Pointer(String),
}

/// One way of deriving subjects from a delivery.
///
/// `template` is text with pointers in braces, such as
/// `cr/github.com/{/repository/full_name}/{/pull_request/number}`; it yields one subject
/// per combination of the values its pointers find, and none when a pointer finds nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectRule {
    /// Events the rule applies to; every event when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<String>,
    /// The rule applies only when this pointer exists and is not null.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
    /// The rule applies only when this pointer is missing or null.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unless: Option<String>,
    pub template: String,
}
