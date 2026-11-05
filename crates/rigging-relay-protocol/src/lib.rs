//! Wire types of the webhook relay.
//!
//! The relay verifies each webhook delivery against its source's configuration
//! ([`source::SourceConfig`]), keeps it in cursor order, and serves the install's
//! deliveries to consumers as [`StreamFrame`]s over
//! `GET /i/<install>/stream?cursor=N`. Consumers acknowledge with [`ConsumerFrame`]s.
//! Installs and sources are provisioned through the operator-authenticated [`admin`] API.
//!
//! Stream query parameters, all optional besides `cursor`: `source=` and
//! `subject_prefix=` (each repeatable; a delivery matches any of the given values)
//! and `bodies=false`, which leaves `body` out of every delivery frame.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod admin;
pub mod source;

/// One verified webhook delivery as the relay keeps it.
///
/// Cursors increase strictly within one install. Every verified delivery has its own
/// cursor; a redelivery (same `source` and `delivery_id`) is kept once.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Delivery {
    pub cursor: u64,
    /// The source name the install chose for the ingress path `/i/<install>/<source>`.
    pub source: String,
    pub event: String,
    pub delivery_id: String,
    /// RFC 3339 UTC time at which the relay received the delivery.
    pub received_at: String,
    /// The subjects the source's rules derived; empty when no rule matched.
    #[serde(default)]
    pub subjects: Vec<String>,
    /// Values copied out of the body by the source's named pointers.
    #[serde(default)]
    pub fields: BTreeMap<String, Value>,
    /// The delivery's JSON body; absent when the consumer asked for `bodies=false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamFrame {
    Delivery(Delivery),
    /// The consumer's cursor is older than retention: a delivery it has not seen may have
    /// been removed. The consumer must refresh whatever it derives from the stream, then
    /// resume from `latest_cursor`. `oldest_cursor` is the oldest retained delivery, absent
    /// when none remain.
    Gap {
        oldest_cursor: Option<u64>,
        latest_cursor: u64,
    },
    /// The consumer has every matching delivery up to `cursor`, the install's latest.
    Ready {
        cursor: u64,
    },
    Acked {
        cursor: u64,
    },
    Error {
        message: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConsumerFrame {
    Ack { cursor: u64 },
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn delivery_frames_carry_the_delivery_beside_its_type() {
        let frame = StreamFrame::Delivery(Delivery {
            cursor: 42,
            source: "daytona".into(),
            event: "sandbox.state.updated".into(),
            delivery_id: "msg_2b".into(),
            received_at: "2026-11-05T18:00:00Z".into(),
            subjects: vec!["sandbox/sandbox123".into()],
            fields: BTreeMap::from([("state".into(), json!("stopped"))]),
            body: None,
        });
        let wire = json!({
            "type": "delivery", "cursor": 42, "source": "daytona", "event": "sandbox.state.updated",
            "delivery_id": "msg_2b", "received_at": "2026-11-05T18:00:00Z",
            "subjects": ["sandbox/sandbox123"], "fields": { "state": "stopped" },
        });
        assert_eq!(serde_json::to_value(&frame).expect("serialize"), wire);
        assert_eq!(serde_json::from_value::<StreamFrame>(wire).expect("deserialize"), frame);
    }
}
