use std::sync::Arc;

use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rigging_http_wire::{Encoding, Wire};

use super::{Inner, TrustError};
use crate::{
    Error, PublicationId,
    api::{self, Diagnostics, PublishEndpoint, TrustedInstance, Untrust},
};

type Daemon = State<Arc<Inner>>;

pub(super) fn router(inner: Arc<Inner>) -> Router {
    Router::new()
        .route(api::IDENTITY, get(identity))
        .route(api::PUBLICATIONS, get(publications))
        .route(api::PUBLISH, post(publish))
        .route(api::WITHDRAW, post(withdraw))
        .route(api::TRUSTED, get(trusted).post(trust))
        .route(api::UNTRUST, post(untrust))
        .route(api::DIAGNOSTICS, get(diagnostics))
        .route(api::BINDINGS, get(bindings))
        .with_state(inner)
}

async fn identity(State(inner): Daemon, encoding: Encoding) -> Response {
    encoding.ok(inner.instance()).into_response()
}

async fn publications(State(inner): Daemon, encoding: Encoding) -> Response {
    encoding.ok(inner.publications().await).into_response()
}

async fn publish(State(inner): Daemon, encoding: Encoding, Wire(request): Wire<PublishEndpoint>) -> Response {
    // A relative path would resolve against the daemon's directory, not the caller's.
    if request.endpoint.is_relative() {
        return encoding.error_code(StatusCode::BAD_REQUEST, "relative_endpoint", "the endpoint must be an absolute path");
    }
    match inner.publish(request).await {
        Ok(publication) => encoding.ok(publication).into_response(),
        Err(error) => refusal(encoding, error),
    }
}

async fn withdraw(State(inner): Daemon, encoding: Encoding, Wire(id): Wire<PublicationId>) -> Response {
    match inner.withdraw(&id).await {
        Ok(()) => encoding.ok(()).into_response(),
        Err(error) => refusal(encoding, error),
    }
}

async fn trusted(State(inner): Daemon, encoding: Encoding) -> Response {
    encoding.ok(inner.trusted().await).into_response()
}

async fn trust(State(inner): Daemon, encoding: Encoding, Wire(instance): Wire<TrustedInstance>) -> Response {
    match inner.trust(instance).await {
        Ok(member) => encoding.ok(member).into_response(),
        Err(error) => trust_refusal(encoding, error),
    }
}

async fn untrust(State(inner): Daemon, encoding: Encoding, Wire(untrust): Wire<Untrust>) -> Response {
    match inner.untrust(&untrust.fingerprint).await {
        Ok(()) => encoding.ok(()).into_response(),
        Err(error) => trust_refusal(encoding, error),
    }
}

async fn bindings(State(inner): Daemon, encoding: Encoding) -> Response {
    encoding.ok(inner.bindings()).into_response()
}

async fn diagnostics(State(inner): Daemon, encoding: Encoding) -> Response {
    let publications = inner.publications().await.publications.len();
    encoding
        .ok(Diagnostics {
            instance: inner.instance(),
            publications,
            trusted: inner.trusted_count().await,
            bindings: inner.bindings().len(),
            peers: inner.peers(),
        })
        .into_response()
}

/// The wire contract for each refusal: its status and stable code.
fn refusal(encoding: Encoding, error: Error) -> Response {
    let (status, code) = match error {
        Error::Denied => (StatusCode::FORBIDDEN, "denied"),
        Error::IdentityMismatch => (StatusCode::FORBIDDEN, "identity_mismatch"),
        Error::UntrustedIntermediary => (StatusCode::FORBIDDEN, "untrusted_intermediary"),
        Error::GrantExpired => (StatusCode::FORBIDDEN, "grant_expired"),
        Error::LivePublisher => (StatusCode::CONFLICT, "live_publisher"),
        Error::StaleGeneration => (StatusCode::CONFLICT, "stale_generation"),
        Error::UnknownPublication => (StatusCode::NOT_FOUND, "unknown_publication"),
        Error::Withdrawn => (StatusCode::GONE, "withdrawn"),
        Error::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        Error::Deadline => (StatusCode::SERVICE_UNAVAILABLE, "deadline"),
        Error::Storage => (StatusCode::SERVICE_UNAVAILABLE, "storage"),
    };
    encoding.error_code(status, code, error.to_string())
}

fn trust_refusal(encoding: Encoding, error: TrustError) -> Response {
    match error {
        TrustError::InvalidKey => encoding.error_code(StatusCode::BAD_REQUEST, "invalid_key", "key must be 32 bytes of lowercase hex"),
        TrustError::OwnKey => encoding.error_code(StatusCode::BAD_REQUEST, "own_key", "an instance cannot trust itself"),
        TrustError::NotMember => encoding.error_code(StatusCode::NOT_FOUND, "not_member", "no such Trusted Group member"),
        TrustError::Storage(error) => encoding.error_code(StatusCode::SERVICE_UNAVAILABLE, "storage", error.to_string()),
        TrustError::Tender(error) => refusal(encoding, error),
    }
}
