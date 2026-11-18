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
        .with_state(inner)
}

async fn identity(State(inner): Daemon, encoding: Encoding) -> Response {
    encoding.ok(inner.instance()).into_response()
}

async fn publications(State(inner): Daemon, encoding: Encoding) -> Response {
    encoding.ok(inner.publications().await).into_response()
}

async fn publish(State(inner): Daemon, encoding: Encoding, Wire(request): Wire<PublishEndpoint>) -> Response {
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

async fn diagnostics(State(inner): Daemon, encoding: Encoding) -> Response {
    let publications = inner.publications().await.len();
    encoding.ok(Diagnostics { instance: inner.instance(), publications, trusted: inner.trusted_count().await }).into_response()
}

fn refusal(encoding: Encoding, error: Error) -> Response {
    let status = match error {
        Error::Denied | Error::IdentityMismatch | Error::UntrustedIntermediary | Error::GrantExpired => StatusCode::FORBIDDEN,
        Error::LivePublisher | Error::StaleGeneration => StatusCode::CONFLICT,
        Error::UnknownPublication => StatusCode::NOT_FOUND,
        Error::Withdrawn => StatusCode::GONE,
        Error::Unavailable | Error::Deadline | Error::Storage => StatusCode::SERVICE_UNAVAILABLE,
    };
    encoding.error_code(status, &code(&error), error.to_string())
}

fn trust_refusal(encoding: Encoding, error: TrustError) -> Response {
    match error {
        TrustError::InvalidKey => encoding.error_code(StatusCode::BAD_REQUEST, "invalid_key", "key must be 32 bytes of lowercase hex"),
        TrustError::OwnKey => encoding.error_code(StatusCode::BAD_REQUEST, "own_key", "an instance cannot trust itself"),
        TrustError::NotMember => encoding.error_code(StatusCode::NOT_FOUND, "not_member", "no such Trusted Group member"),
        TrustError::Storage(error) => encoding.error_code(StatusCode::INTERNAL_SERVER_ERROR, "storage", error.to_string()),
        TrustError::Tender(error) => refusal(encoding, error),
    }
}

/// `LivePublisher` becomes `live_publisher`.
fn code(error: &Error) -> String {
    let mut code = String::new();
    for (index, character) in format!("{error:?}").chars().enumerate() {
        if character.is_uppercase() && index > 0 {
            code.push('_');
        }
        code.push(character.to_ascii_lowercase());
    }
    code
}
