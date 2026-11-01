use axum::{
    Router,
    body::{Body, Bytes},
    http::{HeaderMap, Request, StatusCode, header},
    response::Response,
    routing::{get, post},
};
use futures_util::StreamExt;
use hegel::generators as gs;
use rigging_http_wire::{Encoding, LIMITS, Negotiated, NotAcceptable, Wire, negotiate};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{convert::Infallible, time::Duration};
use tower::ServiceExt;

const LIMIT: usize = 64;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Note {
    text: String,
    count: u64,
    tags: Vec<String>,
}

async fn echo(encoding: Encoding, Wire(note): Wire<Note, LIMIT>) -> Negotiated<Note> {
    encoding.ok(note)
}

async fn bodyless(encoding: Encoding, Wire(()): Wire<(), LIMIT>) -> Negotiated<Value> {
    encoding.ok(json!({"big": u64::MAX, "small": i64::MIN}))
}

fn app() -> Router {
    Router::new().route("/echo", post(echo)).route("/bodyless", get(bodyless).delete(bodyless))
}

async fn send(request: Request<Body>) -> (StatusCode, HeaderMap, Bytes) {
    let response: Response = app().oneshot(request).await.expect("router is infallible");
    let (parts, body) = response.into_parts();
    (parts.status, parts.headers, axum::body::to_bytes(body, 1 << 20).await.expect("response body"))
}

fn decode(headers: &HeaderMap, bytes: &[u8]) -> Value {
    match headers[header::CONTENT_TYPE].to_str().expect("content type") {
        "application/cbor" => flotilla_cbor::from_slice(bytes, &LIMITS).expect("CBOR body"),
        "application/json" => serde_json::from_slice(bytes).expect("JSON body"),
        other => panic!("unexpected content type {other}"),
    }
}

// Specific media ranges override wildcards, so a zero-quality specific range excludes
// its type whatever wildcard accompanies it, and range order never matters. Spans every
// allowed-list order, either excluded type, both wildcard forms, and zero, partial and
// full wildcard quality.
#[hegel::test]
fn exclusions_override_wildcards_in_any_order(tc: hegel::TestCase) {
    let allowed = tc.draw(gs::permutations(vec!["application/json", "application/cbor", "text/markdown"]));
    let excluded = tc.draw(gs::integers::<usize>().min_value(0).max_value(allowed.len() - 1));
    let wildcard = tc.draw(gs::sampled_from(vec!["*/*", "application/*"]));
    let quality = tc.draw(gs::sampled_from(vec!["0", "0.5", "1"]));
    let ranges =
        tc.draw(gs::permutations(vec![format!("{};q=0", allowed[excluded].to_ascii_uppercase()), format!("{wildcard};q={quality}")]));

    let chosen = negotiate(&ranges.join(" , "), &allowed);

    let covered = |media: &str| wildcard == "*/*" || media.starts_with("application/");
    let expected = allowed
        .iter()
        .enumerate()
        .find(|(index, media)| *index != excluded && quality != "0" && covered(media))
        .map(|(index, _)| index)
        .ok_or(NotAcceptable::NoMatch);
    assert_eq!(chosen, expected, "Accept {ranges:?} over {allowed:?}");
}

// The highest quality wins over list order, ties go to the earlier type, an empty Accept
// takes the first, and a quality outside 0..=1 or not a number is refused.
#[test]
fn quality_ordering_and_invalid_qualities() {
    let media = ["application/json", "application/cbor"];
    assert_eq!(negotiate("application/json;q=0.4, application/cbor;q=0.5", &media), Ok(1));
    assert_eq!(negotiate("application/cbor, application/json", &media), Ok(0));
    assert_eq!(negotiate("", &media), Ok(0));
    for quality in ["no", "NaN", "inf", "1.5", "-0.1"] {
        assert_eq!(negotiate(&format!("application/json;q={quality}"), &media), Err(NotAcceptable::InvalidQuality));
    }
}

// An Accept no representation satisfies answers 406 unsupported_format with Vary: Accept,
// in CBOR when the refused header still named it and in JSON otherwise.
#[tokio::test]
async fn unacceptable_requests_answer_406_in_the_requested_error_encoding() {
    for (accept, cbor) in [("text/html", false), ("application/cbor;q=bad", true), ("application/json;q=0, application/cbor;q=0", false)] {
        let request = Request::post("/echo").header(header::ACCEPT, accept).body(Body::from(r#"{"text":"","count":0,"tags":[]}"#));
        let (status, headers, bytes) = send(request.unwrap()).await;
        assert_eq!(status, StatusCode::NOT_ACCEPTABLE, "{accept}");
        assert_eq!(headers[header::VARY], "Accept");
        assert_eq!(headers[header::CONTENT_TYPE], if cbor { "application/cbor" } else { "application/json" }, "{accept}");
        assert_eq!(decode(&headers, &bytes)["code"], "unsupported_format");
    }
}

// A body decodes into the route's type from JSON or CBOR within the limit, and the reply
// comes back in the encoding Accept negotiates, independently of the request's encoding.
// Spans both encodings each way, empty and multibyte text, integers past 2^53, and bodies
// at the limit and one byte over it.
#[hegel::test]
fn json_and_cbor_bodies_decode_and_reply_in_the_negotiated_encoding(tc: hegel::TestCase) {
    let note = Note {
        text: tc.draw(gs::text().max_size(24)),
        count: tc.draw(gs::sampled_from(vec![0, 1 << 53, u64::MAX])),
        tags: tc.draw(gs::vecs(gs::text().max_size(4)).max_size(3)),
    };
    let cbor_in = tc.draw(gs::booleans());
    let cbor_out = tc.draw(gs::booleans());
    let bytes = if cbor_in { flotilla_cbor::to_vec(&note, &LIMITS).unwrap() } else { serde_json::to_vec(&note).unwrap() };
    let request = Request::post("/echo")
        .header(header::CONTENT_TYPE, if cbor_in { "application/cbor" } else { "Application/JSON; charset=utf-8" })
        .header(header::ACCEPT, if cbor_out { "application/cbor" } else { "application/json" })
        .body(Body::from(bytes.clone()))
        .unwrap();
    let (status, headers, body) = tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(send(request));

    if bytes.len() > LIMIT {
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        return;
    }
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], if cbor_out { "application/cbor" } else { "application/json" });
    assert_eq!(headers[header::VARY], "Accept");
    let reply = decode(&headers, &body);
    // JSON tags integers past 2^53 − 1 so a JSON reader cannot round them; CBOR keeps them.
    let count = if !cbor_out && note.count > (1 << 53) - 1 { json!({"u64": note.count.to_string()}) } else { json!(note.count) };
    assert_eq!(reply, json!({"text": note.text, "count": count, "tags": note.tags}));
}

// The limit applies while the body streams: a chunked body with no Content-Length is
// refused with 413 once it passes the limit, without waiting for a body that never ends.
#[tokio::test]
async fn an_over_limit_stream_is_refused_while_reading() {
    let chunks = futures_util::stream::iter([Ok::<_, Infallible>(Bytes::from(vec![b' '; LIMIT])), Ok(Bytes::from_static(b" "))])
        .chain(futures_util::stream::pending());
    let request = Request::post("/echo").body(Body::from_stream(chunks)).unwrap();
    let (status, headers, bytes) = tokio::time::timeout(Duration::from_secs(5), send(request)).await.expect("refused while streaming");
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(decode(&headers, &bytes)["code"], "payload_too_large");
}

// A declared Content-Length over the limit is refused before reading, and one that is not
// a number is a bad request.
#[tokio::test]
async fn declared_lengths_are_checked_before_reading() {
    for (length, expected) in [((LIMIT + 1).to_string(), StatusCode::PAYLOAD_TOO_LARGE), ("lots".into(), StatusCode::BAD_REQUEST)] {
        let request = Request::post("/echo")
            .header(header::CONTENT_LENGTH, length)
            .body(Body::from_stream(futures_util::stream::pending::<Result<Bytes, Infallible>>()));
        let (status, ..) = tokio::time::timeout(Duration::from_secs(5), send(request.unwrap())).await.expect("refused before reading");
        assert_eq!(status, expected);
    }
}

// Only JSON and CBOR bodies are read; any other Content-Type is 415, and a body that is not
// the route's type is 400.
#[tokio::test]
async fn wrong_content_type_and_malformed_bodies_are_refused() {
    for (content_type, body, expected) in [
        ("text/plain", r#"{"text":"","count":0,"tags":[]}"#, StatusCode::UNSUPPORTED_MEDIA_TYPE),
        ("application/x-www-form-urlencoded", "text=a", StatusCode::UNSUPPORTED_MEDIA_TYPE),
        ("application/json", r#"{"text":1}"#, StatusCode::BAD_REQUEST),
        ("application/cbor", "{}", StatusCode::BAD_REQUEST),
    ] {
        let request = Request::post("/echo").header(header::CONTENT_TYPE, content_type).body(Body::from(body)).unwrap();
        let (status, headers, bytes) = send(request).await;
        assert_eq!(status, expected, "{content_type}");
        assert!(decode(&headers, &bytes)["message"].is_string());
    }
}

// GET and DELETE take no body: an empty one decodes as `()`, and any byte is 413 whatever
// the route's limit.
#[tokio::test]
async fn bodyless_methods_take_no_body() {
    for method in ["GET", "DELETE"] {
        let (status, headers, bytes) = send(Request::builder().method(method).uri("/bodyless").body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(decode(&headers, &bytes), json!({"big": {"u64": u64::MAX.to_string()}, "small": {"i64": i64::MIN.to_string()}}));
        let (status, ..) = send(Request::builder().method(method).uri("/bodyless").body(Body::from("{}")).unwrap()).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{method}");
    }
}

// A value the CBOR profile cannot encode still answers, as a 500 error in that encoding;
// and every 401 names the Bearer scheme.
#[tokio::test]
async fn encoding_faults_and_unauthorized_keep_the_error_shape() {
    let mut nested = json!(null);
    for _ in 0..80 {
        nested = json!([nested]);
    }
    let response = Encoding::Cbor.render(StatusCode::OK, nested);
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, 1024).await.unwrap();
    assert_eq!(decode(&parts.headers, &bytes)["code"], "internal_server_error");

    let response = Encoding::Json.error_code(StatusCode::UNAUTHORIZED, "unauthorized", "sign in");
    assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
}
