#![doc = include_str!("../README.md")]

use axum::{
    body::Bytes,
    extract::{FromRequest, FromRequestParts, Request},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::fmt;

/// Response encoding limits: the stack CBOR profile's defaults, widened for large documents.
pub const LIMITS: flotilla_cbor::Limits =
    flotilla_cbor::Limits { max_message: 16 * 1024 * 1024, max_depth: 64, max_elements: 1 << 20, max_byte_string: 16 * 1024 * 1024 };

/// The request body limit a [`Wire`] extractor applies when the route names none.
pub const DEFAULT_BODY_LIMIT: usize = 64 * 1024;

/// Why no representation can be chosen; each answers 406 `unsupported_format`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotAcceptable {
    /// The `Accept` header is not visible ASCII.
    InvalidHeader,
    /// A `q` parameter is not a number between 0 and 1.
    InvalidQuality,
    /// Every representation is excluded or unmatched.
    NoMatch,
}

impl fmt::Display for NotAcceptable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidHeader => "invalid Accept header",
            Self::InvalidQuality => "invalid Accept quality",
            Self::NoMatch => "no acceptable representation",
        })
    }
}

impl std::error::Error for NotAcceptable {}

impl NotAcceptable {
    /// The 406 answer, in the encoding [`Encoding::for_errors`] picks from the same headers.
    pub fn respond(self, headers: &HeaderMap) -> Response {
        Encoding::for_errors(headers).error_code(StatusCode::NOT_ACCEPTABLE, "unsupported_format", self.to_string())
    }
}

/// The request's `Accept` value; absent is empty, which accepts anything.
pub fn accept(headers: &HeaderMap) -> Result<&str, NotAcceptable> {
    headers
        .get(header::ACCEPT)
        .map(|value| value.to_str().map_err(|_| NotAcceptable::InvalidHeader))
        .transpose()
        .map(Option::unwrap_or_default)
}

/// The index into `allowed` (lowercase media types, in tie-break order) that `accept` prefers.
///
/// For each allowed type the most specific matching range sets its quality, so
/// `application/json;q=0, */*` excludes JSON while accepting everything else. The highest
/// quality wins and ties go to the earlier type. An `accept` with no ranges picks the first.
///
/// Qualities are read leniently, as any number from 0 to 1 (`.5` and `1e0` are accepted
/// where RFC 9110 writes `0.5` and `1`), but one that is not a number refuses the whole
/// header, even when another range would match: a client that cannot write `Accept`
/// learns so rather than getting a guess.
pub fn negotiate(accept: &str, allowed: &[&str]) -> Result<usize, NotAcceptable> {
    if media_ranges(accept).next().is_none() {
        return Ok(0);
    }
    let mut candidates = vec![None::<(u8, f32)>; allowed.len()];
    for (media, quality) in media_ranges(accept) {
        let quality = quality.unwrap_or("1").parse::<f32>().map_err(|_| NotAcceptable::InvalidQuality)?;
        if !quality.is_finite() || !(0.0..=1.0).contains(&quality) {
            return Err(NotAcceptable::InvalidQuality);
        }
        for (index, target) in allowed.iter().enumerate() {
            let specificity = if media == *target {
                2
            } else if media == "*/*" {
                0
            } else if media.ends_with("/*") && target.starts_with(media.trim_end_matches('*')) {
                1
            } else {
                continue;
            };
            if candidates[index].is_none_or(|(old, _)| specificity >= old) {
                candidates[index] = Some((specificity, quality))
            }
        }
    }
    candidates
        .iter()
        .enumerate()
        .filter_map(|(index, value)| value.filter(|(_, q)| *q > 0.0).map(|(_, q)| (index, q)))
        .max_by(|(ia, a), (ib, b)| a.total_cmp(b).then(ib.cmp(ia)))
        .map(|(index, _)| index)
        .ok_or(NotAcceptable::NoMatch)
}

/// Each range of an `Accept` value: its lowercase media type and its raw `q` parameter.
/// Empty list elements (`a, , b,`) are skipped, as RFC 9110 §5.6.1 requires of a recipient.
/// [`negotiate`] and [`Encoding::for_errors`] read ranges only through this.
fn media_ranges(accept: &str) -> impl Iterator<Item = (String, Option<&str>)> {
    accept.split(',').filter(|entry| !entry.trim().is_empty()).map(|entry| {
        let mut parts = entry.trim().split(';');
        let media = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
        let quality =
            parts.find_map(|p| p.split_once('=').filter(|(key, _)| key.trim().eq_ignore_ascii_case("q")).map(|(_, value)| value.trim()));
        (media, quality)
    })
}

/// A structured response encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Json,
    Cbor,
}

impl Encoding {
    /// The encoding `Accept` prefers between `application/json` (the default) and `application/cbor`.
    pub fn negotiate(headers: &HeaderMap) -> Result<Self, NotAcceptable> {
        Ok(match negotiate(accept(headers)?, &["application/json", "application/cbor"])? {
            0 => Self::Json,
            _ => Self::Cbor,
        })
    }

    /// The encoding for an error body. A malformed or unsatisfiable `Accept` may still name
    /// CBOR, consistently for single objects and for sequences (`application/cbor-seq`).
    pub fn for_errors(headers: &HeaderMap) -> Self {
        let accept = headers.get(header::ACCEPT).and_then(|value| value.to_str().ok()).unwrap_or("");
        match negotiate(
            accept,
            &["application/json", "application/cbor", "application/cbor-seq", "application/x-ndjson", "application/jsonl"],
        ) {
            Ok(1 | 2) => Self::Cbor,
            Ok(_) => Self::Json,
            Err(NotAcceptable::InvalidQuality)
                if media_ranges(accept).any(|(media, _)| matches!(media.as_str(), "application/cbor" | "application/cbor-seq")) =>
            {
                Self::Cbor
            }
            Err(_) => Self::Json,
        }
    }

    pub fn content_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Cbor => "application/cbor",
        }
    }

    /// One encoded value. Bodies are JSON-shaped: both encodings write the value's
    /// `serde_json::Value`, so they carry the same data, at the cost of holding that tree
    /// beside the encoded bytes. JSON writes integers beyond ±(2^53 − 1) through
    /// [`json_safe_integers`]; CBOR carries them natively. CBOR output is bounded by
    /// [`LIMITS`], so a deeper or larger value is an error.
    pub fn encode<T: Serialize + ?Sized>(self, value: &T) -> Result<Vec<u8>, String> {
        let mut value = serde_json::to_value(value).map_err(|error| error.to_string())?;
        match self {
            Self::Cbor => flotilla_cbor::to_vec(&value, &LIMITS).map_err(|error| error.to_string()),
            Self::Json => {
                json_safe_integers(&mut value);
                serde_json::to_vec(&value).map_err(|error| error.to_string())
            }
        }
    }

    /// One item of a sequence: a JSON Lines line (`\n`-terminated) or one item of a CBOR sequence.
    pub fn encode_item<T: Serialize + ?Sized>(self, value: &T) -> Result<Vec<u8>, String> {
        let mut bytes = self.encode(value)?;
        if self == Self::Json {
            bytes.push(b'\n');
        }
        Ok(bytes)
    }

    /// `value` as the response body, with `Cache-Control: no-store` and `Vary: Accept`. A value
    /// that cannot be encoded answers 500 in the same encoding, naming the encoder's reason
    /// (as a depth or size limit) so a client can tell which limit its request reached.
    pub fn render(self, status: StatusCode, value: impl Serialize) -> Response {
        match self.encode(&value) {
            Ok(bytes) => vary_accept(
                (status, [(header::CONTENT_TYPE, self.content_type()), (header::CACHE_CONTROL, "no-store")], bytes).into_response(),
            ),
            Err(error) => self.error(StatusCode::INTERNAL_SERVER_ERROR, error),
        }
    }

    /// An error body whose code names the status, as `payload_too_large`.
    pub fn error(self, status: StatusCode, message: impl AsRef<str>) -> Response {
        let code = status.canonical_reason().map(|reason| reason.to_ascii_lowercase().replace([' ', '-'], "_"));
        self.error_code(status, code.as_deref().unwrap_or("error"), message)
    }

    /// The error shape `{"code", "message"}`. A 401 carries `WWW-Authenticate: Bearer`.
    pub fn error_code(self, status: StatusCode, code: &str, message: impl AsRef<str>) -> Response {
        let mut response = self.render(status, json!({"code": code, "message": message.as_ref()}));
        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }

    /// `value` with `status`, rendered when the handler returns it.
    pub fn respond<R>(self, status: StatusCode, value: R) -> Negotiated<R> {
        Negotiated { encoding: self, status, value }
    }

    /// `value` with 200.
    pub fn ok<R>(self, value: R) -> Negotiated<R> {
        self.respond(StatusCode::OK, value)
    }
}

/// A handler takes the negotiated encoding by signature; an unacceptable `Accept` answers 406.
impl<S: Send + Sync> FromRequestParts<S> for Encoding {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Self::negotiate(&parts.headers).map_err(|reason| reason.respond(&parts.headers))
    }
}

/// A response value rendered in the negotiated encoding (see [`Encoding::render`]).
#[derive(Debug)]
pub struct Negotiated<R> {
    pub encoding: Encoding,
    pub status: StatusCode,
    pub value: R,
}

impl<R: Serialize> IntoResponse for Negotiated<R> {
    fn into_response(self) -> Response {
        self.encoding.render(self.status, self.value)
    }
}

/// Marks a response as chosen by `Accept`, so caches keep one copy per representation.
pub fn vary_accept(mut response: Response) -> Response {
    response.headers_mut().insert(header::VARY, HeaderValue::from_static("Accept"));
    response
}

/// Rewrites integers beyond ±(2^53 − 1), which JSON readers may round, as
/// `{"u64": "…"}` or `{"i64": "…"}`. `as_u64` and `as_i64` read the number whether or not
/// serde_json's `arbitrary_precision` feature is on, so feature unification does not change it.
pub fn json_safe_integers(value: &mut Value) {
    const SAFE: u64 = (1 << 53) - 1;
    match value {
        Value::Number(n) if n.as_u64().is_some_and(|n| n > SAFE) => *value = json!({"u64": n.to_string()}),
        Value::Number(n) if n.as_i64().is_some_and(|n| n < -(SAFE as i64)) => *value = json!({"i64": n.to_string()}),
        Value::Array(values) => values.iter_mut().for_each(json_safe_integers),
        Value::Object(values) => values.values_mut().for_each(json_safe_integers),
        _ => {}
    }
}

/// A request body refused before or while decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyError {
    status: StatusCode,
    message: String,
}

impl BodyError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self { status, message: message.into() }
    }

    fn too_large() -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, "request body exceeds route limit")
    }

    /// 400, 413 or 415.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    /// The refusal in `encoding`, through [`Encoding::error`].
    pub fn respond(&self, encoding: Encoding) -> Response {
        encoding.error(self.status, &self.message)
    }
}

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for BodyError {}

/// A request body read within its route's limit, not yet decoded.
#[derive(Clone, Debug)]
pub struct Body {
    bytes: Bytes,
    encoding: Encoding,
    limit: usize,
}

impl Body {
    /// Reads at most `limit` bytes, stopping at the limit while streaming. Checks run in this
    /// order: a conflicting or non-numeric `Content-Length` is 400 and one over the
    /// limit is 413; then, with a nonzero limit, a `Content-Type` other than `application/json`
    /// (the default when absent) or `application/cbor` is 415; then a body that streams past
    /// the limit is 413. With a zero limit any body is 413.
    pub async fn read(request: Request, limit: usize) -> Result<Self, BodyError> {
        let headers = request.headers();
        // Every Content-Length value must be the same number: hyper refuses conflicting
        // lengths on HTTP/1, but a request handed here from elsewhere may carry them.
        let mut declared = None;
        for length in headers.get_all(header::CONTENT_LENGTH) {
            // RFC 9110: 1*DIGIT, so no sign or whitespace, which u64::parse would let through.
            let size =
                length.to_str().ok().filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())).and_then(|v| v.parse::<u64>().ok());
            if size.is_none() || declared.is_some_and(|declared| Some(declared) != size) {
                return Err(BodyError::new(StatusCode::BAD_REQUEST, "invalid Content-Length"));
            }
            declared = size;
        }
        if declared.is_some_and(|size| size > limit as u64) {
            return Err(BodyError::too_large());
        }
        let media = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let encoding = match media.as_str() {
            "application/cbor" => Encoding::Cbor,
            "application/json" => Encoding::Json,
            _ if limit == 0 => Encoding::Json,
            _ => return Err(BodyError::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "use application/json or application/cbor")),
        };
        // http-body-util's limiting body: unknown-length streams stop at the limit too,
        // rather than collecting first and checking afterwards.
        let bytes = axum::body::to_bytes(request.into_body(), limit).await.map_err(|_| BodyError::too_large())?;
        Ok(Self { bytes, encoding, limit })
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// The body as `T`, through serde_json or the stack CBOR profile's safe reader bounded by
    /// the route limit; malformed input is 400.
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T, BodyError> {
        match self.encoding {
            Encoding::Cbor => {
                flotilla_cbor::from_slice(&self.bytes, &flotilla_cbor::Limits { max_message: self.limit, ..Default::default() })
                    .map_err(|error| error.to_string())
            }
            Encoding::Json => serde_json::from_slice(&self.bytes).map_err(|error| error.to_string()),
        }
        .map_err(|message| BodyError::new(StatusCode::BAD_REQUEST, message))
    }
}

/// A request body decoded as `T` by signature, within `LIMIT` bytes ([`Body::read`]).
///
/// GET, HEAD and DELETE take no body: their limit is zero, and `T` is decoded from an absent
/// value, so such a route takes `Wire<()>` or `Wire<Option<_>>`. `Wire` refuses only the
/// body, in the encoding `Accept` negotiates, or in [`Encoding::for_errors`]'s pick when
/// `Accept` is unacceptable. A route that negotiates takes [`Encoding`] too, which runs
/// first and answers 406 for an unacceptable `Accept` before `Wire` reads anything.
#[derive(Clone, Debug)]
pub struct Wire<T, const LIMIT: usize = DEFAULT_BODY_LIMIT>(pub T);

impl<S: Send + Sync, T: DeserializeOwned, const LIMIT: usize> FromRequest<S> for Wire<T, LIMIT> {
    type Rejection = Response;

    async fn from_request(request: Request, _: &S) -> Result<Self, Self::Rejection> {
        let encoding = Encoding::negotiate(request.headers()).unwrap_or_else(|_| Encoding::for_errors(request.headers()));
        let bodyless = matches!(*request.method(), Method::GET | Method::HEAD | Method::DELETE);
        let body = Body::read(request, if bodyless { 0 } else { LIMIT }).await.map_err(|error| error.respond(encoding))?;
        let value = if bodyless {
            T::deserialize(serde::de::value::UnitDeserializer::<serde::de::value::Error>::new())
                .map_err(|error| BodyError::new(StatusCode::BAD_REQUEST, error.to_string()))
        } else {
            body.decode()
        };
        value.map(Wire).map_err(|error| error.respond(encoding))
    }
}

/// A response that is a sequence of values, one [`Encoding::encode_item`] each: JSON Lines or
/// a CBOR sequence (RFC 8742), which a client reads with [`Items`] as the bytes arrive.
impl Encoding {
    /// The encoding `Accept` prefers between `application/jsonl` (the default, also read as
    /// `application/x-ndjson`) and `application/cbor-seq`.
    pub fn negotiate_sequence(headers: &HeaderMap) -> Result<Self, NotAcceptable> {
        Ok(match negotiate(accept(headers)?, &["application/jsonl", "application/x-ndjson", "application/cbor-seq"])? {
            0 | 1 => Self::Json,
            _ => Self::Cbor,
        })
    }

    pub fn sequence_type(self) -> &'static str {
        match self {
            Self::Json => "application/jsonl",
            Self::Cbor => "application/cbor-seq",
        }
    }

    /// The encoding a sequence response's `Content-Type` names, if it names one.
    pub fn of_sequence(content_type: &str) -> Option<Self> {
        match content_type.split(';').next().unwrap_or_default().trim().to_ascii_lowercase().as_str() {
            "application/jsonl" | "application/x-ndjson" => Some(Self::Json),
            "application/cbor-seq" => Some(Self::Cbor),
            _ => None,
        }
    }
}

/// Splits a sequence body into its values as its bytes arrive, in any pieces. A value is
/// bounded by [`LIMITS`]: one still arriving past `max_message` is an error, not more buffer.
#[derive(Debug)]
pub struct Items {
    encoding: Encoding,
    buffer: Vec<u8>,
}

impl Items {
    pub fn new(encoding: Encoding) -> Self {
        Self { encoding, buffer: vec![] }
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// The next whole value, or `None` until more bytes arrive. JSON Lines skips blank lines.
    pub fn take<T: DeserializeOwned>(&mut self) -> Result<Option<T>, String> {
        loop {
            let (len, value) = match self.encoding {
                Encoding::Json => {
                    let Some(end) = self.buffer.iter().position(|&b| b == b'\n') else {
                        return self.waiting();
                    };
                    let line = &self.buffer[..end];
                    if line.trim_ascii().is_empty() {
                        self.buffer.drain(..=end);
                        continue;
                    }
                    (end + 1, serde_json::from_slice(line).map_err(|error| error.to_string()))
                }
                Encoding::Cbor => {
                    let Some(len) = flotilla_cbor::item_len(&self.buffer, &LIMITS).map_err(|error| error.to_string())? else {
                        return Ok(None);
                    };
                    (len, flotilla_cbor::from_slice(&self.buffer[..len], &LIMITS).map_err(|error| error.to_string()))
                }
            };
            self.buffer.drain(..len);
            return value.map(Some);
        }
    }

    /// Whether no part of a value is waiting: a body that ends otherwise ended mid-value.
    pub fn is_empty(&self) -> bool {
        match self.encoding {
            Encoding::Json => self.buffer.trim_ascii().is_empty(),
            Encoding::Cbor => self.buffer.is_empty(),
        }
    }

    fn waiting<T>(&self) -> Result<Option<T>, String> {
        if self.buffer.len() > LIMITS.max_message {
            return Err(format!("a line of over {} bytes", LIMITS.max_message));
        }
        Ok(None)
    }
}
