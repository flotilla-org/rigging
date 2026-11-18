use std::path::Path;

use http::StatusCode;
use reqwest::{
    Method, Request, Url,
    header::{self, HeaderValue},
};
use rigging_http_client::{HttpClient, ReqwestHttpClient, http_channel_label};
use rigging_http_wire::LIMITS;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, from_value};
use tender::api::ErrorBody;

/// A test's own client for the control API, as any consumer would write one.
pub struct Control(ReqwestHttpClient);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Cbor,
}

impl Control {
    pub fn new(socket: &Path) -> Self {
        Self(ReqwestHttpClient::local(socket).expect("local client"))
    }

    pub async fn get<R: DeserializeOwned>(&self, path: &str) -> Result<R, (StatusCode, ErrorBody)> {
        self.call::<(), R>(Method::GET, path, None, Format::Json).await
    }

    pub async fn post<T: Serialize, R: DeserializeOwned>(&self, path: &str, body: &T) -> Result<R, (StatusCode, ErrorBody)> {
        self.call(Method::POST, path, Some(body), Format::Json).await
    }

    pub async fn call<T: Serialize, R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&T>,
        format: Format,
    ) -> Result<R, (StatusCode, ErrorBody)> {
        let mut request = Request::new(method, Url::parse(&format!("http://tender{path}")).expect("url"));
        let media = if format == Format::Json { "application/json" } else { "application/cbor" };
        request.headers_mut().insert(header::ACCEPT, HeaderValue::from_static(media));
        if let Some(body) = body {
            request.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(media));
            let bytes = match format {
                Format::Json => serde_json::to_vec(body).expect("json"),
                Format::Cbor => flotilla_cbor::to_vec(body, &LIMITS).expect("cbor"),
            };
            *request.body_mut() = Some(bytes.into());
        }
        let response = self.0.execute(request, &http_channel_label("POST", path)).await.expect("control socket");
        let decode = |bytes: &[u8]| -> Value {
            match format {
                Format::Json => serde_json::from_slice(bytes).expect("json body"),
                Format::Cbor => flotilla_cbor::from_slice(bytes, &LIMITS).expect("cbor body"),
            }
        };
        let value = decode(response.body());
        if response.status().is_success() {
            Ok(from_value(value).expect("response shape"))
        } else {
            Err((response.status(), from_value(value).expect("error shape")))
        }
    }
}
