//! Network-boundary stand-in support; preserve the production request except its authority.
use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::Router;
use bytes::Bytes;
use tokio::task::JoinHandle;
use url::Url;

use rigging_http_client::HttpClient;
use rigging_http_client::ReqwestHttpClient;
use rigging_process::ChannelLabel;

/// Loopback HTTP server with a production executor that preserves request shape.
pub struct StandIn {
    /// Redirects requests for the declared service origin to this server.
    pub http: Arc<dyn HttpClient>,
    /// Base URL for sending malformed requests directly to the stand-in.
    pub url: Url,
    tasks: Vec<JoinHandle<()>>,
}

impl StandIn {
    /// Start service routes and reject requests intended for any other origin.
    pub async fn start(origin: &'static str, router: Router) -> Self {
        Self::start_many([(origin, router)]).await
    }

    /// Serve independent origins through real loopback HTTP. Paths and queries
    /// are preserved, and undeclared origins are refused before any network IO.
    pub async fn start_many(routes: impl IntoIterator<Item = (&'static str, Router)>) -> Self {
        let mut bases = std::collections::BTreeMap::new();
        let mut tasks = Vec::new();
        for (origin, router) in routes {
            assert!(!bases.contains_key(origin), "duplicate stand-in origin");
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("stand-in listener");
            let base = Url::parse(&format!("http://{}", listener.local_addr().expect("address"))).expect("URL");
            bases.insert(origin, base);
            tasks.push(tokio::spawn(async move { axum::serve(listener, router).await.expect("stand-in server") }));
        }
        let url = bases.values().next().expect("at least one origin").clone();
        Self { http: Arc::new(Redirect { bases }), url, tasks }
    }
}

impl Drop for StandIn {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

struct Redirect {
    bases: std::collections::BTreeMap<&'static str, Url>,
}

#[async_trait]
impl HttpClient for Redirect {
    async fn execute(&self, mut request: reqwest::Request, label: &ChannelLabel) -> Result<http::Response<Bytes>, String> {
        let origin = request.url().origin().ascii_serialization();
        let mut url = self.bases.get(origin.as_str()).ok_or_else(|| "undeclared stand-in origin".to_string())?.clone();
        url.set_path(request.url().path());
        url.set_query(request.url().query());
        *request.url_mut() = url;
        tokio::time::timeout(Duration::from_secs(5), ReqwestHttpClient::new().execute(request, label))
            .await
            .map_err(|_| "HTTP contract stand-in request timed out after 5 seconds".to_string())?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::to_bytes, extract::Request, routing::any};
    // Multiple service authorities keep distinct routers and preserve real
    // request headers, encoded query, method and body over the HTTP boundary.
    #[tokio::test]
    async fn multiple_origins_preserve_requests_and_refuse_unknown() {
        rigging_tls::install_default_provider();
        let router = || {
            Router::new().fallback(any(|r: Request| async move {
                let (parts, body) = r.into_parts();
                assert_eq!(parts.method, "POST");
                assert_eq!(parts.uri.to_string(), "/x?labels=%7B%22a%22%3A%22b%22%7D");
                assert_eq!(parts.headers["authorization"], "Bearer synthetic");
                to_bytes(body, 1024).await.unwrap()
            }))
        };
        let server = StandIn::start_many([
            ("https://one.invalid", router()),
            ("https://two.invalid", Router::new().fallback(any(|| async { "two" }))),
        ])
        .await;
        let client = reqwest::Client::new();
        let req = client
            .post("https://one.invalid/x?labels=%7B%22a%22%3A%22b%22%7D")
            .header("authorization", "Bearer synthetic")
            .body("one")
            .build()
            .unwrap();
        let label = ChannelLabel::Http("multi-origin".into());
        assert_eq!(server.http.execute(req, &label).await.unwrap().body().as_ref(), b"one");
        let req = client.get("https://two.invalid/").build().unwrap();
        assert_eq!(server.http.execute(req, &label).await.unwrap().body().as_ref(), b"two");
        let req = client.get("https://unknown.invalid/").build().unwrap();
        assert!(server.http.execute(req, &label).await.is_err());
    }
}
