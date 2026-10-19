use async_trait::async_trait;
pub use rigging_process::{
    http_channel_label, http_channel_label_with, ChannelLabel, ChannelLabeler, ChannelRequest, DefaultLabeler, TaskId,
    REPLAY_LABELS_ENABLED,
};
use std::path::Path;

/// Execute an HTTP request with an automatically derived channel label.
#[macro_export]
macro_rules! http_execute {
    ($http:expr, $request:expr, $labeler:expr $(,)?) => {{
        let __request = $request;
        let __label = $crate::http_channel_label_with::<{ $crate::REPLAY_LABELS_ENABLED }, _>(
            __request.method().as_str(),
            __request.url().as_str(),
            &$labeler,
        );
        $http.execute(__request, &__label).await
    }};
    ($http:expr, $request:expr $(,)?) => {{
        let __request = $request;
        let __label = $crate::http_channel_label(__request.method().as_str(), __request.url().as_str());
        $http.execute(__request, &__label).await
    }};
}

/// Trait abstracting HTTP request execution so providers can be tested
/// without making real network calls.
///
/// Uses reqwest::Request as input (callers build with the reqwest builder API)
/// and returns http::Response<bytes::Bytes> (the standard Rust HTTP type that
/// reqwest is built on, trivially constructable in tests).
#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn execute(&self, request: reqwest::Request, label: &ChannelLabel) -> Result<http::Response<bytes::Bytes>, String>;

    /// Stream a response body to a file. Test clients may use the buffered
    /// `execute` implementation; production overrides this to bound memory.
    async fn execute_to_file(&self, request: reqwest::Request, label: &ChannelLabel, path: &Path) -> Result<http::StatusCode, String> {
        let response = self.execute(request, label).await?;
        let status = response.status();
        if status.is_success() {
            tokio::fs::write(path, response.body()).await.map_err(|error| error.to_string())?;
        }
        Ok(status)
    }
}

/// Production implementation that delegates to `reqwest::Client`.
pub struct ReqwestHttpClient {
    client: reqwest::Client,
}

impl ReqwestHttpClient {
    pub fn new() -> Self {
        const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
        let client = rigging_tls::client_builder().timeout(REQUEST_TIMEOUT).build().expect("build HTTP client");
        Self { client }
    }
}

impl Default for ReqwestHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HttpClient for ReqwestHttpClient {
    async fn execute(&self, request: reqwest::Request, _label: &ChannelLabel) -> Result<http::Response<bytes::Bytes>, String> {
        let resp = self.client.execute(request).await.map_err(|e| e.to_string())?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.bytes().await.map_err(|e| e.to_string())?;
        let mut builder = http::Response::builder().status(status);
        for (name, value) in headers.iter() {
            builder = builder.header(name, value);
        }
        builder.body(body).map_err(|e| e.to_string())
    }

    async fn execute_to_file(&self, request: reqwest::Request, _label: &ChannelLabel, path: &Path) -> Result<http::StatusCode, String> {
        use tokio::io::AsyncWriteExt;
        let mut response = self.client.execute(request).await.map_err(|error| error.to_string())?;
        let status = response.status();
        if status.is_success() {
            let mut file = tokio::fs::File::create(path).await.map_err(|error| error.to_string())?;
            while let Some(chunk) = response.chunk().await.map_err(|error| error.to_string())? {
                file.write_all(&chunk).await.map_err(|error| error.to_string())?;
            }
            file.flush().await.map_err(|error| error.to_string())?;
        }
        Ok(status)
    }
}
