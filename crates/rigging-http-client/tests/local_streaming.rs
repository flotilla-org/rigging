#![cfg(unix)]

use async_trait::async_trait;
use bytes::Bytes;
use rigging_http_client::{ChannelLabel, HttpClient, ReqwestHttpClient, StreamingBody, http_channel_label};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::oneshot;
use tokio::time::timeout;

// A local client reaches its socket whatever the URL's host, and a streamed body yields each
// chunk as the server writes it: the second chunk is held back until the first has arrived.
#[tokio::test]
async fn a_local_stream_yields_chunks_as_they_are_written() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("endpoint.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let (first_read, wait_first) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut io = BufReader::new(stream);
        let mut head = String::new();
        loop {
            let mut line = String::new();
            io.read_line(&mut line).await.unwrap();
            if line == "\r\n" {
                break;
            }
            head.push_str(&line);
        }
        io.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/jsonl\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nfirst\n\r\n")
            .await
            .unwrap();
        io.flush().await.unwrap();
        wait_first.await.unwrap();
        io.write_all(b"7\r\nsecond\n\r\n0\r\n\r\n").await.unwrap();
        head
    });
    let client = ReqwestHttpClient::local(&socket).unwrap();
    let url = "http://endpoint/threads/t1/events";
    let request = reqwest::Request::new(reqwest::Method::GET, url.parse().unwrap());
    let response = client.execute_streaming(request, &http_channel_label("GET", url)).await.unwrap();
    assert_eq!(response.headers()["content-type"], "application/jsonl");
    let mut body = response.into_body();
    let chunk = timeout(Duration::from_secs(2), body.chunk()).await.expect("first chunk before the rest is written").unwrap();
    assert_eq!(chunk.as_deref(), Some(&b"first\n"[..]));
    first_read.send(()).unwrap();
    assert_eq!(body.chunk().await.unwrap().as_deref(), Some(&b"second\n"[..]));
    assert_eq!(body.chunk().await.unwrap(), None);
    assert!(server.await.unwrap().starts_with("GET /threads/t1/events HTTP/1.1\r\n"));
}

struct Canned;

#[async_trait]
impl HttpClient for Canned {
    async fn execute(&self, _: reqwest::Request, _: &ChannelLabel) -> Result<http::Response<Bytes>, String> {
        Ok(http::Response::new(Bytes::from_static(b"whole")))
    }
}

// A client that only buffers still streams: its body comes as one chunk.
#[tokio::test]
async fn a_buffered_client_streams_its_body_as_one_chunk() {
    let url = "http://endpoint/";
    let request = reqwest::Request::new(reqwest::Method::GET, url.parse().unwrap());
    let mut body = Canned.execute_streaming(request, &http_channel_label("GET", url)).await.unwrap().into_body();
    assert_eq!(body.chunk().await.unwrap().as_deref(), Some(&b"whole"[..]));
    assert_eq!(body.chunk().await.unwrap(), None);
    let mut empty = StreamingBody::from(Bytes::new());
    assert_eq!(empty.chunk().await.unwrap(), None);
}
