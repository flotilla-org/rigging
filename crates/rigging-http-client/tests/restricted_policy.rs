use rigging_http_client::{HttpClient, ReqwestHttpClient, http_channel_label};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

// Real HTTP proxy stand-in: client requests use the supervisor transport and
// a redirect remains a response, rather than silently making another upstream call.
#[tokio::test]
async fn supervisor_proxy_and_no_redirects() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept()).await.unwrap().unwrap();
        let mut io = BufReader::new(socket);
        let mut head = String::new();
        loop {
            let mut line = String::new();
            io.read_line(&mut line).await.unwrap();
            if line == "\r\n" {
                break;
            }
            head.push_str(&line);
        }
        io.write_all(
            b"HTTP/1.1 302 Found\r\nLocation: http://upstream.invalid/elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        head
    });
    let client = ReqwestHttpClient::restricted(Some(&format!("http://{address}")), None).unwrap();
    let request = reqwest::Request::new(reqwest::Method::GET, "http://upstream.invalid/resource".parse().unwrap());
    let response = client.execute(request, &http_channel_label("GET", "http://upstream.invalid/resource")).await.unwrap();
    assert_eq!(response.status(), 302);
    assert!(server.await.unwrap().starts_with("GET http://upstream.invalid/resource HTTP/1.1\r\n"));
}

// Invalid transport configuration is refused without including input contents.
#[test]
fn invalid_ca_and_proxy_are_redacted() {
    assert!(ReqwestHttpClient::restricted(None, Some(b"invalid secret-looking PEM")).is_err());
    let error = match ReqwestHttpClient::restricted(Some("http://[secret"), None) {
        Err(error) => error,
        Ok(_) => panic!("invalid proxy accepted"),
    };
    assert!(!error.contains("secret"));
}

// Additional valid roots are accepted; empty bundles fail instead of silently
// keeping only built-in roots. The checked-in certificate contains no private key.
#[test]
fn valid_and_empty_ca_bundles() {
    assert!(ReqwestHttpClient::restricted(None, Some(include_bytes!("test-ca.pem"))).is_ok());
    assert!(ReqwestHttpClient::restricted(None, Some(b"")).is_err());
}

// A connection closed without a response produces one failure, with no second
// connection within the 200ms observation window. This stand-in is the failing upstream network seam.
#[tokio::test]
async fn failed_upstream_has_no_immediate_retry() {
    use std::time::Duration;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept()).await.unwrap().unwrap();
        let mut reader = BufReader::new(socket);
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            if line == "\r\n" {
                break;
            }
        }
        drop(reader);
        assert!(tokio::time::timeout(Duration::from_millis(200), listener.accept()).await.is_err(), "unexpected retry connection");
    });
    let client = ReqwestHttpClient::restricted(None, None).unwrap();
    let url = format!("http://{address}/failure");
    let request = reqwest::Request::new(reqwest::Method::GET, url.parse().unwrap());
    assert!(
        tokio::time::timeout(Duration::from_secs(2), client.execute(request, &http_channel_label("GET", &url))).await.unwrap().is_err()
    );
    tokio::time::timeout(Duration::from_secs(2), server).await.unwrap().unwrap();
}
