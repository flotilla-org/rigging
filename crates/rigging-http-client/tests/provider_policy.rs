use rigging_http_client::{HttpClient, ReqwestHttpClient, http_channel_label};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

// Real HTTP proxy stand-in: provider requests use the supervisor transport and
// a redirect remains a response, rather than silently making another vendor call.
#[tokio::test]
async fn supervisor_proxy_and_no_redirects() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
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
        io.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://vendor.invalid/elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        head
    });
    let client = ReqwestHttpClient::for_provider(Some(&format!("http://{address}")), None).unwrap();
    let request = reqwest::Request::new(reqwest::Method::GET, "http://vendor.invalid/resource".parse().unwrap());
    let response = client.execute(request, &http_channel_label("GET", "http://vendor.invalid/resource")).await.unwrap();
    assert_eq!(response.status(), 302);
    assert!(server.await.unwrap().starts_with("GET http://vendor.invalid/resource HTTP/1.1\r\n"));
}

// Invalid transport configuration is refused without including input contents.
#[test]
fn invalid_ca_and_proxy_are_redacted() {
    assert!(ReqwestHttpClient::for_provider(None, Some(b"invalid secret-looking PEM")).is_err());
    let error = match ReqwestHttpClient::for_provider(Some("http://[secret"), None) {
        Err(error) => error,
        Ok(_) => panic!("invalid proxy accepted"),
    };
    assert!(!error.contains("secret"));
}
