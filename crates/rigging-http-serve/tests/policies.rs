#![cfg(unix)]
use axum::{Extension, Router, routing::any};
use rigging_http_serve::{Authentication, Caller, TcpPolicy, serve_unix_connection};
use std::{future::pending, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixStream},
};

fn router() -> Router {
    Router::new().fallback(any(|Extension(caller): Extension<Caller<String>>| async move { format!("{caller:?}") }))
}
async fn request(policy: TcpPolicy<String>, method: &str, host: &str, headers: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let task = tokio::spawn(policy.serve_connection(server, router(), pending()));
    client
        .write_all(
            format!("{method} /fallback HTTP/1.1\r\nHost: {host}\r\n{headers}Connection: close\r\nContent-Length: 0\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(3), client.read_to_string(&mut response)).await.unwrap().unwrap();
    task.await.unwrap().unwrap();
    response
}

// Consumer sessions must produce their custom identity on accepted connections.
// Generate all method/Origin/upgrade combinations, with invalid/empty/duplicate
// authorities and session credentials. Cookie-dependent unsafe requests and
// upgrades require the matching Origin; ordinary GET remains compatible.
#[tokio::test]
async fn consumer_policy_matrix() {
    let policy = TcpPolicy::new(["localhost:1234".into(), "127.0.0.1:1234".into()], |req| {
        (req.headers().get("cookie")?.to_str().ok()? == "session=valid")
            .then(|| Authentication { caller: Caller::Custom("session-user".to_owned()), uses_cookie: true })
    });
    for method in ["GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE", "PATCH"] {
        for origin in [
            "",
            "Origin: http://localhost:1234\r\n",
            "Origin: null\r\n",
            "Origin: http://localhost:1234\r\nOrigin: http://localhost:1234\r\n",
        ] {
            for upgrade in ["", "Upgrade: websocket\r\n"] {
                let response =
                    request(policy.clone(), method, "localhost:1234", &format!("Cookie: session=valid\r\n{origin}{upgrade}")).await;
                let safe = matches!(method, "GET" | "HEAD" | "OPTIONS");
                let permitted = origin == "Origin: http://localhost:1234\r\n" || (origin.is_empty() && safe && upgrade.is_empty());
                assert!(
                    response.starts_with(if permitted { "HTTP/1.1 200" } else { "HTTP/1.1 403" }),
                    "{method}, {origin:?}, {upgrade:?}: {response}"
                );
                if permitted && method != "HEAD" {
                    assert!(response.ends_with("Custom(\"session-user\")"), "{response}");
                }
            }
        }
    }
    for host in ["evil:1234", "localhost:1235", "", "localhost:1234\r\nHost: localhost:1234"] {
        assert!(request(policy.clone(), "GET", host, "Cookie: session=valid\r\n").await.starts_with("HTTP/1.1 421"));
    }
    for credentials in ["", "Cookie: session=invalid\r\n"] {
        assert!(request(policy.clone(), "GET", "localhost:1234", credentials).await.starts_with("HTTP/1.1 401"));
    }
    assert!(
        request(policy, "GET", "127.0.0.1:1234", "Cookie: session=valid\r\nOrigin: http://127.0.0.1:1234\r\n")
            .await
            .ends_with("Custom(\"session-user\")")
    );
}

// Built-in policies preserve bearer precedence and cookie GET compatibility,
// enforce cookie Origin on POST/upgrades, and support bearer-only consumers.
#[tokio::test]
async fn token_modes() {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(b"secret").into();
    for cookies in [true, false] {
        let policy = if cookies {
            TcpPolicy::token_or_cookie(["local:80".into()], digest)
        } else {
            TcpPolicy::bearer_only(["local:80".into()], digest)
        };
        for (method, headers, cookie_status) in [
            ("GET", "Cookie: rigging_token=secret\r\n", 200),
            ("POST", "Cookie: rigging_token=secret\r\n", 403),
            ("GET", "Cookie: rigging_token=secret\r\nUpgrade: websocket\r\n", 403),
            ("POST", "Cookie: rigging_token=secret\r\nOrigin: http://local:80\r\n", 200),
            ("POST", "Authorization: Bearer secret\r\nCookie: rigging_token=secret\r\n", 200),
            ("GET", "Authorization: Bearer wrong\r\nCookie: rigging_token=secret\r\n", 401),
        ] {
            let expected = if !cookies && !headers.contains("Authorization:") { 401 } else { cookie_status };
            let response = request(policy.clone(), method, "local:80", headers).await;
            assert!(response.starts_with(&format!("HTTP/1.1 {expected}")), "{response}");
        }
    }
}

// Accepted Unix connections map actual kernel credentials to consumer identities
// and protect fallback routes without owning or binding a listener.
#[tokio::test]
async fn accepted_unix_identity() {
    let (mut client, server) = UnixStream::pair().unwrap();
    let task = tokio::spawn(serve_unix_connection(
        server,
        router(),
        |peer| {
            // SAFETY: geteuid has no preconditions.
            assert_eq!(peer.uid, unsafe { libc::geteuid() });
            Caller::Custom("environment".to_owned())
        },
        pending(),
    ));
    client.write_all(b"GET /fallback HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(3), client.read_to_string(&mut response)).await.unwrap().unwrap();
    assert!(response.ends_with("Custom(\"environment\")"), "{response}");
    task.await.unwrap().unwrap();
}

// A protocol multiplexer may inspect a buffered first byte without losing it;
// kernel identity captured before wrapping still reaches the route.
#[tokio::test]
async fn buffered_unix_connection() {
    use rigging_http_serve::UnixConnectionPolicy;
    use tokio::io::{AsyncBufReadExt, BufStream};
    let (mut client, server) = UnixStream::pair().unwrap();
    let policy = UnixConnectionPolicy::new(&server, Caller::<String>::Unix).unwrap();
    client.write_all(b"GET / HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut buffered = BufStream::new(server);
    assert_eq!(buffered.fill_buf().await.unwrap()[0], b'G');
    let task = tokio::spawn(policy.serve_connection(buffered, router(), pending()));
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(3), client.read_to_string(&mut response)).await.unwrap().unwrap();
    assert!(response.contains("Unix(PeerCredentials"), "{response}");
    task.await.unwrap().unwrap();
}

// Accepted-connection serving retains Hyper upgrade metadata: an authenticated
// browser WebSocket handshake must reach axum's upgrade extractor successfully.
#[tokio::test]
async fn websocket_upgrade() {
    use axum::{extract::WebSocketUpgrade, routing::get};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let policy = TcpPolicy::new(["local:80".into()], |_| Some(Authentication { caller: Caller::<()>::Cookie, uses_cookie: true }));
    let app = Router::new().route("/", get(|ws: WebSocketUpgrade| async { ws.on_upgrade(|_| async {}) }));
    let task = tokio::spawn(policy.serve_connection(server, app, pending()));
    client.write_all(b"GET / HTTP/1.1\r\nHost: local:80\r\nOrigin: http://local:80\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").await.unwrap();
    let mut bytes = [0; 1024];
    let n = tokio::time::timeout(Duration::from_secs(3), client.read(&mut bytes)).await.unwrap().unwrap();
    assert!(std::str::from_utf8(&bytes[..n]).unwrap().starts_with("HTTP/1.1 101"));
    task.await.unwrap().unwrap();
}

// The listener entry point applies the same configurable authority policy as
// accepted connections, retaining the generated token and shutdown lifecycle.
#[tokio::test]
async fn configured_listener() {
    use rigging_http_serve::TcpServer;
    use tokio::sync::oneshot;
    let dir = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let token_path = dir.path().join("token");
    let server = TcpServer::bind("127.0.0.1:0".parse().unwrap(), &token_path).await.unwrap();
    let address = server.local_addr().unwrap();
    let policy = server.bearer_only_policy::<String>().with_authorities([format!("localhost:{}", address.port())]);
    let token = std::fs::read_to_string(token_path).unwrap();
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(server.serve_with_policy(router(), policy, async {
        let _ = stopped.await;
    }));
    for (host, status) in [(format!("localhost:{}", address.port()), 200), (address.to_string(), 421)] {
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = String::new();
        tokio::time::timeout(Duration::from_secs(3), client.read_to_string(&mut response)).await.unwrap().unwrap();
        assert!(response.starts_with(&format!("HTTP/1.1 {status}")), "{response}");
    }
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

// Shutdown of a single accepted connection drains an admitted request before
// completing, just like listener shutdown.
#[tokio::test]
async fn accepted_connection_shutdown_drains() {
    use std::sync::Arc;
    use tokio::sync::{Notify, oneshot};
    let (client, server) = UnixStream::pair().unwrap();
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let app = Router::new().fallback(any({
        let entered = entered.clone();
        let release = release.clone();
        move || {
            let entered = entered.clone();
            let release = release.clone();
            async move {
                entered.notify_one();
                release.notified().await;
                "finished"
            }
        }
    }));
    let (stop, stopped) = oneshot::channel();
    let mut task = tokio::spawn(serve_unix_connection(server, app, Caller::<()>::Unix, async {
        let _ = stopped.await;
    }));
    let client = tokio::spawn(async move {
        let mut client = client;
        client.write_all(b"GET / HTTP/1.1\r\nHost: local\r\n\r\n").await.unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        response
    });
    tokio::time::timeout(Duration::from_secs(3), entered.notified()).await.unwrap();
    stop.send(()).unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(30), &mut task).await.is_err());
    release.notify_one();
    assert!(tokio::time::timeout(Duration::from_secs(3), client).await.unwrap().unwrap().ends_with("finished"));
    tokio::time::timeout(Duration::from_secs(3), task).await.unwrap().unwrap().unwrap();
}
