#![cfg(unix)]
use axum::{Extension, Router, routing::get};
use rigging_http_serve::{Caller, TcpServer, UnixServer};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UnixStream},
    sync::oneshot,
};

async fn exchange(mut stream: impl AsyncRead + AsyncWrite + Unpin, headers: &str) -> String {
    stream.write_all(format!("GET / HTTP/1.1\r\n{headers}Connection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_string(&mut response)).await.unwrap().unwrap();
    response
}
fn router() -> Router {
    Router::new().route("/", get(|Extension(caller): Extension<Caller<String>>| async move { format!("{caller:?}") }))
}

// One router must see kernel credentials over Unix and authenticated typed
// identities over TCP. Generate the cross product of credential and web-policy
// cases, including duplicate, missing, empty, and malformed headers.
#[tokio::test]
async fn one_router_two_real_listeners() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.path().join("http.sock");
    let token_path = dir.path().join("token");
    fs::write(&token_path, "previous-secret").unwrap();
    let old_inode = fs::metadata(&token_path).unwrap().ino();
    let unix = UnixServer::bind(&socket, 0o600).await.unwrap();
    assert_eq!(fs::metadata(&socket).unwrap().mode() & 0o777, 0o600);
    let tcp = TcpServer::bind("127.0.0.1:0".parse().unwrap(), &token_path).await.unwrap();
    let address = tcp.local_addr().unwrap();
    let token = fs::read_to_string(&token_path).unwrap();
    assert_eq!(token.len(), 64);
    assert_ne!(token, "previous-secret");
    assert_ne!(old_inode, fs::metadata(&token_path).unwrap().ino());
    assert_eq!(fs::metadata(&token_path).unwrap().mode() & 0o777, 0o600);
    let app = router();
    let (unix_stop, stopped) = oneshot::channel();
    let unix_task = tokio::spawn(unix.serve(app.clone(), Caller::<String>::Unix, async {
        let _ = stopped.await;
    }));
    let (tcp_stop, stopped) = oneshot::channel();
    let tcp_task = tokio::spawn(tcp.serve::<String, _>(app, async {
        let _ = stopped.await;
    }));
    let response = exchange(UnixStream::connect(&socket).await.unwrap(), "Host: local\r\n").await;
    // SAFETY: getuid/getgid have no preconditions.
    assert!(response.contains(&format!("uid: {}", unsafe { libc::getuid() })), "{response}");
    assert!(response.contains(&format!("gid: {}", unsafe { libc::getgid() })));
    #[cfg(target_os = "linux")]
    assert!(response.contains(&format!("pid: Some({})", std::process::id())));
    let credentials = [
        (format!("Authorization: Bearer {token}\r\n"), 200, "Bearer"),
        (format!("Authorization: bearer {token}\r\n"), 200, "Bearer"),
        (format!("Authorization: bEaReR {token}\r\n"), 200, "Bearer"),
        (format!("Authorization: Basic {token}\r\n"), 401, ""),
        (format!("Authorization: Bearer  {token}\r\n"), 401, ""),
        (format!("Authorization: Bearer {token}\r\nAuthorization: Bearer wrong\r\n"), 401, ""),
        (format!("Cookie: rigging_token={token}\r\nCookie: rigging_token=wrong\r\n"), 401, ""),
        (format!("Authorization: Bearer wrong\r\nCookie: rigging_token={token}\r\n"), 401, ""),
        (format!("Cookie: other=x; rigging_token={token}\r\n"), 200, "Cookie"),
        ("Authorization: Bearer wrong\r\n".into(), 401, ""),
        ("Cookie: rigging_token=wrong\r\n".into(), 401, ""),
        ("Cookie: rigging_token=\r\n".into(), 401, ""),
        ("Authorization: Bearer \r\n".into(), 401, ""),
        ("".into(), 401, ""),
        (format!("Authorization: Bearer {token}\r\nAuthorization: Bearer {token}\r\n"), 401, ""),
        (format!("Cookie: rigging_token={token}; rigging_token={token}\r\n"), 401, ""),
        (format!("Authorization: invalid\r\nCookie: rigging_token={token}\r\n"), 401, ""),
    ];
    for (auth, authenticated_status, identity) in credentials {
        for (host, origin, allowed) in [
            (address.to_string(), String::new(), true),
            (address.to_string(), format!("Origin: http://{address}\r\n"), true),
            ("evil.example".into(), String::new(), false),
            (address.to_string(), "Origin: https://evil.example\r\n".into(), false),
            (address.to_string(), "Origin: null\r\n".into(), false),
            (format!("{address}\r\nHost: evil.example"), String::new(), false),
            (address.to_string(), format!("Origin: http://{address}\r\nOrigin: http://evil.example\r\n"), false),
            (address.to_string(), format!("Origin: http://{address}\r\nOrigin: http://{address}\r\n"), false),
        ] {
            let response = exchange(TcpStream::connect(address).await.unwrap(), &format!("Host: {host}\r\n{origin}{auth}")).await;
            let expected = if host != address.to_string() {
                421
            } else if allowed {
                authenticated_status
            } else {
                403
            };
            assert!(response.starts_with(&format!("HTTP/1.1 {expected}")), "{response}");
            if expected == 200 {
                assert!(response.ends_with(identity), "{response}");
            }
        }
    }
    unix_stop.send(()).unwrap();
    tcp_stop.send(()).unwrap();
    unix_task.await.unwrap().unwrap();
    tcp_task.await.unwrap().unwrap();
    assert!(!socket.exists());
    let restarted = TcpServer::bind(address, &token_path).await.unwrap();
    assert_ne!(token, fs::read_to_string(&token_path).unwrap());
    drop(restarted);
}

// Socket lifecycle: reclaim only refused sockets; preserve live sockets,
// ordinary files, symlinks, and paths replaced after bind. Reject public parents.
#[tokio::test]
async fn socket_hygiene_and_custom_identity() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("http.sock");
    // Invalid modes must fail before creating or removing an endpoint.
    for mode in [0o1000, 0o1777, u32::MAX] {
        let error = UnixServer::bind(&path, mode).await.err().unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(!path.exists());
    }
    assert!(TcpServer::bind("0.0.0.0:0".parse().unwrap(), dir.path().join("token")).await.is_err());
    drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
    let server = UnixServer::bind(&path, 0o600).await.unwrap();
    assert!(UnixServer::bind(&path, 0o600).await.is_err());
    assert!(path.exists());
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(server.serve(router(), |_| Caller::Custom("environment-7".to_owned()), async {
        let _ = stopped.await;
    }));
    let response = exchange(UnixStream::connect(&path).await.unwrap(), "Host: local\r\n").await;
    assert!(response.ends_with("Custom(\"environment-7\")"), "{response}");
    // Replace the pathname while the original listener is alive: cleanup must
    // preserve this different socket inode.
    fs::remove_file(&path).unwrap();
    let replacement = std::os::unix::net::UnixListener::bind(&path).unwrap();
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
    assert!(path.exists());
    drop(replacement);
    fs::remove_file(&path).unwrap();
    fs::write(&path, "keep").unwrap();
    assert!(UnixServer::bind(&path, 0o600).await.is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), "keep");
    let link = dir.path().join("link");
    symlink(&path, &link).unwrap();
    assert!(UnixServer::bind(&link, 0o600).await.is_err());
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(UnixServer::bind(dir.path().join("new"), 0o600).await.is_err());
    assert!(TcpServer::bind("127.0.0.1:0".parse().unwrap(), dir.path().join("token")).await.is_err());
    assert!(TcpServer::bind("0.0.0.0:0".parse().unwrap(), dir.path().join("token")).await.is_err());
}

// Shutdown must wait for an admitted request to finish, preserving its response.
#[tokio::test]
async fn graceful_shutdown_drains_requests() {
    use std::sync::Arc;
    use tokio::sync::Notify;
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("http.sock");
    let server = UnixServer::bind(&path, 0o600).await.unwrap();
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let app = Router::new().route(
        "/",
        get({
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
        }),
    );
    let (stop, stopped) = oneshot::channel();
    let mut task = tokio::spawn(server.serve(app, Caller::<()>::Unix, async {
        let _ = stopped.await;
    }));
    let client = tokio::spawn(async move { exchange(UnixStream::connect(path).await.unwrap(), "Host: local\r\n").await });
    tokio::time::timeout(Duration::from_secs(3), entered.notified()).await.unwrap();
    stop.send(()).unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(30), &mut task).await.is_err());
    release.notify_one();
    assert!(client.await.unwrap().ends_with("finished"));
    tokio::time::timeout(Duration::from_secs(3), task).await.unwrap().unwrap().unwrap();
}

// Atomic token replacement must replace a symlink without modifying its target;
// IPv6 uses the bound bracketed authority for the same web policy as IPv4.
#[tokio::test]
async fn ipv6_and_token_symlink_replacement() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let target = dir.path().join("preserve");
    fs::write(&target, "untouched").unwrap();
    let token_path = dir.path().join("token");
    symlink(&target, &token_path).unwrap();
    let tcp = TcpServer::bind("[::1]:0".parse().unwrap(), &token_path).await.unwrap();
    let address = tcp.local_addr().unwrap();
    assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
    assert!(!fs::symlink_metadata(&token_path).unwrap().file_type().is_symlink());
    let token = fs::read_to_string(&token_path).unwrap();
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(tcp.serve::<String, _>(router(), async {
        let _ = stopped.await;
    }));
    for (headers, expected) in [
        (format!("Host: {address}\r\nOrigin: http://{address}\r\n"), 200),
        (format!("Host: {address}\r\nHost: {address}\r\n"), 421),
        (String::new(), 421),
        ("Host: localhost\r\n".into(), 421),
        (format!("Host: {address}\r\nOrigin: https://{address}\r\n"), 403),
    ] {
        let response = exchange(TcpStream::connect(address).await.unwrap(), &format!("{headers}Authorization: Bearer {token}\r\n")).await;
        assert!(response.starts_with(&format!("HTTP/1.1 {expected}")), "{response}; expected={expected}, headers={headers:?}");
    }
    // The middleware also protects the router's fallback routes.
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(format!("GET /missing HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_string(&mut response)).await.unwrap().unwrap();
    assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}
