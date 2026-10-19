//! Local HTTP listeners with transport-independent caller identities.
//!
//! Bind inside an existing private directory owned by the current user. Ancestors
//! must also be trusted: this crate does not defend against the owning user
//! replacing paths concurrently. Clone one router for both listeners; routes
//! extract `Extension<Caller<MyIdentity>>`. Authentication is installed outside
//! the router, including fallback routes. Shutdown stops accepting and drains
//! in-flight HTTP requests using axum's graceful shutdown.
#![cfg(unix)]
#![doc = include_str!("../README.md")]

use axum::{
    Router,
    extract::{ConnectInfo, Request, connect_info::Connected},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::Response,
    serve::{IncomingStream, Listener},
};
use hyper::server::conn::http1;
use sha2::{Digest, Sha256};
use std::{
    fs,
    future::Future,
    io::{self, Write},
    net::SocketAddr,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::net::{TcpListener, UnixListener, UnixStream};

/// Kernel credentials, never inferred from HTTP headers. PID is unavailable on
/// platforms where the kernel exposes only getpeereid (including macOS).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCredentials {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<i32>,
}

/// Consumers can carry an application identity without teaching routes about
/// listeners. A Unix identity mapper may return `Custom` for environment sockets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caller<C = ()> {
    Unix(PeerCredentials),
    Bearer,
    Cookie,
    Custom(C),
}

fn private_parent(path: &Path) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| io::Error::other("path needs a private parent"))?;
    let meta = fs::symlink_metadata(parent)?;
    // SAFETY: geteuid has no preconditions.
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "parent must be private and owned by this user"));
    }
    Ok(())
}

struct SocketGuard {
    path: PathBuf,
    dev: u64,
    ino: u64,
}
impl SocketGuard {
    fn matches(&self) -> bool {
        fs::symlink_metadata(&self.path).is_ok_and(|m| m.file_type().is_socket() && m.dev() == self.dev && m.ino() == self.ino)
    }
}
impl Drop for SocketGuard {
    fn drop(&mut self) {
        if self.matches() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// A bound Unix endpoint. Dropping it removes only the socket it created.
pub struct UnixServer {
    listener: UnixListener,
    guard: SocketGuard,
}
impl UnixServer {
    /// Refuses live sockets, symlinks and non-sockets. Only a connection-refused
    /// socket in a private parent is considered stale. Mode is set before serving;
    /// the private parent prevents access during bind/chmod. The stale-check/unlink
    /// sequence assumes the owning user does not replace the path concurrently.
    pub async fn bind(path: impl AsRef<Path>, mode: u32) -> io::Result<Self> {
        let path = path.as_ref();
        private_parent(path)?;
        if mode & !0o777 != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid socket mode"));
        }
        match fs::symlink_metadata(path) {
            Ok(meta) => {
                if !meta.file_type().is_socket() {
                    return Err(io::Error::new(io::ErrorKind::AlreadyExists, "path is not a socket"));
                }
                let unchanged = || fs::symlink_metadata(path).is_ok_and(|m| m.dev() == meta.dev() && m.ino() == meta.ino());
                match UnixStream::connect(path).await {
                    Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                        if !unchanged() {
                            return Err(io::Error::other("socket changed during stale check"));
                        }
                        fs::remove_file(path)?;
                    }
                    result => {
                        return Err(result.err().unwrap_or_else(|| io::Error::new(io::ErrorKind::AddrInUse, "socket is live")));
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
        let listener = UnixListener::bind(path)?;
        let meta = fs::symlink_metadata(path)?;
        let guard = SocketGuard { path: path.to_owned(), dev: meta.dev(), ino: meta.ino() };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        Ok(Self { listener, guard })
    }

    /// Map kernel credentials into the same caller type used by the TCP router.
    pub async fn serve<C, M, F>(self, router: Router, identity: M, shutdown: F) -> io::Result<()>
    where
        C: Clone + Send + Sync + 'static,
        M: Fn(PeerCredentials) -> Caller<C> + Clone + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        let Self { listener, guard } = self;
        let router =
            router.layer(middleware::from_fn(move |ConnectInfo(peer): ConnectInfo<PeerCredentials>, mut request: Request, next: Next| {
                let caller = identity(peer);
                async move {
                    request.extensions_mut().insert(caller);
                    next.run(request).await
                }
            }));
        let result = axum::serve(PeerListener(listener), router.into_make_service_with_connect_info::<PeerCredentials>())
            .with_graceful_shutdown(shutdown)
            .await;
        drop(guard);
        result
    }
}

struct PeerListener(UnixListener);
impl Listener for PeerListener {
    type Io = UnixStream;
    type Addr = PeerCredentials;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            if let Ok((stream, _)) = self.0.accept().await
                && let Ok(cred) = stream.peer_cred()
            {
                return (stream, PeerCredentials { uid: cred.uid(), gid: cred.gid(), pid: cred.pid() });
            }
            // Retry transient accept/credential failures, including EMFILE, with
            // backoff rather than failing the server or admitting an unknown peer.
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    fn local_addr(&self) -> io::Result<Self::Addr> {
        // axum 0.8 serving does not require local_addr; Addr here describes peers,
        // not the bound socket. Revisit this assumption when upgrading axum.
        Err(io::Error::new(io::ErrorKind::Unsupported, "listener has no peer credentials"))
    }
}
impl Connected<IncomingStream<'_, PeerListener>> for PeerCredentials {
    fn connect_info(stream: IncomingStream<'_, PeerListener>) -> Self {
        *stream.remote_addr()
    }
}

/// Bound loopback endpoint. Each bind creates and atomically replaces a random
/// 256-bit token file (0600). The token remains on disk after shutdown; the next
/// start rotates it. No secret is exposed through Debug or caller identities.
pub struct TcpServer {
    listener: TcpListener,
    token_hash: [u8; 32],
    authority: String,
}
impl TcpServer {
    /// If token replacement fails, the listener is dropped and the previous
    /// token file remains; it is replaced on the next successful bind.
    pub async fn bind(address: SocketAddr, token_path: impl AsRef<Path>) -> io::Result<Self> {
        if !address.ip().is_loopback() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "TCP address must be loopback"));
        }
        let path = token_path.as_ref();
        private_parent(path)?;
        let listener = TcpListener::bind(address).await?;
        let authority = listener.local_addr()?.to_string();
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
        let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let mut file = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
        file.as_file().set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(token.as_bytes())?;
        file.as_file().sync_all()?;
        file.persist(path).map_err(|e| e.error)?;
        Ok(Self { listener, token_hash: Sha256::digest(token.as_bytes()).into(), authority })
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Construct the default token-or-cookie policy for this listener.
    pub fn policy<C: Clone + Send + Sync + 'static>(&self) -> TcpPolicy<C> {
        TcpPolicy::token_or_cookie([self.authority.clone()], self.token_hash)
    }

    /// Construct a bearer-only policy using this listener's generated token.
    pub fn bearer_only_policy<C: Clone + Send + Sync + 'static>(&self) -> TcpPolicy<C> {
        TcpPolicy::bearer_only([self.authority.clone()], self.token_hash)
    }

    /// Serve with the default token-or-cookie policy.
    pub async fn serve<C, F>(self, router: Router, shutdown: F) -> io::Result<()>
    where
        C: Clone + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        let policy = self.policy::<C>();
        self.serve_with_policy(router, policy, shutdown).await
    }

    /// Serve using an explicitly configured Host and authentication policy.
    pub async fn serve_with_policy<C, F>(self, router: Router, policy: TcpPolicy<C>, shutdown: F) -> io::Result<()>
    where
        C: Clone + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        axum::serve(self.listener, policy.protect(router)).with_graceful_shutdown(shutdown).await
    }
}

/// Authentication result. Set `uses_cookie` whenever admission relies on a
/// browser cookie, including consumer-owned session cookies.
pub struct Authentication<C = ()> {
    pub caller: Caller<C>,
    pub uses_cookie: bool,
}

type Authenticate<C> = dyn Fn(&Request) -> Option<Authentication<C>> + Send + Sync;

/// Reusable TCP request policy, independent of listener ownership.
/// Authorities are exact Host values, including ports and IPv6 brackets.
/// Origin is intentionally limited to `http://{Host}` for direct loopback HTTP;
/// TLS termination and HTTPS origins are not supported.
#[derive(Clone)]
pub struct TcpPolicy<C = ()> {
    authorities: Vec<String>,
    authenticate: std::sync::Arc<Authenticate<C>>,
}

impl<C: Clone + Send + Sync + 'static> TcpPolicy<C> {
    /// Supply consumer authentication, returning None to refuse with 401.
    /// The callback borrows the full request immutably, including method, URI,
    /// headers and extensions, so it can implement login exchanges and session
    /// authentication without splitting and rebuilding the request. It cannot
    /// consume the body. It must be cheap and synchronous.
    ///
    /// Security-critical: return `uses_cookie: true` whenever admission depends
    /// on a cookie, including with `Caller::Custom`. Incorrectly reporting false
    /// bypasses the cookie-dependent Origin requirement.
    pub fn new(
        authorities: impl IntoIterator<Item = String>,
        authenticate: impl Fn(&Request) -> Option<Authentication<C>> + Send + Sync + 'static,
    ) -> Self {
        Self { authorities: authorities.into_iter().collect(), authenticate: std::sync::Arc::new(authenticate) }
    }

    /// Replace the exact accepted Host authorities. An empty list refuses all requests.
    pub fn with_authorities(mut self, authorities: impl IntoIterator<Item = String>) -> Self {
        self.authorities = authorities.into_iter().collect();
        self
    }

    /// Default token-or-cookie authentication using a SHA-256 token digest.
    pub fn token_or_cookie(authorities: impl IntoIterator<Item = String>, token_hash: [u8; 32]) -> Self {
        Self::tokens(authorities, token_hash, true)
    }

    /// Only Authorization: Bearer is accepted; cookies never grant admission.
    pub fn bearer_only(authorities: impl IntoIterator<Item = String>, token_hash: [u8; 32]) -> Self {
        Self::tokens(authorities, token_hash, false)
    }

    fn tokens(authorities: impl IntoIterator<Item = String>, token_hash: [u8; 32], cookies: bool) -> Self {
        Self::new(authorities, move |request| {
            let headers = request.headers();
            let valid = |token: &str| bool::from(token_hash.ct_eq(&Sha256::digest(token.as_bytes())));
            if headers.contains_key(header::AUTHORIZATION) {
                single(headers, header::AUTHORIZATION)
                    .and_then(|v| v.split_once(' '))
                    .filter(|(scheme, token)| scheme.eq_ignore_ascii_case("Bearer") && valid(token))
                    .map(|_| Authentication { caller: Caller::Bearer, uses_cookie: false })
            } else if cookies {
                let mut tokens = headers
                    .get_all(header::COOKIE)
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .flat_map(|v| v.split(';'))
                    .filter_map(|v| v.trim().strip_prefix("rigging_token="));
                let first = tokens.next();
                if tokens.next().is_some() {
                    return None;
                }
                first.filter(|v| valid(v)).map(|_| Authentication { caller: Caller::Cookie, uses_cookie: true })
            } else {
                None
            }
        })
    }

    fn protect(self, router: Router) -> Router {
        router.layer(middleware::from_fn(move |mut request: Request, next: Next| {
            let policy = self.clone();
            async move {
                let headers = request.headers();
                let Some(host) = single(headers, header::HOST).filter(|h| policy.authorities.iter().any(|a| a == h)) else {
                    return refusal(StatusCode::MISDIRECTED_REQUEST);
                };
                let origin_present = headers.contains_key(header::ORIGIN);
                if origin_present && single(headers, header::ORIGIN) != Some(format!("http://{host}").as_str()) {
                    return refusal(StatusCode::FORBIDDEN);
                }
                let Some(authentication) = (policy.authenticate)(&request) else {
                    return refusal(StatusCode::UNAUTHORIZED);
                };
                // Only known safe methods are exempt; unknown methods fail closed.
                let unsafe_method = !matches!(
                    *request.method(),
                    axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS | axum::http::Method::TRACE
                );
                if authentication.uses_cookie && !origin_present && (unsafe_method || headers.contains_key(header::UPGRADE)) {
                    return refusal(StatusCode::FORBIDDEN);
                }
                request.extensions_mut().insert(authentication.caller);
                next.run(request).await
            }
        }))
    }

    /// Serve one accepted connection, including WebSocket upgrades. The stream
    /// may wrap a socket to replay bytes consumed by a protocol multiplexer.
    /// Accept only from a loopback listener: this entry point cannot inspect
    /// the underlying socket address and does not enforce loopback binding.
    pub async fn serve_connection<I, F>(self, stream: I, router: Router, shutdown: F) -> io::Result<()>
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
        F: Future<Output = ()> + Send,
    {
        serve_connection(stream, self.protect(router), shutdown).await
    }
}

fn single(headers: &axum::http::HeaderMap, name: header::HeaderName) -> Option<&str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() { None } else { Some(value) }
}

fn refusal(status: StatusCode) -> Response {
    Response::builder().status(status).body(axum::body::Body::empty()).unwrap()
}

/// Serve an accepted Unix stream with the listener API's kernel identity mapping.
/// Obtain credentials before wrapping or consuming the stream for protocol sniffing.
pub async fn serve_unix_connection<C, M, F>(stream: UnixStream, router: Router, identity: M, shutdown: F) -> io::Result<()>
where
    C: Clone + Send + Sync + 'static,
    M: Fn(PeerCredentials) -> Caller<C> + Clone + Send + Sync + 'static,
    F: Future<Output = ()> + Send,
{
    let policy = UnixConnectionPolicy::new(&stream, identity)?;
    policy.serve_connection(stream, router, shutdown).await
}

/// Capture a Unix peer's kernel identity before wrapping its stream to replay
/// bytes consumed by a protocol multiplexer. Use only with that same connection.
pub struct UnixConnectionPolicy<C = ()> {
    caller: Caller<C>,
}

impl<C: Clone + Send + Sync + 'static> UnixConnectionPolicy<C> {
    pub fn new(stream: &UnixStream, identity: impl FnOnce(PeerCredentials) -> Caller<C>) -> io::Result<Self> {
        let cred = stream.peer_cred()?;
        Ok(Self { caller: identity(PeerCredentials { uid: cred.uid(), gid: cred.gid(), pid: cred.pid() }) })
    }

    /// Serve the connection whose credentials were captured by `new`, optionally
    /// wrapped in an application-owned buffered stream. Shutdown drains requests;
    /// the consumer owns upgraded sessions.
    pub async fn serve_connection<I, F>(self, stream: I, router: Router, shutdown: F) -> io::Result<()>
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
        F: Future<Output = ()> + Send,
    {
        serve_connection(stream, router.layer(axum::Extension(self.caller)), shutdown).await
    }
}

async fn serve_connection<I, F>(stream: I, router: Router, shutdown: F) -> io::Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    F: Future<Output = ()> + Send,
{
    let connection = http1::Builder::new()
        .serve_connection(hyper_util::rt::TokioIo::new(stream), hyper_util::service::TowerToHyperService::new(router))
        .with_upgrades();
    tokio::pin!(connection);
    tokio::pin!(shutdown);
    tokio::select! {
        result = &mut connection => result.map_err(io::Error::other),
        () = &mut shutdown => {
            connection.as_mut().graceful_shutdown();
            connection.await.map_err(io::Error::other)
        }
    }
}
