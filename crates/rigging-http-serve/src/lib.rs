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
    /// the private parent prevents access during bind/chmod.
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
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    fn local_addr(&self) -> io::Result<Self::Addr> {
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

    /// Accept a bearer token or `rigging_token` cookie. Host must equal the bound
    /// numeric authority (including port); Origin may be absent, otherwise it
    /// must equal `http://{authority}`. No CORS or cookie issuance is provided.
    pub async fn serve<C, F>(self, router: Router, shutdown: F) -> io::Result<()>
    where
        C: Clone + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        let Self { listener, token_hash, authority } = self;
        let router = router.layer(middleware::from_fn(move |mut request: Request, next: Next| {
            let authority = authority.clone();
            async move {
                let headers = request.headers();
                let single = |name| {
                    let mut values = headers.get_all(name).iter();
                    let value = values.next()?.to_str().ok()?;
                    if values.next().is_some() { None } else { Some(value) }
                };
                if single(header::HOST) != Some(authority.as_str())
                    || (headers.contains_key(header::ORIGIN) && single(header::ORIGIN) != Some(format!("http://{authority}").as_str()))
                {
                    return Response::builder().status(StatusCode::FORBIDDEN).body(axum::body::Body::empty()).unwrap();
                }
                let valid = |token: &str| bool::from(token_hash.ct_eq(&Sha256::digest(token.as_bytes())));
                let caller = if headers.contains_key(header::AUTHORIZATION) {
                    single(header::AUTHORIZATION).and_then(|v| v.strip_prefix("Bearer ")).filter(|v| valid(v)).map(|_| Caller::<C>::Bearer)
                } else {
                    let mut tokens = headers
                        .get_all(header::COOKIE)
                        .iter()
                        .filter_map(|v| v.to_str().ok())
                        .flat_map(|v| v.split(';'))
                        .filter_map(|v| v.trim().strip_prefix("rigging_token="));
                    let first = tokens.next();
                    if tokens.next().is_none() { first.filter(|v| valid(v)).map(|_| Caller::<C>::Cookie) } else { None }
                };
                match caller {
                    Some(caller) => {
                        request.extensions_mut().insert(caller);
                        next.run(request).await
                    }
                    None => Response::builder().status(StatusCode::UNAUTHORIZED).body(axum::body::Body::empty()).unwrap(),
                }
            }
        }));
        axum::serve(listener, router).with_graceful_shutdown(shutdown).await
    }
}
