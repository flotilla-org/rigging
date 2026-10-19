# rigging-http-serve

Serve clones of one axum 0.8 router over Unix sockets and loopback TCP.
Routes extract `axum::Extension<Caller<C>>`; the listener installs the caller
before any route or fallback executes. `C` is a consumer-owned identity type.

```rust,no_run
use axum::{Extension, Router, routing::get};
use rigging_http_serve::{Caller, TcpServer, UnixServer};

# async fn example() -> std::io::Result<()> {
let app = Router::new().route("/", get(|Extension(caller): Extension<Caller>| async move {
    format!("{caller:?}")
}));
// The existing directory must be private (0700) and owned by the current user.
let unix = UnixServer::bind("/run/user/1000/my-service/http.sock", 0o600).await?;
let tcp = TcpServer::bind("127.0.0.1:0".parse().unwrap(), "/run/user/1000/my-service/token").await?;
println!("HTTP address: {}", tcp.local_addr()?);
// Use application-owned shutdown futures instead of pending() in production.
tokio::try_join!(
    unix.serve(app.clone(), Caller::<()>::Unix, std::future::pending()),
    tcp.serve::<(), _>(app, std::future::pending()),
)?;
# Ok(()) }
```

For an environment socket, replace `Caller::<()>::Unix` with a closure returning
`Caller::Custom(MyIdentity { ... })`, and extract `Caller<MyIdentity>` on both
transports. The closure receives kernel UID, GID and optional PID. It must be
cheap and synchronous. Applications enforce their own authorization using that
identity; Unix peers are not filtered by UID beyond filesystem permissions.

TCP accepts `Authorization: Bearer <token>` or `Cookie: rigging_token=<token>`.
An Authorization header takes precedence: an invalid bearer cannot fall back to
a cookie. Duplicate credentials are refused. The token is 64 lowercase hex
characters with no newline, generated from 256 random bits. Its SHA-256 digest
is compared with `subtle` in constant time. Hashing time depends on submitted
length, not secret contents. Every successful TCP bind atomically replaces the
token file with a fresh 0600 file, including replacing a symlink rather than
following it. Use a distinct token path per listener; rotating a shared path does
not revoke an already running listener's in-memory token.

Host must exactly match the bound numeric IP and port, including brackets for
IPv6. Origin may be absent; if present it must be exactly `http://<Host>`.
`localhost`, alternate ports, HTTPS origins, `null`, and duplicate Host/Origin
headers are refused. The crate does not issue cookies, enable CORS, or provide
a login endpoint. A browser-facing consumer must deliver its cookie through a
trusted mechanism and should set HttpOnly, SameSite=Strict and Path=/.

All endpoint parents must already exist, be owned by the effective UID and have
no group/other permissions. Symlink parents are refused; ancestors must be
trusted. Concurrent pathname replacement by the owning user is outside the
threat model. No process-global umask is changed. Socket permissions are applied
before requests are served, protected during bind/chmod by the private parent.
Only connection-refused socket files are reclaimed; live sockets, ordinary
files, symlinks and other connection errors are preserved. Cleanup checks device
and inode so it preserves a replacement endpoint. Shutdown futures stop new
accepts and drain HTTP requests; applications manage upgraded sessions and any
shutdown deadline themselves.

Linux uses tokio's SO_PEERCRED implementation. macOS uses its getpeereid
implementation; PID is optional and must never be assumed available. This crate
currently exposes its serving interface on Unix only. Windows named pipes,
blocking runtimes, HTTP clients, and project-specific authorization remain
outside this crate.
