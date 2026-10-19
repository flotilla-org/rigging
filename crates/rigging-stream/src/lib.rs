//! Shared Tokio byte streams, seeded from drydock-transport at b076dbea.
//! Framing, routing, and ownership policy belong to the consumer.
use tokio::io::{AsyncRead, AsyncWrite};

/// A full-duplex byte stream. Write shutdown preserves the readable half.
pub trait RawStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> RawStream for T {}
/// A type-erased stream suitable for `tokio::io::copy_bidirectional`.
pub type ByteStream = Box<dyn RawStream>;
