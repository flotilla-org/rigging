# rigging-stream

The shared `RawStream: AsyncRead + AsyncWrite + Unpin + Send` trait and
`ByteStream = Box<dyn RawStream>` alias, seeded from drydock-transport at
`b076dbea24883af99356410c14cff40f44b9fd8a`. Tender and drydock can reexport these
types directly. Stream routing, framing, connection identity and transport
ownership stay with consumers. `rigging-ssh` exercises the types against real
OpenSSH channels, including half-close and backpressure.
