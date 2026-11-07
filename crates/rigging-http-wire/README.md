# rigging-http-wire

The HTTP wire rules every route in the stack takes by default, as axum 0.8
extractors and a responder. It builds on every target; `rigging-http-serve`
supplies the listeners on Unix.

- **Responses.** `Encoding` (JSON or CBOR) is negotiated from `Accept`: the most
  specific matching range sets each type's quality, so `application/json;q=0, */*`
  excludes JSON. An unsatisfiable or malformed `Accept` answers 406
  `unsupported_format`. Bodies carry `Cache-Control: no-store` and `Vary: Accept`.
  Errors are `{"code", "message"}` in the negotiated encoding; JSON writes
  integers beyond ±(2^53 − 1) as `{"u64": "…"}` or `{"i64": "…"}`.
- **Requests.** `Content-Type` is `application/json` (the default) or
  `application/cbor`, else 415. The route's byte limit is applied while reading,
  so a chunked body stops at the limit with 413; GET, HEAD and DELETE take none.
  CBOR decodes through `flotilla-cbor`'s safe reader within that limit.
- **Sequences.** A response of many values, such as a watch stream, negotiates
  `application/jsonl` (the default; `application/x-ndjson` too) or
  `application/cbor-seq` with `Encoding::negotiate_sequence`, and writes each
  value with `encode_item`. A client splits the body back into values with
  `Items` as its bytes arrive; it builds without a server.

```rust,no_run
use axum::{Router, routing::post};
use rigging_http_wire::{Encoding, Negotiated, Wire};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Invocation { name: String }
#[derive(Serialize)]
struct Invoked { name: String }

// A body of at most 16 KiB in, the negotiated representation out.
async fn invoke(encoding: Encoding, Wire(body): Wire<Invocation, 16384>) -> Negotiated<Invoked> {
    encoding.ok(Invoked { name: body.name })
}

let app: Router = Router::new().route("/verbs/{name}", post(invoke));
```

A route whose limit or body depends on more than its signature reads with
`Body::read(request, limit)` and decodes with `Body::decode` later. A route with
more representations than JSON and CBOR negotiates with `negotiate` over its own
list and still answers through `Encoding`.
