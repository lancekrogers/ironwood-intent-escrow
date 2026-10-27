# WebAssembly verifier for Cloudflare Workers

The Worker runs the same 18 checks as the native `verify` binary, using the
shared Rust library with `default-features = false`. Wallets, signing, proving,
native sockets, and OS randomness are excluded. The public `runs/` records are
embedded at build time. Each click fetches fresh node responses; it does not
submit a transaction or use keys or funds.

## Current deployment blocker

The Wasm port compiles and passes its recorded-response and failure tests.
Cloudflare's remote preview successfully fetches the NEAR receipt, but Zcash
gRPC requests return HTTP 525 (TLS handshake failure), including with
`cf.grpcWeb: "convert"` and `auto_grpc_convert`. Native gRPC from the development
machine succeeds. A second Zcash endpoint also returned 525 from the edge.

Cloudflare's [gRPC conversion announcement](https://blog.cloudflare.com/grpc-workers/)
describes private-beta access. The installed workerd types expose the conversion
option, but accepting the configuration does not prove upstream connectivity.
The cause of the edge TLS failure has not been isolated to beta enrollment or
the upstream's TLS configuration. No TLS checks have been disabled.

**Do not use this as the submission demo yet.** The checked-in frontend stays
unconfigured. No permanent Worker or Pages site has been deployed for this port.
The next acceptance gate is a successful live run of all 18 checks from
Cloudflare, followed by CPU measurements within the
[Free plan's 10 ms limit](https://developers.cloudflare.com/workers/platform/limits/).
Local Node benchmarks are encouraging but are not Cloudflare CPU measurements:
the ~896 KB Wasm module took ~1.5 ms median warmed up and ~9.3 ms on its first call.

## Build and test

Prerequisites: Rust, Node 22+, Python 3, and a clang with the Wasm backend.
On macOS this requires LLVM clang rather than Apple's clang; the build script
detects an installed Homebrew LLVM. On Linux, set
`CC_wasm32_unknown_unknown=clang` and `AR_wasm32_unknown_unknown=llvm-ar` if needed.

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.129 --locked --root target/wasm-tools
npm ci --prefix worker
just worker-check
```

The Rust adapter tests and actual Wasm tests use recorded responses as fixtures.
They do not claim to fetch live nodes. Negative tests cover wrong heights,
changed transaction bytes, absent receipts, malformed protobufs, truncated
gRPC messages, error status, and oversized upstream bodies.

To test live transport on the actual Cloudflare network with your Wrangler login:

```sh
just worker-preview
curl http://localhost:8789/api/verify
```

Local emulation cannot establish whether Cloudflare's edge conversion works.

## Deployment contract

Only `GET /api/verify` runs verification. It accepts no user-provided URLs,
transaction IDs, files, commands, or keys. `GET /health` reports service health
and the source commit. CORS is restricted to `https://lancekrogers.github.io`;
the endpoint itself is public. The rate-limit binding allows approximately six
checks per IP per minute per Cloudflare location. It is not a global quota.
Upstream calls have 20-second timeouts and 1 MiB response limits. Reports are
uncached and include failures rather than substituting stored bytes for a
failed network request.

After the live transport and CPU gates pass, build from the committed source,
deploy with `npm exec -- wrangler deploy` inside `worker/`, set the actual HTTPS
endpoint in `web/config.json`, and test from the published GitHub Pages origin.
Deploying does not require purchasing a domain or enabling Containers. Never
upgrade the account's billing plan as part of this workflow.
