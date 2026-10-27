# WebAssembly verifier for Cloudflare Workers

The Worker runs the same 18 checks as the native `verify` binary, using the
shared Rust library with `default-features = false`. Wallets, signing, proving,
native sockets, and OS randomness are excluded. Public `runs/` records are
embedded at build time. Each click queries testnet data services; it does not
submit a transaction or use keys or funds.

At Worker startup, Rust computes and retains the checks for the immutable embedded
Zcash transactions. Each request fetches fresh responses and checks mined heights;
a cryptographic result is reused only when the fetched bytes exactly equal the
checked bytes. Changed bytes run through the original checker. A failed fetch
never receives a cached pass. This keeps repeated cryptographic work outside the
Free plan’s per-request CPU budget without caching network verification reports.

Zcash bytes and mined heights come from the public
[ZecBlock testnet HTTPS API](https://github.com/Kenbak/zecblock/blob/main/public/openapi-v1.json).
NEAR receipts come directly from its archival testnet RPC. The report names both
sources. The Rust checks compare fetched bytes and heights against the committed
records. These are public-service attestations, not independent consensus
validation. Recorded signer outcomes remain labeled as recorded assertions.

## Build and test

Prerequisites: Rust, Node 22+, Python 3, and a clang with the Wasm backend.
On macOS this requires LLVM clang rather than Apple's clang; the build script
detects installed Homebrew LLVM. On Linux, install clang and llvm, and set
`CC_wasm32_unknown_unknown=clang` and `AR_wasm32_unknown_unknown=llvm-ar` if needed.

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.129 --locked --root target/wasm-tools
npm ci --prefix worker
just worker-check
```

The Rust adapter tests and actual Wasm tests use recorded responses as fixtures.
They do not claim to fetch live data. Negative tests cover wrong heights, changed
transaction bytes, missing receipts, wrong networks, noncanonical transactions,
HTTP failures, and oversized upstream bodies.

To test live transport on Cloudflare using your Wrangler login:

```sh
just worker-preview
curl http://localhost:8789/api/verify
```

## Deploy

Build from a committed source revision so the report links to the deployed code:

```sh
just worker-build
cd worker
npm exec -- wrangler deploy
```

Verify `/api/verify` returns all 18 passing checks before setting its HTTPS URL
in `web/config.json`. Publish the frontend with the repository's Pages workflow.
CORS is restricted to `https://lancekrogers.github.io`; the endpoint itself is
public. `GET /health` reports service health and source commit.

Cloudflare applies its fixed 10 ms CPU limit on the
[Workers Free plan](https://developers.cloudflare.com/workers/platform/limits/).
Free accounts must omit the configurable `limits.cpu_ms` setting, which is
reserved for paid plans. Waiting for network responses does not consume that CPU budget. No Containers,
database, domain purchase, or paid plan upgrade is needed. Free request/usage
limits still apply. A local benchmark is not a measurement of edge CPU usage.

## Request boundaries

Only `GET /api/verify` runs verification. It accepts no user-provided URLs,
transaction IDs, files, commands, or keys. The rate-limit binding allows
approximately six checks per IP per minute per Cloudflare location; it is not
a global quota. Upstream calls have 20-second timeouts and 1 MiB response limits.
Reports are uncached and include failures rather than substituting stored bytes
for a failed network request. A public API may itself cache blockchain data;
the timestamp records when this service fetched and checked its responses.
