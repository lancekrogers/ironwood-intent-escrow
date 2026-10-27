# Browser verification demo

The static interface is in `web/`. It shows the two completed testnet paths,
links the raw evidence, and displays results from the existing Rust verifier.
It does not create wallets, sign transactions, or require testnet funds.

## Local checks

```sh
just web-check
just web-build
just web-preview
```

`web-build` builds the verifier from the current checkout, packages an explicit
allowlist of public assets under `target/web/`, and runs live verification to
produce `verification.json`. It exits nonzero on a failed or incomplete run.
The report is still written on verifier failure so a publisher can display the
failure instead of silently retaining a previous green result.

The frontend is hosted on GitHub Pages and calls the
[Cloudflare Worker](../worker/README.md). The Worker compiles the shared Rust
checks to WebAssembly, queries the ZecBlock testnet HTTPS API and NEAR archival
RPC, and returns the same report schema. It needs no native server or credentials.
The report links to the deployed source commit and names the data sources.

`web/config.json` selects the endpoint and labels the mode explicitly:

- `{"mode":"live","report_url":"https://<verifier-host>/api/verify"}` queries
  public testnet services when clicked.
- `{"mode":"published","report_url":"verification.json"}` reads a previously
  generated report, explicitly labeled as not an on-demand check.

`just web-build` remains useful for local native-verifier reports. The Pages
workflow packages the static frontend with `scripts/build_web.py`; live reports
come from the Worker, not a scheduled build.

## Report integrity and limits

`scripts/verification_report.py` invokes the fixed `verify` binary with no user
arguments. It requires the exact set of 18 named checks, matching totals, no
skips, and an exit code consistent with the outcome. Timeouts and malformed
output become `unavailable`, never successful verification. Reports include a
UTC timestamp and source commit. The Wasm adapter calls these same checks directly, without parsing CLI output.
The browser repeats the schema and consistency
checks before showing results and clears earlier results if a request fails.

The page distinguishes fetched node evidence, transaction/receipt validation,
and recorded signer outcomes. The last group does not independently prove that
a signer applied a policy. Neither mode creates a new transaction or performs
independent consensus validation.
