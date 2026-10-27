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

Hosting is not configured yet. `web/config.json` intentionally disables the
button until the deployment mode is chosen:

- `{"mode":"live","report_url":"https://<verifier-host>/api/verify"}` asks a
  hosted service to run the read-only verifier for the request.
- `{"mode":"published","report_url":"verification.json"}` reads a report
  generated during publication. The UI explicitly says this is not an
  on-demand node check and flags a report older than 24 hours.

GitHub Pages serves the interface but cannot execute the native Rust binary.
Live mode therefore requires an additional backend. Published mode can use
GitHub Actions to generate the report and publish it with Pages. No credentials
or wallets belong in either deployment.

## Report integrity and limits

`scripts/verification_report.py` invokes the fixed `verify` binary with no user
arguments. It requires the exact set of 18 named checks, matching totals, no
skips, and an exit code consistent with the outcome. Timeouts and malformed
output become `unavailable`, never successful verification. Reports include a
UTC timestamp and source commit. The browser repeats the schema and consistency
checks before showing results and clears earlier results if a request fails.

The page distinguishes fetched node evidence, transaction/receipt validation,
and recorded signer outcomes. The last group does not independently prove that
a signer applied a policy. Neither mode creates a new transaction or performs
independent consensus validation.
