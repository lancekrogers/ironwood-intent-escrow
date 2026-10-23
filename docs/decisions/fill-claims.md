# Decision: fill claims

Festival ZS0001, sequence 01, task 01. Decided 2026-10-22.

Before either refund signer, the deadline device or the payer, produces a
round 2 share for a refund, it looks for a fill claim for the quote. A fill
claim is a pointer to the NEAR payment the solver says filled the quote. If
a claim exists, the signer re-fetches that payment from its own archival
RPC and runs the same `check_payload` the release path runs. A payment that
attests means the quote was paid, and the signer refuses with `quote_paid`.

The hole this closes: until now the refund rule in `shares.md` checked that
the refund pays the payer after expiry and never asked whether the quote
was filled. An honest payer's automation, run after expiry, could refund a
quote the solver had already paid on NEAR.

## The constraint

NEAR JSON-RPC finds a transaction by its hash and its sender, and by
nothing else. The crate's interface to it is the `NearRpc` trait in
`src/attest.rs`:

```rust
pub trait NearRpc {
    /// The endpoint, recorded in the attestation.
    fn url(&self) -> &str;
    /// The raw JSON-RPC response body of `tx` with `wait_until: FINAL`.
    fn tx(&self, hash: &str, sender: &str) -> Result<Vec<u8>, Error>;
}
```

No RPC method finds an `ft_transfer` by its memo, so a signer cannot ask
NEAR "was quote X paid?". It needs a pointer, and the solver is the party
that has one. A third-party indexer could answer the memo query, but it
would add a dependency and a party the signer has to trust, so it is
rejected.

`attest` in `src/attest.rs` is `rpc.tx(hash, sender)` followed by
`check_payload(quote, pointer, banned, payload)`. The four outcomes below
split on which of the two fails, so the refund signers call the two
separately and never call `attest`.

Measured against `https://archival-rpc.testnet.near.org` on 2026-10-22:

- A `tx` call for a hash the node has never observed holds for about 33 s
  and answers HTTP 408 with a JSON-RPC error,
  `{"name":"HANDLER_ERROR","cause":{"name":"TIMEOUT_ERROR","info":{"cause":"NOT_OBSERVED"}}}`.
  There is no distinct "unknown transaction" answer for a bogus hash.
- A `tx` call for the fill's hash with a wrong `sender_account_id` returns
  the transaction anyway, with its real `signer_id`. `check_payload`
  compares `signer_id` to the pointer's sender, so a wrong sender fails the
  check rather than the fetch.
- `ArchivalRpc::tx` (`src/near.rs`) returns the body of an HTTP 2xx or 4xx
  response as `Ok`, because NEAR reports handler errors as JSON with either
  status. A JSON-RPC error body is therefore not a transport error at the
  trait boundary, and the refund signers must classify it themselves.

## The claim

The solver writes one file per quote, immediately after its NEAR payment
succeeds and before it asks anyone for a signature:

```text
~/.ironwood-intent-escrow/testnet/claims/<quote id hex>.json
```

```json
{
  "quote_id": "<64 lowercase hex>",
  "near_tx_hash": "<base58 NEAR transaction hash>",
  "near_sender": "<solver account>",
  "rpc_url": "<the RPC the solver used>"
}
```

- The directory is mode 0700 and the file mode 0600.
- The file is written under a temporary name and linked into place, so a
  crash never leaves a partial claim, and an existing claim is never
  replaced.
- A second write for the same quote with the same hash and sender is a
  no-op, so a resumed fill run can write it again. A second write naming
  any other payment is refused with `claim`.
- A claim file that does not parse, or whose `quote_id` is not the quote
  the file is named for, is refused with `claim`. The signer does not sign
  over a claim store it cannot read.
- The claim holds a quote id, a NEAR hash, two NEAR strings, and nothing
  else. It holds no Zcash address, transaction id, or amount of any kind.

`rpc_url` is informational. The refund signer re-fetches from its own
configured RPC, `ARCHIVAL_RPC` in `src/attest.rs`, and ignores the claim's
URL. A payload the solver hands over, or a URL the solver chooses, is not a
check.

## What a refund signer does

`deadline_sign` and `payer_refund` keep their existing checks, in the
existing order: the package is the PCZT's own (`package_mismatch`), the
package does not pay the solver (`refused_release` for the deadline device,
`not_a_refund` for the payer), the memo carries this quote's id
(`not_a_refund`), the quote has expired (`not_expired`), and every output is
an address the refund key detects (`not_a_refund`). All of those are
refused before the claim store is read, so no network call happens for a
package that would be refused anyway.

Then, as step 6 of the refusal rule in `shares.md`, the signer looks up a
claim for `quote.id`. A claim file it cannot read is refused with `io`, and
a claim file that does not parse or names another quote is refused with
`claim`, before anything is fetched. Once the store answers, there are exactly four
outcomes:

1. **No claim file.** Sign.
2. **A claim, and no answer.** `NearRpc::tx` fails (transport, TLS, HTTP
   5xx, timeout), or it returns a body that is not JSON, that carries a
   JSON-RPC `error` of any kind, or that has no `result`. That includes the
   HTTP 408 `TIMEOUT_ERROR` a rate-limited, lagging, or unobserved lookup
   returns. Refuse with
   `claim_unverified`. The device cannot tell whether the quote was paid,
   so it does not sign. The operator reruns later.
3. **A claim, a fetched result, and `check_payload` fails.** The claim is
   false: wrong quote id, wrong amount, wrong sender, wrong destination, a
   failed transfer, or a payment that carries a Zcash value
   (`banned_field`), which the release path would refuse as well. Sign. A
   solver cannot block a refund by pointing a claim at a real transaction
   that did not pay the quote.
4. **A claim, a fetched result, and `check_payload` passes.** The quote was
   paid on NEAR. Refuse with `quote_paid`.

Outcome 2 is the cautious side by design. A claim that names a hash the
archival node never observed holds the refund at `claim_unverified` until
the hash appears or the operator removes the claim. The operator is the
payer, who owns the claim directory, so a bogus hash delays a refund and
cannot block it.

## What this protects

The deadline device is the payer's own device, and in this deployment the
claim store is on the payer's machine. A dishonest payer can delete the
claim, withhold it, or run a patched signer, and then refund a quote the
solver already paid. The guard does not protect the solver from a
dishonest payer.

What the guard does protect: an honest payer's automation, and operator
error, from refunding a filled quote. It also gives the refund path the
same attestation discipline as the release path: a refund signer that sees
a claim re-fetches the payment from its own node and decides on the fetched
bytes.

The payer can withhold a claim because NEAR cannot be searched by memo, so
without the pointer the device has nothing to fetch. A deadline holder the
payer does not control, with a claim channel the payer cannot intercept, is
future work.

## Banned values for the refund check

The refund signer runs `check_payload` with a `Banned` set of the three
values it knows before any refund is built:

1. the escrow unified address;
2. the transaction id that funded the escrow note being refunded;
3. the escrow note's zatoshi amount, `ESCROW_ZATOSHIS` in `src/run.rs`.

When the refund binary checks the fill quote during the refund run, the
note that quote would refund is the fill's escrow note, so the fund
transaction id in that set is the fill's, read from the fill run's state.

The refund address is not in the set: it does not exist until the refund is
built, and the claim is checked after that only because the earlier checks
must refuse first. `check_payload` bans any token that decodes as a Zcash
address regardless.

## Key material

A claim is not key material. It names a public NEAR transaction and two
public NEAR accounts. It lives under `~/.ironwood-intent-escrow/testnet/`
anyway, outside every repository, beside the run state it belongs to.
