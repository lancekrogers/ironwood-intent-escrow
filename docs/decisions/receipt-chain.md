# Decision: the receipt chain

Festival II0001, sequence 01, task 01. Decided 2026-10-22.

The payer co-signs a release only after re-fetching, from a node the payer
chooses, one NEAR transaction that paid the quote. That transaction carries
the quote id and the destination amount. It never carries a Zcash address, a
Zcash transaction id, or the zatoshi amount of the escrow note.

The hole this closes: NEAR Intents writes a `refundTo` shielded address onto
NEAR when a ZEC swap deposit registers. Zakura's note (read 2026-10-22,
https://zakura.com/engineering/quantum-unlinkability/) states it: "That
address is written to NEAR's public chain as soon as the deposit registers,
whether or not a refund ever happens." This product's receipt has no such
field.

## Network

NEAR testnet, chain id `testnet`, genesis
`FWJ9kR6KFWoyMoNjpLXXGHeuiy7tEY6GmoFeCA5yuc6b`, protocol version 88 on the
day of this decision.

## Payment shape

One NEAR account (the solver's) calls `ft_transfer` on the NEP-141 contract
`wrap.testnet` (wNEAR, `ft_metadata` spec `ft-1.0.0`, 24 decimals, confirmed
by view call on 2026-10-22). The call:

- `receiver_id`: the payer's NEAR destination account from the quote.
- `amount`: the destination asset amount from the quote, as a decimal string
  of yoctowNEAR.
- `memo`: the 32-byte quote id as 64 lowercase hex characters, and nothing
  else.
- `deposit`: 1 yoctoNEAR, as NEP-141 requires.

NEP-141 defines `memo` as "for use cases that may benefit from indexing or
providing information for a transfer" and the `ft_transfer` NEP-297 event
log carries `memo` in its `data`. So the quote id appears twice in the
fetched transaction: in the FunctionCall `args` and in the
`EVENT_JSON:{"standard":"nep141",...}` log of the receipt outcome. The
attestation requires both.

A plain NEAR `Transfer` action has no args and no memo, so native NEAR
cannot carry the quote id. wNEAR was chosen over deploying a receipt
contract because it needs no deployment: the solver wraps testnet NEAR by
calling `near_deposit` on `wrap.testnet`, and the receiver registers storage
once with `storage_deposit`. A receipt contract remains an option if a later
asset is not NEP-141. Nothing in the shape changes for the checker.

## Re-fetch

The payer fetches the transaction with the `tx` RPC method (`tx_status` for
the same payload plus every receipt), params `tx_hash`, `sender_account_id`,
`wait_until: "FINAL"`. The solver supplies exactly two things: the
transaction hash and the sender account id. The solver's copy of the
transaction, its receipts, or its logs is never the input to the check.

Endpoint: `https://archival-rpc.testnet.near.org`, the archival node NEAR
operates. Verified on 2026-10-22:

- It answers `block` for height 200,000,000. The non-archival
  `https://rpc.testnet.near.org` returns `UNKNOWN_BLOCK` (HTTP 422, "DB Not
  Found Error") for the same height.
- Both nodes report `earliest_block_height` 274,102,855 against latest
  274,291,832 in `status`, a window of about 189,000 blocks. That number is
  the hot store. On the archival node, older data is served from the cold
  store, which the block probe above proves. A non-archival node has only
  the window.

So a review that re-fetches weeks after the fill must use the archival
endpoint. The NEAR docs (https://docs.near.org/api/rpc/providers, read
2026-10-22) call it "severely rate limited", which is fine for one fetch per
run and one per review. Fallbacks with archival testnet data on the same
page: QuickNode and All That Node (free tiers), FASTNEAR
(`https://archival-rpc.testnet.fastnear.com`, answers `status` today, paid
for archival per the docs).

Response shape the attestation reads, confirmed from a live testnet
transaction on 2026-10-22:

- `transaction.actions[].FunctionCall.{method_name, args, gas, deposit}`,
  with `args` base64 JSON.
- `receipts_outcome[].outcome.logs[]`, strings, where NEP-297 events are
  `EVENT_JSON:` followed by JSON.
- `status.SuccessValue` on success. Anything else fails the attestation.

## Record

`runs/fill.json` stores `near_rpc_url`, `near_tx_hash`, `near_sender`, and
`near_payload_sha256`. `runs/fill.near.json` stores the raw JSON-RPC result
bytes the payer fetched. The review hashes the file and compares it to the
record before trusting either.

## Fail the run

Search only two places in the fetched transaction: the decoded `args` of
each `FunctionCall` action, and every string in `receipts_outcome[].outcome.logs`.
Never search block hashes, transaction or receipt hashes, `gas`, block
heights, or `deposit`.

Known values, each a `banned_field` error if present:

1. The escrow unified address string.
2. Any payer refund address string recorded in `runs/refund.json`.
3. The fund transaction id, as 64 hex characters.
4. The spend transaction id, as 64 hex characters.
5. The zatoshi amount of the escrow note, as a decimal string token.

Decoded addresses, each a `banned_field` error if present:

6. A token starting `utest1` or `u1` that bech32m-decodes as a Zcash
   unified address.
7. A token starting `tm`, `t2`, `t1`, or `t3` that Base58Check-decodes
   with a Zcash transparent address prefix.

Decode before banning. `tmp`, `t2-escrow.testnet`, and the wNEAR memo text
are not matches. Do not scan for any 32-byte hex value: the quote id is one
and must be present.

Required values, each a `missing_field` error if absent:

- The quote id, 64 lowercase hex, in `args.memo` and in the `ft_transfer`
  event log `memo`.
- `args.receiver_id` equal to the quote's `destination_account`.
- `args.amount` equal to the quote's `amount`.
- `transaction.receiver_id` equal to the quote's `asset` contract
  (`wrap.testnet`).
- `status.SuccessValue`.

## Test amounts

The quote's destination `amount` and the escrow note's zatoshi amount must
differ as decimal strings, so rule 5 above cannot match the payment's own
amount. The fill binary refuses a quote where they are equal.

## Not blocked

A NEP-141 transfer on testnet carries the quote id without any Zcash value
in its args or logs. The chain stays NEAR testnet. Sequence 04 implements
this file as `attest`.
