# ironwood-intent-escrow

## Track

Cross-chain: "Swaps, bridges, and intents that reach other chains without
unshielding on the way through."

## What it is

A payer locks ZEC in one shielded Ironwood note that any two of three FROST
shares can spend, and a solver fills the payer's quote by paying on NEAR,
where the payment's only link to the escrow is a 32-byte quote id and it
never carries a Zcash address, transaction ID, or amount. Cross-chain intent
flows today write a refund address onto the public chain the moment a
deposit registers; here the refund address is made inside the payer's wallet
only when a refund is built, and it never reaches the quote or NEAR. Both
paths ran end to end on Zcash testnet and NEAR testnet, and one command re-
checks all four Zcash transactions and the NEAR payment against live public
nodes with no keys or funds. The code was written for this hackathon: re-
randomized FROST over RedPallas signing Ironwood spends through PCZTs, a
NEAR receipt check that refuses any Zcash value, and a refund check that
refuses a refund when the quote's claimed NEAR payment re-fetches and checks
out. It is a testnet build with a trusted-dealer key, and the deadline
device that co-signs refunds is the payer's own, so it protects the payer
and an honest payer's automation, not a solver facing a dishonest payer.

## What stays private and what is public

| Who | Sees | Does not see |
|---|---|---|
| Zcash observer | Two fully shielded Ironwood transactions per run, their action counts and fees | Note values, addresses, memos, any link to NEAR except timing |
| NEAR observer | Both NEAR accounts, the wNEAR amount, the 32-byte quote id | Any Zcash address, transaction id, or amount |
| Solver | The escrow note and its value, when it is spent, its own payment | The refund address or the refund output |

## Verify it in two minutes

```text
git clone https://github.com/lancekrogers/ironwood-intent-escrow
cd ironwood-intent-escrow
cargo run --release --bin verify
```

`verify` reads only the repository's `runs/` and needs no keys, wallets, or
accounts. It fetches the four Zcash transactions from the light server
`testnet.zec.rocks:443` and the NEAR payment from
`archival-rpc.testnet.near.org`, checks each against the recorded bytes,
heights, and hashes, runs the Zcash checker and the NEAR receipt check on
what it fetched, and checks the recorded policy outcomes. It prints one
`PASS` or `FAIL` line per check and ends with:

```text
18 passed, 0 failed, 0 skipped (offline)
```

The first run compiles the Zcash crates. From a fresh clone on a 16-core
Apple M4 Max the build took 30 s and the checks 4 s; a smaller machine
builds for longer. `cargo run --release --bin verify -- --offline` runs the
same checks on the stored bytes without the network.

## Testnet evidence

| Run | Step | Zcash transaction | Mined at |
|---|---|---|---|
| Fill | fund escrow | `20058089e6c8b5b00744c935d62308da9af52ef613537496ff22bf70e03b0512` | 4,530,559 |
| Fill | release to solver | `f094fdf4c1daf2b8d63af8011d1601ff1288895fbe1289be7b7ec9009c6df61b` | 4,530,577 |
| Refund | fund escrow | `ff34db628bac27cf13a2c3e814a17261072c0138c327332ad0c6bd4154cfaf54` | 4,531,486 |
| Refund | refund to a fresh address | `aed8163c89199d72eb0b56028cb23b0ebe0f8598cf22cf397b38a3e68c4c184f` | 4,531,498 |

The fill's NEAR payment is
[`7J1bzUpXaJo2oHqtbXHh5sme7FXhucexpiQiQ7fkG7uk`](https://testnet.nearblocks.io/txns/7J1bzUpXaJo2oHqtbXHh5sme7FXhucexpiQiQ7fkG7uk),
an `ft_transfer` of 0.01 wNEAR on `wrap.testnet` whose memo is the quote id.
The deadline device refused the fill's release, still refused it during the
refund run, and signed the refund only after expiry. Before funding the
refund, the refund check re-fetched the fill quote's NEAR payment and
refused that quote as `quote_paid`.

## How it was built

Rust, on `frost-core` and `frost-rerandomized` 3.0.0, `reddsa` 0.5.2,
`orchard` 0.16.0, `zcash_primitives` 0.31.0, `pczt` 0.10.0,
`zcash_client_backend` 0.25.0, and `zcash_client_sqlite` 0.23.0, with a
public light server and no local node. All code was written from 2026-10-20
onward. The work was planned and executed with Festival and its `fest` CLI:
design decisions were pinned in `docs/decisions/` before the code that
implements them, and every sequence of work ended with its own tests and
review
([Built with Festival](https://github.com/lancekrogers/ironwood-intent-escrow#built-with-festival)).

## Limitations

1. The solver is not protected from a dishonest payer: the deadline device
   is the payer's, so the payer effectively holds two shares.
2. A payer can withhold the solver's fill claim, which is stored on the
   payer's machine; NEAR cannot be searched by memo.
3. The expiry is signer policy. The chain accepts a refund two shares sign
   at any time.
4. The key came from a trusted dealer, not distributed key generation,
   because ZIP 312 does not yet specify key generation for these keys.
5. The key uses the legacy `use_qsk = false` derivation, so the note is not
   quantum recoverable.
6. An observer of both chains can align a NEAR payment and a Zcash release
   by timing.
7. The NEAR leg, the solver's account and its wNEAR payment, is public by
   design.

## Demo

Video:
https://github.com/lancekrogers/ironwood-intent-escrow/blob/main/demo/zecathon.mp4
(2 min 54 s, narrated). The `verify` segment runs live; the fill and refund
segments show the recorded runs and say so.

## Repository

https://github.com/lancekrogers/ironwood-intent-escrow, public at
submission. Licensed MIT OR Apache-2.0.
