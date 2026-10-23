# Decision: the crate stack

Festival II0001, sequence 01, task 03. Decided 2026-10-22.

## Blocked

A full viewing key for a FROST-generated Ironwood key cannot be derived
today. The two runs use a trusted-dealer test key instead. This is not
distributed key generation, and `keygen` must grow into it later.

Evidence, each read on 2026-10-22:

- ZIP 312 (https://zips.z.cash/zip-0312): status Draft. Its Key Generation
  section does not specify `nk` or `rivk`; it says "this ZIP does not
  specify a key generation procedure; but refer to that specification for
  guidelines."
- zcash/zips#895 "[ZIP 312] Specify key generation, change randomizer
  handling" (https://github.com/zcash/zips/pull/895): open, 21 commits, not
  merged, no current approval. The latest comments (KHADEVS 2026-10-15,
  aryaethn 2026-10-16) are still arguing how `sk` is derived in contributory
  generation so that it does not leak through the COCKTAIL-DKG transcript or
  let the last participant bias it.
- ZIP 2005 (https://zips.z.cash/zip-2005): status Proposed. "FROST
  distributed key generation requires the use_qsk = true case." It requires
  participants to "privately agree on a value sk" and derive `nk`, `qsk`,
  `qk`, and `rivk_ext` from it. It does not say how they agree. That is what
  zips#895 is for.
- ZcashFoundation/frost#1094 (https://github.com/ZcashFoundation/frost/issues/1094):
  open. conradoplg's reply of 2026-09-21: FVK derivation is blocked on
  zips#895 being finished, integrated with ZIP 2005, and then implemented.
  Using the `from_sk_ak_incompatible` style constructor gives up quantum
  recoverability.
- The `orchard` crate at `main` (0.16.0, 2026-09-29): `src/keys.rs` has no
  `use_qsk` or `rivk_ext`. Fatihmaull reported the same on 2026-10-02 in
  frost#1094.

## Fallback for the two runs

Trusted dealer, in `keygen`:

1. Generate a normal Orchard spending key `sk` in memory: fill 32 bytes
   from the OS RNG and retry `orchard::keys::SpendingKey::from_bytes` until
   it returns `Some`. That is the body of `SpendingKey::random`, which is
   `pub(crate)` in orchard 0.16.0.
2. Derive `ask`, `ak`, `nk`, and `rivk` from it the way every existing wallet
   does (`SpendAuthorizingKey::from`, `FullViewingKey::from`). This is the
   `use_qsk = false` path. ZIP 2005 calls it the legacy derivation. It is not
   quantum recoverable, and the decision file says so rather than pretending.
3. Split `ask` into three shares, threshold two, with
   `frost_core::keys::split` over the RedPallas spend-auth ciphersuite
   (`reddsa::frost::redpallas::PallasBlake2b512`), using `ask`'s 32 bytes as
   the `SigningKey`. orchard 0.16.0 gives `SpendAuthorizingKey` no byte
   accessor, so `keygen` reads the bytes as
   `SpendAuthorizingKey::from(&sk).randomize(&pallas::Scalar::ZERO).to_bytes()`
   and passes them to `SigningKey::deserialize`. Adding zero leaves the
   scalar unchanged, and `From<&SpendingKey>` has already negated `ask` so
   that `ak` has ỹ = 0. `pallas` is `pasta_curves` 0.6.1, already in the
   lockfile through `orchard`; sequence 02 adds it as a direct dependency.
   The dealer's secret polynomial lives only inside that call.
4. Write `payer.key`, `solver.key`, `deadline.key` (one `KeyPackage` each)
   and `escrow.fvk` (the `FullViewingKey` bytes: `ak`, `nk`, `rivk`). Drop
   `sk`, `ask`, and the polynomial. Nothing else is written.

The FROST verifying key equals `ak` by construction, so the Ironwood address
derived from `escrow.fvk` is the address the three shares can spend from.
Checked on 2026-10-22 with a scratch build against these pins: for 64
random keys, the group verifying key from `split` serialized to the same 32
bytes as `ak` in `FullViewingKey::to_bytes`, and every `KeyPackage` carried
it. The ciphersuite's even-y step changes nothing, because `ak` already has
ỹ = 0.

`keygen` keeps the `FullViewingKey` return type so that the distributed path
can replace step 1 through 3 without changing callers once zips#895 lands in
ZIP 2005 and the `orchard` crate implements `use_qsk`.

## Crates

| Crate | Version | Released | Role |
|---|---|---|---|
| `frost-core` | 3.0.0 | 2026-04-23 | DKG parts, `keys::split`, round 1, round 2, aggregate |
| `frost-rerandomized` | 3.0.0 | 2026-04-23 | re-randomized signing with a caller-supplied `Randomizer` |
| `reddsa` | 0.5.2, feature `frost` | 2026-05-22 | the RedPallas spend-auth ciphersuite `reddsa::frost::redpallas` |
| `orchard` | 0.16.0 | 2026-09-30 | keys, notes, the Halo 2 circuit, bundle types that Ironwood reuses |
| `zcash_primitives` | 0.31.0 | 2026-10-21 | v6 transactions, `Builder::{add_ironwood_spend, add_ironwood_output}` |
| `pczt` | 0.10.0 | 2026-10-21 | ZIP 374 PCZT with an Ironwood bundle, `Prover::create_ironwood_proof`, `Signer::apply_ironwood_signature` |
| `zcash_client_backend` | 0.25.0 | 2026-10-21 | Ironwood scanning, `ShieldedPool::Ironwood`, light-client gRPC |
| `zcash_client_sqlite` | 0.23.0 | 2026-10-21 | the payer wallet store |
| `zcash_keys` | 0.17.0 | 2026-10-21 | unified addresses and unified keys |
| `zcash_address` | 0.14.0 | 2026-10-21 | address encoding, `utest1` on testnet |
| `zcash_protocol` | 0.11.0 | 2026-10-21 | `BranchId::Nu6_3`, `Nu7`, network parameters |

Four facts the versions force:

- `reddsa` 0.6.x dropped the `frost` feature (0.6.1 features: alloc,
  default, internal, nightly, serde, std, zeroize). conradoplg said on
  2026-10-01 that the ciphersuites will move into the FROST repository. On
  2026-10-22 that repository has no RedPallas crate. So the FROST
  ciphersuite is `reddsa` 0.5.2 with `frost`, which depends on
  `frost-rerandomized ^3.0.0`.
- `orchard` 0.16.0 depends on `reddsa ^0.6` and `pasta_curves ^0.6`, while
  `reddsa` 0.5.2 uses `pasta_curves ^0.5`. Two `reddsa` and two
  `pasta_curves` versions build side by side. The FROST signature and the
  randomized verifying key cross that boundary as 64 and 32 bytes, and
  `orchard::primitives::redpallas::Signature<SpendAuth>` is rebuilt from
  those bytes. No type from one side is passed to the other.
- `frost_rerandomized::sign` with a caller-supplied `Randomizer` is marked
  deprecated in 3.0.0 in favour of `sign_with_randomizer_seed`, which
  derives the randomizer from a seed and the commitments. Zcash needs the
  transaction's own `alpha`, so this crate calls the deprecated `sign` under
  `#[allow(deprecated)]` and builds `RandomizedParams::from_randomizer` for
  `aggregate`. conradoplg wrote on 2026-09-21 that an external randomizer
  mechanism will stay because Zcash requires it.
- `pczt`'s `Signer::sign_ironwood` takes an `&SpendAuthorizingKey`, which no
  holder has. The coordinator applies the aggregated signature with
  `Signer::apply_ironwood_signature(index, Signature<SpendAuth>)` instead.
  The randomizer is the escrow spend's `alpha`, read with
  `orchard::pczt::Spend::alpha()` and passed to FROST as
  `frost_rerandomized::Randomizer::deserialize` of its 32 bytes.

The `orchard` crate's `unstable-frost` feature only widens visibility of two
items in `keys.rs`. It is not a FROST implementation. Not enabled.

One feature pairing the lockfile does not catch: `zcash_client_backend`'s
`pczt` feature turns on `transparent-inputs` in the backend and in
`zcash_keys`. `zcash_client_sqlite` 0.23.0 then fails to compile (12 errors:
missing transparent trait items, non-exhaustive `Recipient` matches) unless
its own `transparent-inputs` feature is on too. `Cargo.toml` enables it. It
compiles the wallet's transparent code; the checker still rejects any
transparent output.

Measured on the testnet payer wallet, 2026-10-22: with `transparent-inputs`
on, `zcash_client_sqlite` pre-derives transparent gap-limit addresses for
each account in its own `addresses` table: 10 external, 5 internal, and 10
ephemeral. It also marks one default address per account as exposed in its
bookkeeping. None of them leaves the wallet. `payer_address` derives the
faucet address with the transparent receiver omitted, and
`fresh_refund_address` requests an Orchard receiver only. Both refuse an
address with a transparent receiver.

## Prover

No parameter files. ZIP 2005 changes the note construction and "would not
require any change to the Orchard-protocol (or proposed OrchardZSA-protocol)
circuits for the time being." Ironwood proofs are Orchard Halo 2 proofs. The
`orchard` crate builds the proving key in process with
`orchard::circuit::ProvingKey::build(OrchardCircuitVersion::PostNu6_3)` under
its `circuit` feature. Ironwood bundles are protocol version 3, and
`Bundle::circuit_version` maps that to `PostNu6_3`, the circuit that enforces
the `disableCrossAddress` input. A key for another version fails at proving.
There is nothing to download, and a judge needs no files beyond the crate.

`params/` stays in `.gitignore` as a guard, and the Sapling Groth16 files
(`sapling-spend.params`, `sapling-output.params`) are not needed because no
Sapling bundle is built.

Build time of the `PostNu6_3` proving key on this machine (Apple M4 Max, 16
cores), measured 2026-10-22 with the pinned `orchard`: 0.9 s in a release
build and 11.9 s in a debug build. `cargo test` runs the debug build, so a
test that proves pays about 12 s once per process. Build the key once and
share it, the way `zcash_primitives`' `cached_orchard_proving_key` does.

## Network and activation

Zcash testnet. Verified in Zebra `main`,
`zebra-chain/src/parameters/constants.rs`, on 2026-10-22:

| Upgrade | Testnet height | Mainnet height | Branch id |
|---|---|---|---|
| NU6.3 (Ironwood) | 4,134,000 | 3,428,143 | `0x37a5165b` |
| NU7 | 4,465,026 | 3,543,405 | `0x77190ad9` |

The explore note's 4,134,000 was correct. NU7 activated on testnet at
4,465,026 (mined 2026-10-04 per press coverage of the Zebra 7.0.0-rc.0
schedule), so today's testnet is past both. Every Ironwood-pool output note
is a recoverable note from NU6.3, and post-NU7 rules (25 second block
spacing, ZIP 318 canonical crossings, 120-block default expiry) apply to the
transactions this crate builds. `zcash_primitives` 0.31.0 and
`zcash_client_backend` 0.25.0 implement those rules.

## Broadcast path

Nothing in this path is installed on this machine. The fill binary talks to
a light server over gRPC with `zcash_client_backend`; it does not need a
local node.

- Light server: `zaino.testnet.unsafe.zec.rocks:443` and
  `testnet.zec.rocks:443` both accept TCP on 2026-10-22.
  `lightwalletd.testnet.electriccoin.co:9067` does not answer. Sequence 03
  confirms which one serves Ironwood compact blocks and tree state before the
  wallet depends on it. Zaino 0.10.1 (2026-09-29) reports the `ironwood` pool
  in `getblockchaininfo` and writes the Ironwood `finalRoot` in
  `z_gettreestate`, so a Zaino-backed endpoint is the expected answer.
  Both endpoints are TLS on 443.
- Measured by sequence 03 on 2026-10-22 with `cargo run --bin
  payer_wallet`, which calls `GetLatestBlock` and `GetTreeState` over TLS
  and does nothing else:
  - `testnet.zec.rocks:443` answered gRPC at tip 4,530,274 with a
    non-empty Ironwood tree in `TreeState.ironwood_tree`. It is the light
    server the payer wallet uses.
  - `zaino.testnet.unsafe.zec.rocks:443` answered HTTP 503 Service
    Unavailable, not gRPC.
  - `testnet.zec.rocks` serves Ironwood actions in compact blocks. The
    payer wallet's first light-client scan, approved by Lance on 2026-10-22,
    found the faucet note in the Ironwood pool from compact blocks alone.
  - `testnet.zec.rocks` accepts Ironwood transactions through
    `send_transaction`, and `get_transaction` reports their heights. Sequence
    05 broadcast four on 2026-10-22, all mined: two escrow fundings and two
    FROST-signed escrow spends (`runs/fill.json`, `runs/refund.json`). No
    local node was used at any point.
- TLS: `Cargo.toml` turns on `zcash_client_backend`'s
  `lightwalletd-tonic-transport` and `lightwalletd-tonic-tls-webpki-roots`,
  plus `tonic` 0.14 with `tls-ring` and `tokio`. ring is the rustls provider
  because aws-lc-rs needs cmake. The crates this added to `Cargo.lock` are
  all permissive: ring (Apache-2.0 AND ISC), rustls (Apache-2.0 OR ISC OR
  MIT), rustls-webpki (ISC), webpki-roots (CDLA-Permissive-2.0), and
  tokio-rustls, h2, tower, mio, and the rest (MIT or Apache-2.0). No existing
  package changed version.
- Full node, if a local one is ever needed: Zebra v7.0.0 (2026-10-22),
  which carries the NU7 heights above.
- Wallet: Zallet v0.1.0-beta.3 (2026-08-26) has PCZT JSON-RPC methods and
  `z_sendfromaccount` on the PCZT pipeline. Its release notes do not mention
  Ironwood, so it is not the broadcast path; the crate builds and submits
  transactions itself through `zcash_client_backend`'s `send_transaction`.

## Funding

- Zcash testnet TAZ: https://faucet.testnet.valargroup.dev sends 0.125 TAZ
  a day and states "Unified, Sapling and transparent testnet addresses are
  accepted." https://zcashfaucet.jinolabs.xyz sends 0.1 TAZ per address
  every 24 hours as a shielded transfer from its own Zebra and Zallet; its
  page showed an "empty" state marker on 2026-10-22. Neither page says
  whether it pays an Ironwood receiver. Since NU6.3 forbids cross-address
  Orchard outputs in v6 bundles, a faucet running current software pays an
  Ironwood receiver when the unified address carries one. The payer wallet's
  unified address therefore carries only the Orchard receiver that Ironwood
  shares: no Sapling and no transparent receiver (decided by Lance on
  2026-10-22, replacing an Orchard-plus-Sapling address that was never
  funded). No Sapling spend is ever built, so the Prover section stands. Two
  faucet days cover one fill and one refund at the amounts sequence 05 uses.
- NEAR testnet: near-cli-rs creates and funds an account from the faucet
  service. Two accounts are needed, one solver that pays and one payer that
  receives. The solver wraps NEAR into wNEAR with `near_deposit` on
  `wrap.testnet`, and the payer account registers once with
  `storage_deposit` on `wrap.testnet`.
- NEAR accounts, created 2026-10-22 with near-cli-rs 0.26.2 (0.30.1 needs
  rustc 1.93; this machine has 1.92 and the toolchain was not changed) via
  `account create-account sponsor-by-faucet-service`:
  `ironwood-solver-a5slbw.testnet` (10 NEAR, 0.1 wrapped to wNEAR) and
  `ironwood-payer-a5slbw.testnet` (registered on `wrap.testnet`). Their key
  files are in `~/.ironwood-intent-escrow/testnet/near/`, mode 0600,
  outside every repository; `run.json` there names the accounts and the CLI
  for the run binaries.
- Payer wallet: a `zcash_client_sqlite` database owned by this crate, in
  `src/wallet.rs` (sequence 03), holding one unified spending key for the
  funding note and a second for refund addresses. No external wallet
  application holds payer funds.
- Payer wallet on testnet, created 2026-10-22 by `cargo run --bin
  payer_wallet -- ~/.ironwood-intent-escrow/testnet/payer`. The directory is
  outside every repository, mode 0700. It holds `payer_wallet.key`,
  `refund.key`, `payer_wallet.sqlite`, and `birthday.json`, each mode 0600.
  The birthday is height 4,530,275, taken from the `testnet.zec.rocks` tree
  state at 4,530,274.
- Faucet payment: done 2026-10-22. `POST /api/claim` on
  https://faucet.testnet.valargroup.dev, which needs no browser or captcha,
  paid 0.125 TAZ to the address in `runs/payer_address.txt`. The note was
  mined at height 4,530,426 in the Ironwood pool, and
  `PayerWallet::spendable_note` returned it after the default ten
  confirmations. https://zcashfaucet.jinolabs.xyz needs a browser captcha
  and was not used. One payout covers both runs: each escrow note is well
  under half of it.
- The Orchard-pool case did not occur: the valar faucet paid the Orchard
  receiver into the Ironwood pool, so no Orchard-to-Ironwood move is built.

## Not pinned

Nothing. The light server is `testnet.zec.rocks:443` for tree state,
compact blocks, and broadcast, measured above.
