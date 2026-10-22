# Decision: the share holders

Festival II0001, sequence 01, task 02. Decided 2026-10-22.

Spend authority over the escrow note is a 2-of-3 threshold over the Orchard
spend authorizing key `ask`, signed with re-randomized FROST on RedPallas.
No holder has `ask`. No process ever assembles it.

## The three shares

Three key files, produced by `keygen` in sequence 02, kept in three separate
directories and never concatenated, copied together, or printed:

| File | Holder | Process | Signs |
|---|---|---|---|
| `payer.key` | the payer | the payer process | the release, after attestation; the refund |
| `solver.key` | the solver | the solver process | the release only |
| `deadline.key` | the payer's second device | the deadline process | the refund only, after expiry |

The deadline holder is not an arbiter. It is the payer's own second device,
so the solver never holds it and the payer cannot be locked out by a third
party. Its only job is to refuse to pay the solver.

Two of the three signatures make a valid spend authorization. One signature
share is not a signature. `aggregate` in `src/frost.rs` returns
`threshold_not_met` for a single share, and the chain accepts nothing a
single share produces.

## What sits beside each share

- `escrow.fvk`: the escrow full viewing key, `ak` (the FROST verifying key),
  `nk`, and `rivk`. Every holder has a copy. It derives the escrow address,
  the incoming viewing key for scanning, and the nullifier for a spend. It
  cannot spend. How `nk` and `rivk` are produced depends on
  `docs/decisions/stack.md`: derived per ZIP 312 when distributed key
  generation is available, or derived by the trusted dealer from the
  in-memory spending key when it is not.
- The payer's refund full viewing key: held by the payer process and by the
  deadline process. The deadline signer uses it to confirm a refund output
  pays an address the payer's wallet detects. Neither process needs the
  refund spending key to make that check. The refund spending key stays in
  the payer wallet (`refund.key`, sequence 03).
- The solver's Ironwood address: an Ironwood-only unified address that the
  solver's test wallet generates. Both policy signers compare every PCZT
  output against it. It is recorded in this file once generated:

  ```
  solver_address: utest1hgqeh0gzlgrdcduysnuvkpa477tn976m3zpafv7xz0larteu7hnkvaqqergw2ll9alnepga24kaga6wved0gdrnmeq95q09sc5gqwwvq
  ```

  Filled by sequence 05 on 2026-10-22. Sequence 03 did not create the
  solver's wallet, so the fill run created it in
  `~/.ironwood-intent-escrow/testnet/solver/` and wrote this Orchard-only
  address to `runs/solver_address.txt`. An address is not key material and
  may be committed.

No file in this list is a spending key. `*.key` files are excluded by
`.gitignore`; `escrow.fvk` and the refund full viewing key stay out of the
repository too, because a full viewing key reveals every payment to the
escrow.

## No timelock

Ironwood is a shielded pool. It has no script, so it has no `nLockTime`
style refusal and no way to make a signature valid only after a height. The
deadline is therefore policy inside the deadline signer, not consensus. A
reviewer should read it that way: the chain will accept an early refund if
two shares sign it, and the design relies on the deadline holder being the
payer's own device that refuses to sign early.

## Two signing rounds

FROST is interactive. There is no single-call sign.

1. Round 1. Each signer taking part runs `round1` with its share, keeps the
   nonces in memory, and publishes `Commitments { signer, commitments }`.
2. Package. The coordinator (the payer process in both runs) builds
   `SigningPackage { sighash, randomizer, commitments, pczt_hash }` from the
   checker view of the PCZT. `randomizer` is the spend randomizer `alpha` of
   the escrow action, so the aggregate verifies against the randomized `ak`
   the transaction carries. `pczt_hash` binds the package to the PCZT the
   signer inspected.
3. Round 2. Each signer verifies the package against the PCZT it holds,
   applies its policy, and only then runs `round2` to produce
   `Share { signer, share }`. A policy refusal happens here, before any
   share exists.
4. Aggregate. The coordinator combines two shares, verifies the signature
   against the randomized verifying key, and finishes the transaction.

Sequence 02 defines these message types in `src/cosign.rs`.

## The refusal rule for `deadline_sign`

`deadline_sign(quote, pczt, nonces, package, now)` in sequence 04:

1. Check `package.pczt_hash` is the hash of `pczt` and `package.sighash` is
   the checker view's sighash. Otherwise `package_mismatch`.
2. If any output of the PCZT pays the solver address, return
   `refused_release`. This is checked first and unconditionally.
3. If the memo quote id does not equal `quote.id`, return `not_a_refund`.
4. If `now < quote.expiry_unix`, return `not_expired`. The expiry comes from
   the `Quote` the signer is handed, never from the memo. The memo carries
   only the quote id.
5. If any new shielded output is not an address the payer's refund full
   viewing key detects, return `not_a_refund`.
6. Otherwise produce the round 2 share.

The deadline signer never signs a release. Its share is not collected for
the fill, and the fill binary records that it returned `refused_release`.

## Who signs what

- Release (note to solver): payer and solver. The payer signs only after
  `attest` succeeds on the NEAR transaction per
  `docs/decisions/receipt-chain.md`. The solver signs whenever it wants to
  be paid.
- Refund (note to a fresh payer address): payer and deadline. The solver
  share is not used.
- One share alone: nothing the chain accepts.

## Key material

This file contains no key material. No decision file, example, test
fixture, or run record may contain a share, a spending key, or a full
viewing key.
