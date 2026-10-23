//! Fixtures for the policy tests: a `keygen` escrow with a synthetic note,
//! an offline payer wallet, and the three role-checked signers.

use ironwood_intent_escrow::attest::Banned;
use ironwood_intent_escrow::claims::{FillClaim, NoClaims};
use ironwood_intent_escrow::cosign::Share;
use ironwood_intent_escrow::frost::{round1, ShareFile};
use ironwood_intent_escrow::note::{
    escrow_spend_fee, spend_pczt, EscrowSpend, NoteInputs, SpendOutput,
};
use ironwood_intent_escrow::policy::{
    build_refund, deadline_sign, payer_refund, release_ovk, signing_package, DeadlineSigner,
    PayerSigner, RefundGuard, SolverSigner,
};
use ironwood_intent_escrow::quote::Quote;
use ironwood_intent_escrow::view::{verify_package, PackageFacts};
use ironwood_intent_escrow::wallet::PayerWallet;
use ironwood_intent_escrow::Error;
use orchard::keys::FullViewingKey;
use serde_json::Value;
use tempfile::TempDir;
use zcash_keys::address::UnifiedAddress;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;
use zcash_protocol::consensus::Network;
use zcash_protocol::value::Zatoshis;

use super::{
    escrow_note, offline_wallet, runs_file, throwaway_address, PanickingRpc, ESCROW_VALUE,
};

pub const NETWORK: Network = Network::TestNetwork;

pub struct Escrow {
    pub dir: TempDir,
    pub _wallet_dir: TempDir,
    pub inputs: NoteInputs,
    pub solver: UnifiedAddress,
    pub wallet: PayerWallet,
    pub refund_fvk: FullViewingKey,
}

pub fn escrow() -> Escrow {
    let dir = tempfile::tempdir().unwrap();
    let wallet_dir = tempfile::tempdir().unwrap();
    let inputs = escrow_note(dir.path());
    let wallet = offline_wallet(wallet_dir.path());
    let refund_fvk = wallet.refund_fvk().unwrap();
    Escrow {
        dir,
        _wallet_dir: wallet_dir,
        inputs,
        solver: throwaway_address(),
        wallet,
        refund_fvk,
    }
}

pub fn share(e: &Escrow, name: &str) -> ShareFile {
    ShareFile::read(&e.dir.path().join(name)).unwrap()
}

pub fn payer(e: &Escrow) -> PayerSigner {
    PayerSigner::new(
        share(e, "payer.key"),
        e.inputs.fvk.clone(),
        e.refund_fvk.clone(),
        &e.solver,
    )
    .unwrap()
}

pub fn deadline(e: &Escrow) -> DeadlineSigner {
    DeadlineSigner::new(
        share(e, "deadline.key"),
        e.inputs.fvk.clone(),
        e.refund_fvk.clone(),
        &e.solver,
    )
    .unwrap()
}

/// The whole escrow note, less the fee, to `to`, under the escrow OVK.
pub fn release_to(e: &Escrow, to: &UnifiedAddress, quote: &Quote) -> (EscrowSpend, PackageFacts) {
    let fee = escrow_spend_fee(NETWORK, &e.inputs, 1).unwrap().into_u64();
    let outputs = [SpendOutput {
        address: to.clone(),
        value: Zatoshis::const_from_u64(ESCROW_VALUE - fee),
    }];
    let spend = spend_pczt(
        NETWORK,
        &e.inputs,
        &outputs,
        &quote.id,
        &release_ovk(&e.inputs.fvk),
    )
    .unwrap();
    let facts = verify_package(&spend.pczt, &e.inputs.fvk).unwrap();
    (spend, facts)
}

pub fn banned() -> Banned {
    Banned::new().zatoshis(ESCROW_VALUE)
}

/// A quote whose expiry is `expiry`, for the refund tests.
pub fn quote_expiring(expiry: u64) -> Quote {
    Quote::new(
        "payer-ironwood.testnet",
        "wrap.testnet",
        250_000_000_000_000_000_000_000,
        expiry,
    )
    .unwrap()
}

pub const EXPIRY: u64 = 1_792_800_000;

pub fn solver(e: &Escrow) -> SolverSigner {
    SolverSigner::new(share(e, "solver.key"), e.inputs.fvk.clone(), &e.solver).unwrap()
}

/// The guard the tests that predate fill claims use: no claims, and an RPC
/// that panics if a signer ever fetches.
pub fn no_claims_guard() -> RefundGuard<'static> {
    RefundGuard {
        claims: &NoClaims,
        rpc: &PanickingRpc,
        banned: Banned::new(),
    }
}

/// A refund of `e`'s escrow note for `quote`, built at `now`, and its facts.
pub fn refund_for(e: &mut Escrow, quote: &Quote, now: u64) -> (EscrowSpend, PackageFacts) {
    let refund = build_refund(quote, &e.inputs, &mut e.wallet, now).unwrap();
    let facts = verify_package(&refund.pczt, &e.inputs.fvk).unwrap();
    (refund, facts)
}

/// Round 1 for the payer and the deadline device, one package, and both
/// refund signers' round 2 at `now` under `guard`: (deadline, payer).
pub fn refund_round2(
    e: &Escrow,
    quote: &Quote,
    refund: &EscrowSpend,
    facts: &PackageFacts,
    now: u64,
    guard: &RefundGuard,
) -> (Result<Share, Error>, Result<Share, Error>) {
    let (deadline_nonces, deadline_commitments) = round1(&share(e, "deadline.key"));
    let (payer_nonces, payer_commitments) = round1(&share(e, "payer.key"));
    let package = signing_package(facts, vec![payer_commitments, deadline_commitments]);
    let pczt = &refund.pczt;
    let deadline_result = deadline_sign(
        &deadline(e),
        quote,
        pczt,
        deadline_nonces,
        &package,
        now,
        guard,
    );
    let payer_result = payer_refund(&payer(e), quote, pczt, payer_nonces, &package, now, guard);
    (deadline_result, payer_result)
}

/// `runs/fill.json`, the fill run's record.
pub fn fill_record() -> Value {
    serde_json::from_slice(&runs_file("fill.json")).unwrap()
}

/// The quote the fill run's solver paid, `runs/fill.quote.json`, with its
/// expiry moved to `expiry` so a refund of it can be built.
pub fn recorded_fill_quote(expiry: u64) -> Quote {
    let mut quote =
        Quote::parse(std::str::from_utf8(&runs_file("fill.quote.json")).unwrap()).unwrap();
    quote.expiry_unix = expiry;
    quote
}

/// A claim for `quote` that points at the fill run's recorded NEAR payment.
pub fn recorded_claim(quote: &Quote) -> FillClaim {
    let fill = fill_record();
    FillClaim {
        quote_id: quote.id,
        near_tx_hash: fill["near_tx_hash"].as_str().unwrap().into(),
        near_sender: fill["near_sender"].as_str().unwrap().into(),
        rpc_url: fill["near_rpc_url"].as_str().unwrap().into(),
    }
}

/// The banned set a refund signer uses for the fill's escrow note: the
/// fill record's escrow address, fund transaction id, and zatoshi amount.
pub fn recorded_refund_banned() -> Banned {
    let fill = fill_record();
    let fund = Transaction::read(&runs_file("fill.fund.tx")[..], BranchId::Nu7).unwrap();
    Banned::new()
        .address(fill["escrow_address"].as_str().unwrap())
        .txid(&fund.txid())
        .zatoshis(fill["escrow_zatoshis"].as_u64().unwrap())
}
