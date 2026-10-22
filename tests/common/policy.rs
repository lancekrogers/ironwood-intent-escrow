//! Fixtures for the policy tests: a `keygen` escrow with a synthetic note,
//! an offline payer wallet, and the three role-checked signers.

use ironwood_intent_escrow::attest::Banned;
use ironwood_intent_escrow::frost::ShareFile;
use ironwood_intent_escrow::note::{
    escrow_spend_fee, spend_pczt, EscrowSpend, NoteInputs, SpendOutput,
};
use ironwood_intent_escrow::policy::{release_ovk, DeadlineSigner, PayerSigner, SolverSigner};
use ironwood_intent_escrow::quote::Quote;
use ironwood_intent_escrow::view::{verify_package, PackageFacts};
use ironwood_intent_escrow::wallet::PayerWallet;
use orchard::keys::FullViewingKey;
use tempfile::TempDir;
use zcash_keys::address::UnifiedAddress;
use zcash_protocol::consensus::Network;
use zcash_protocol::value::Zatoshis;

use super::{escrow_note, offline_wallet, throwaway_address, ESCROW_VALUE};

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
