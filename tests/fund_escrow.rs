//! The funding transaction, built offline from a synthetic Ironwood note.
//! Run with `cargo test fund_escrow`.
//!
//! The note sits alone in a one-leaf commitment tree, so its Merkle path and
//! anchor are computed here, not scanned. Everything after the inputs is the
//! real path: the builder, the PCZT roles, the Ironwood proof, the payer's
//! spend authorization, and the extracted transaction.

use incrementalmerkletree::{Hashable, Level};
use ironwood_intent_escrow::address::escrow_address;
use ironwood_intent_escrow::frost::keygen;
use ironwood_intent_escrow::note::{
    actions_opening_under, extract, fund_pczt, no_action_opens_under_zero_ovk, prove,
    transparent_bundle_is_empty, tx_bytes, FundInputs, ZERO_OVK,
};
use ironwood_intent_escrow::Error;
use orchard::keys::{FullViewingKey, OutgoingViewingKey, Scope, SpendAuthorizingKey, SpendingKey};
use orchard::note::{NoteVersion, RandomSeed, Rho};
use orchard::tree::{MerkleHashOrchard, MerklePath};
use orchard::value::NoteValue;
use pczt::roles::creator::Creator;
use pczt::roles::io_finalizer::IoFinalizer;
use pczt::roles::signer::Signer;
use pczt::Pczt;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use rand::TryRng;
use zcash_keys::address::UnifiedAddress;
use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
use zcash_primitives::transaction::fees::zip317::FeeRule;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::TransparentAddress;

const NOTE_VALUE: u64 = 12_500_000;
const AMOUNT: u64 = 4_000_000;
const TARGET: u32 = 4_530_500;

struct Payer {
    sk: SpendingKey,
    fvk: FullViewingKey,
}

fn random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    SysRng.try_fill_bytes(&mut bytes).unwrap();
    bytes
}

fn payer() -> Payer {
    let sk = loop {
        if let Some(sk) = Option::from(SpendingKey::from_bytes(random_bytes())) {
            break sk;
        }
    };
    let fvk = FullViewingKey::from(&sk);
    Payer { sk, fvk }
}

/// One V3 note to the payer, alone in a one-leaf tree at position 0.
fn inputs(payer: &Payer) -> FundInputs {
    let rho = loop {
        if let Some(rho) = Option::from(Rho::from_bytes(&random_bytes())) {
            break rho;
        }
    };
    let rseed = loop {
        if let Some(rseed) = Option::from(RandomSeed::from_bytes(random_bytes(), &rho)) {
            break rseed;
        }
    };
    let note = orchard::Note::from_parts(
        payer.fvk.address_at(0u32, Scope::External),
        NoteValue::from_raw(NOTE_VALUE),
        rho,
        rseed,
        NoteVersion::V3,
    )
    .unwrap();
    let auth_path: [MerkleHashOrchard; 32] =
        std::array::from_fn(|level| MerkleHashOrchard::empty_root(Level::from(level as u8)));
    let merkle_path = MerklePath::from_parts(0, auth_path);
    let anchor = merkle_path.root(note.commitment().into());
    FundInputs {
        fvk: payer.fvk.clone(),
        note,
        merkle_path,
        anchor,
        target_height: BlockHeight::from_u32(TARGET),
    }
}

fn escrow() -> UnifiedAddress {
    let dir = tempfile::tempdir().unwrap();
    escrow_address(&keygen(dir.path()).unwrap())
}

fn sign_prove_extract(payer: &Payer, pczt: Pczt, spend_index: usize) -> Transaction {
    let pczt = prove(pczt).unwrap();
    let mut signer = Signer::new(pczt).unwrap();
    signer
        .sign_ironwood(
            UnwrapErr(SysRng),
            spend_index,
            &SpendAuthorizingKey::from(&payer.sk),
        )
        .unwrap();
    extract(signer.finish()).unwrap()
}

/// A funding transaction built outside the library's guards, for the two
/// negative fixtures: an escrow output to `escrow_ovk`, and optionally a
/// transparent output.
fn fixture(payer: &Payer, escrow_ovk: [u8; 32], transparent: bool) -> Transaction {
    let inputs = inputs(payer);
    let escrow = *escrow().orchard().unwrap();
    let transparent_value = if transparent { 1_000_000 } else { 0 };
    let assemble = |change: u64| {
        let mut builder = Builder::new(
            Network::TestNetwork,
            inputs.target_height,
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: Some(inputs.anchor),
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        builder
            .add_ironwood_spend::<std::convert::Infallible>(
                payer.fvk.clone(),
                inputs.note,
                inputs.merkle_path.clone(),
            )
            .unwrap();
        builder
            .add_ironwood_output::<std::convert::Infallible>(
                Some(OutgoingViewingKey::from(escrow_ovk)),
                escrow,
                Zatoshis::const_from_u64(AMOUNT),
                MemoBytes::empty(),
            )
            .unwrap();
        if transparent {
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKeyHash([0x11; 20]),
                    Zatoshis::const_from_u64(transparent_value),
                )
                .unwrap();
        }
        builder
            .add_ironwood_output::<std::convert::Infallible>(
                Some(payer.fvk.to_ovk(Scope::Internal)),
                payer.fvk.address_at(0u32, Scope::Internal),
                Zatoshis::const_from_u64(change),
                MemoBytes::empty(),
            )
            .unwrap();
        builder
    };
    let fee = assemble(0)
        .get_fee(&FeeRule::standard())
        .unwrap()
        .into_u64();
    let built = assemble(NOTE_VALUE - AMOUNT - transparent_value - fee)
        .build_for_pczt(UnwrapErr(SysRng), &FeeRule::standard())
        .unwrap();
    let spend_index = built.ironwood_meta.spend_action_index(0).unwrap();
    let pczt = Creator::build_from_parts(built.pczt_parts).unwrap();
    let pczt = IoFinalizer::new(pczt)
        .finalize_io(UnwrapErr(SysRng))
        .unwrap();
    sign_prove_extract(payer, pczt, spend_index)
}

#[test]
fn fund_escrow_check_fails_a_transparent_output() {
    let payer = payer();
    let tx = fixture(&payer, *payer.fvk.to_ovk(Scope::External).as_ref(), true);
    assert!(!transparent_bundle_is_empty(&tx));
    assert!(no_action_opens_under_zero_ovk(&tx));
}

#[test]
fn fund_escrow_check_fails_an_output_under_the_zero_ovk() {
    let payer = payer();
    let tx = fixture(&payer, ZERO_OVK, false);
    assert!(transparent_bundle_is_empty(&tx));
    assert!(!no_action_opens_under_zero_ovk(&tx));
    assert_eq!(
        actions_opening_under(&tx, &OutgoingViewingKey::from(ZERO_OVK)).len(),
        1
    );
}

#[test]
fn fund_escrow_refuses_the_zero_ovk() {
    let payer = payer();
    let err = fund_pczt(
        Network::TestNetwork,
        &inputs(&payer),
        &escrow(),
        Zatoshis::const_from_u64(AMOUNT),
        OutgoingViewingKey::from(ZERO_OVK),
    )
    .err()
    .unwrap();
    assert!(matches!(err, Error::ZeroOutgoingViewingKey), "{err}");
}

#[test]
fn fund_escrow_refuses_an_amount_the_note_does_not_cover() {
    let payer = payer();
    let err = fund_pczt(
        Network::TestNetwork,
        &inputs(&payer),
        &escrow(),
        Zatoshis::const_from_u64(NOTE_VALUE),
        payer.fvk.to_ovk(Scope::External),
    )
    .err()
    .unwrap();
    assert!(matches!(err, Error::InsufficientFunds { .. }), "{err}");
}

#[test]
fn fund_escrow_transaction_is_ironwood_only_with_real_ovks() {
    let payer = payer();
    let escrow_ua = escrow();
    let external = payer.fvk.to_ovk(Scope::External);
    let internal = payer.fvk.to_ovk(Scope::Internal);
    let fund = fund_pczt(
        Network::TestNetwork,
        &inputs(&payer),
        &escrow_ua,
        Zatoshis::const_from_u64(AMOUNT),
        external.clone(),
    )
    .unwrap();
    let (fee, change) = (fund.fee.into_u64(), fund.change.into_u64());
    assert_eq!(change, NOTE_VALUE - AMOUNT - fee);
    let tx = sign_prove_extract(&payer, fund.pczt, fund.spend_index);
    let ironwood = tx.ironwood_bundle().expect("an Ironwood bundle");
    println!(
        "fund: {} Ironwood actions, fee {fee} zatoshis, change {change}",
        ironwood.actions().len()
    );

    // transparent_bundle_is_empty
    assert!(transparent_bundle_is_empty(&tx));
    assert!(tx.orchard_bundle().is_none());
    // no_action_opens_under_zero_ovk
    assert!(no_action_opens_under_zero_ovk(&tx));

    // The escrow output opens under the payer's external key, pays the
    // escrow receiver the amount, and the change opens under the internal key.
    let opened: Vec<(orchard::Address, u64)> = [&external, &internal]
        .into_iter()
        .flat_map(|ovk| ironwood.recover_outputs_with_ovks(std::slice::from_ref(ovk)))
        .map(|(_, _, note, address, _)| (address, note.value().inner()))
        .collect();
    assert!(opened.contains(&(*escrow_ua.orchard().unwrap(), AMOUNT)));
    assert!(opened.contains(&(payer.fvk.address_at(0u32, Scope::Internal), change)));
    assert_eq!(opened.len(), 2);

    // The raw bytes round-trip, which is what check_zec and runs/ consume.
    let bytes = tx_bytes(&tx).unwrap();
    let parsed = Transaction::read(&bytes[..], BranchId::Nu7).unwrap();
    assert_eq!(parsed.txid(), tx.txid());
}
