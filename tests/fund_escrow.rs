//! The funding transaction, built offline from a synthetic Ironwood note.
//! Run with `cargo test fund_escrow`.
//!
//! The note sits alone in a one-leaf commitment tree, so its Merkle path and
//! anchor are computed here, not scanned. Everything after the inputs is the
//! real path: the builder, the PCZT roles, the Ironwood proof, the payer's
//! spend authorization, and the extracted transaction.

mod common;

use common::{escrow, fixture, inputs, payer, sign_prove_extract, AMOUNT, NOTE_VALUE};
use ironwood_intent_escrow::note::{
    actions_opening_under, fund_pczt, no_action_opens_under_zero_ovk, transparent_bundle_is_empty,
    tx_bytes, ZERO_OVK,
};
use ironwood_intent_escrow::Error;
use orchard::keys::{OutgoingViewingKey, Scope};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BranchId, Network};
use zcash_protocol::value::Zatoshis;

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
