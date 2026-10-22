//! `check_zec` on raw transaction bytes. Run with `cargo test check_zec`.
//!
//! Three fixtures, each a proved and signed funding transaction from a
//! synthetic note: a valid one from the library's `fund_pczt`, one with a
//! transparent output, and one whose escrow output is encrypted to the
//! all-zero outgoing viewing key.

mod common;

use common::{escrow, fixture, inputs, payer, sign_prove_extract, AMOUNT};
use ironwood_intent_escrow::checker::check_zec;
use ironwood_intent_escrow::note::{fund_pczt, tx_bytes, ZERO_OVK};
use ironwood_intent_escrow::Error;
use orchard::keys::Scope;
use zcash_protocol::consensus::Network;
use zcash_protocol::value::Zatoshis;

#[test]
fn check_zec_fails_a_transparent_output() {
    let payer = payer();
    let tx = fixture(&payer, *payer.fvk.to_ovk(Scope::External).as_ref(), true);
    let err = check_zec(&tx_bytes(&tx).unwrap()).unwrap_err();
    assert!(matches!(err, Error::TransparentOutput), "{err}");
    assert!(err.to_string().starts_with("transparent_output"));
}

#[test]
fn check_zec_fails_the_zero_outgoing_viewing_key() {
    let payer = payer();
    let tx = fixture(&payer, ZERO_OVK, false);
    let err = check_zec(&tx_bytes(&tx).unwrap()).unwrap_err();
    assert!(matches!(err, Error::ZeroOutgoingViewingKey), "{err}");
    assert!(err.to_string().starts_with("zero_outgoing_viewing_key"));
}

#[test]
fn check_zec_fails_bytes_that_are_not_a_transaction() {
    let err = check_zec(&[0x05, 0x00, 0x00, 0x80]).unwrap_err();
    assert!(matches!(err, Error::Checker(_)), "{err}");
}

#[test]
fn check_zec_accepts_a_valid_fund() {
    let payer = payer();
    let fund = fund_pczt(
        Network::TestNetwork,
        &inputs(&payer),
        &escrow(),
        Zatoshis::const_from_u64(AMOUNT),
        payer.fvk.to_ovk(Scope::External),
    )
    .unwrap();
    let tx = sign_prove_extract(&payer, fund.pczt, fund.spend_index);
    check_zec(&tx_bytes(&tx).unwrap()).unwrap();
}
