//! The checker on both recorded runs. Run with
//! `cargo test --test fill_and_refund`.
//!
//! Reads only `runs/`: the two records, the four raw transactions, the
//! fetched NEAR payload, and the two quotes. It generates no key and touches
//! no network. A missing record fails the test; it never skips.

mod common;

use common::{runs_file as runs, StoredRpc};
use ironwood_intent_escrow::attest::{attest, check_payload};
use ironwood_intent_escrow::checker::check_zec;
use ironwood_intent_escrow::run::sha256;
use ironwood_intent_escrow::verify::{txid_of, Records};
use ironwood_intent_escrow::Error;
use serde_json::Value;

/// The records directory through the same loader `verify` uses, so the
/// banned set and the pointer are the binary's own.
fn records() -> Records {
    Records::load(&std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("runs")).unwrap()
}

fn txid(name: &str) -> String {
    txid_of(&runs(name)).unwrap().to_string()
}

#[test]
fn fill_and_refund_banned_fixture_fails() {
    let r = records();
    let fixture = common::fixture_bytes("near_banned.json");
    let err = check_payload(
        &common::fixture_quote(),
        &common::fixture_pointer(),
        &r.banned().unwrap(),
        &fixture,
    )
    .unwrap_err();
    assert!(matches!(err, Error::BannedField(_)), "{err}");

    // The recorded payload with a testnet address planted in a log fails too.
    let mut payload: Value = serde_json::from_slice(&runs("fill.near.json")).unwrap();
    let logs = payload["result"]["receipts_outcome"][0]["outcome"]["logs"]
        .as_array_mut()
        .unwrap();
    logs.push(Value::String(format!(
        "to {}",
        r.refund["refund_address"].as_str().unwrap()
    )));
    let mutated = serde_json::to_vec(&payload).unwrap();
    let err = check_payload(
        &r.fill_quote,
        &r.pointer().unwrap(),
        &r.banned().unwrap(),
        &mutated,
    )
    .unwrap_err();
    assert!(matches!(err, Error::BannedField(_)), "{err}");
}

#[test]
fn fill_and_refund_zec_transactions_pass_the_checker() {
    for name in [
        "fill.fund.tx",
        "fill.spend.tx",
        "refund.fund.tx",
        "refund.spend.tx",
    ] {
        check_zec(&runs(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    let r = records();
    assert_eq!(r.fill["fund_txid"].as_str().unwrap(), txid("fill.fund.tx"));
    assert_eq!(
        r.fill["spend_txid"].as_str().unwrap(),
        txid("fill.spend.tx")
    );
    assert_eq!(
        r.refund["fund_txid"].as_str().unwrap(),
        txid("refund.fund.tx")
    );
    assert_eq!(
        r.refund["spend_txid"].as_str().unwrap(),
        txid("refund.spend.tx")
    );
}

#[test]
fn fill_and_refund_near_payload_attests() {
    let r = records();
    let payload = runs("fill.near.json");
    assert_eq!(
        hex::encode(sha256(&payload)),
        r.fill["near_payload_sha256"].as_str().unwrap()
    );
    assert_eq!(
        r.fill_quote.id.to_hex(),
        r.fill["quote_id"].as_str().unwrap()
    );
    let attestation = attest(
        &r.fill_quote,
        &r.pointer().unwrap(),
        &r.banned().unwrap(),
        &StoredRpc(payload),
    )
    .unwrap();
    assert_eq!(
        hex::encode(attestation.payload_sha256),
        r.fill["near_payload_sha256"].as_str().unwrap()
    );
}

#[test]
fn fill_and_refund_refund_address_stays_off_the_fill_side() {
    let refund = records().refund;
    let address = refund["refund_address"].as_str().unwrap();
    assert!(address.starts_with("utest1"), "{address}");
    for name in [
        "fill.json",
        "fill.near.json",
        "fill.quote.json",
        "refund.quote.json",
    ] {
        let bytes = runs(name);
        assert!(
            !bytes
                .windows(address.len())
                .any(|w| w == address.as_bytes()),
            "{name}"
        );
    }
    assert_eq!(refund["refund_address_in_quote"], Value::Bool(false));
}

#[test]
fn fill_and_refund_records_the_policy_outcomes() {
    let Records { fill, refund, .. } = records();
    assert_eq!(fill["deadline_refused_release"], Value::Bool(true));
    assert_eq!(refund["fill_package_still_refused"], Value::Bool(true));
    assert_eq!(refund["deadline_signed_after_expiry"], Value::Bool(true));
    // The refund was signed under the fill-claim guard, and the guard
    // refused the fill's quote as paid (docs/decisions/fill-claims.md).
    assert_eq!(refund["fill_claim_checked"], Value::Bool(true));
    assert_eq!(
        refund["fill_quote_refund_refused"],
        Value::String("quote_paid".into())
    );
    for r in [&fill, &refund] {
        let broadcast = r["broadcast"].as_str().unwrap();
        assert!(broadcast == "sent" || broadcast == "blocked", "{broadcast}");
        if broadcast == "sent" {
            assert!(r["fund_mined_height"].as_u64().is_some());
            assert!(r["spend_mined_height"].as_u64().is_some());
        }
    }
}
