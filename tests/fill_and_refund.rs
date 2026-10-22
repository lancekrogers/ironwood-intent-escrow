//! The checker on both recorded runs. Run with
//! `cargo test --test fill_and_refund`.
//!
//! Reads only `runs/`: the two records, the four raw transactions, the
//! fetched NEAR payload, and the two quotes. It generates no key and touches
//! no network. A missing record fails the test; it never skips.

mod common;

use std::path::PathBuf;

use ironwood_intent_escrow::attest::{attest, check_payload, Banned, NearRpc, NearTxPointer};
use ironwood_intent_escrow::checker::check_zec;
use ironwood_intent_escrow::quote::Quote;
use ironwood_intent_escrow::run::sha256;
use ironwood_intent_escrow::Error;
use serde_json::Value;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

fn runs(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("runs")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn record(name: &str) -> Value {
    serde_json::from_slice(&runs(name)).unwrap()
}

fn txid_of(name: &str) -> zcash_primitives::transaction::TxId {
    Transaction::read(&runs(name)[..], BranchId::Nu7)
        .unwrap()
        .txid()
}

/// The `Banned` set task 03 names: the escrow address, the refund address,
/// both Zcash ids of the fill, and the zatoshi amount.
fn banned(fill: &Value, refund: &Value) -> Banned {
    Banned::new()
        .address(fill["escrow_address"].as_str().unwrap())
        .address(refund["refund_address"].as_str().unwrap())
        .txid(&txid_of("fill.fund.tx"))
        .txid(&txid_of("fill.spend.tx"))
        .zatoshis(fill["escrow_zatoshis"].as_u64().unwrap())
}

struct StoredRpc(Vec<u8>);

impl NearRpc for StoredRpc {
    fn url(&self) -> &str {
        "runs/fill.near.json"
    }
    fn tx(&self, _hash: &str, _sender: &str) -> Result<Vec<u8>, Error> {
        Ok(self.0.clone())
    }
}

fn pointer(fill: &Value) -> NearTxPointer {
    NearTxPointer {
        hash: fill["near_tx_hash"].as_str().unwrap().to_string(),
        sender: fill["near_sender"].as_str().unwrap().to_string(),
    }
}

#[test]
fn fill_and_refund_banned_fixture_fails() {
    let fill = record("fill.json");
    let refund = record("refund.json");
    let quote = Quote::parse(std::str::from_utf8(&runs("fill.quote.json")).unwrap()).unwrap();
    let fixture = common::fixture_bytes("near_banned.json");
    let err = check_payload(
        &common::fixture_quote(),
        &common::fixture_pointer(),
        &banned(&fill, &refund),
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
        refund["refund_address"].as_str().unwrap()
    )));
    let mutated = serde_json::to_vec(&payload).unwrap();
    let err =
        check_payload(&quote, &pointer(&fill), &banned(&fill, &refund), &mutated).unwrap_err();
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
    let fill = record("fill.json");
    let refund = record("refund.json");
    assert_eq!(
        fill["fund_txid"].as_str().unwrap(),
        txid_of("fill.fund.tx").to_string()
    );
    assert_eq!(
        fill["spend_txid"].as_str().unwrap(),
        txid_of("fill.spend.tx").to_string()
    );
    assert_eq!(
        refund["fund_txid"].as_str().unwrap(),
        txid_of("refund.fund.tx").to_string()
    );
    assert_eq!(
        refund["spend_txid"].as_str().unwrap(),
        txid_of("refund.spend.tx").to_string()
    );
}

#[test]
fn fill_and_refund_near_payload_attests() {
    let fill = record("fill.json");
    let refund = record("refund.json");
    let payload = runs("fill.near.json");
    assert_eq!(
        hex::encode(sha256(&payload)),
        fill["near_payload_sha256"].as_str().unwrap()
    );
    let quote = Quote::parse(std::str::from_utf8(&runs("fill.quote.json")).unwrap()).unwrap();
    assert_eq!(quote.id.to_hex(), fill["quote_id"].as_str().unwrap());
    let attestation = attest(
        &quote,
        &pointer(&fill),
        &banned(&fill, &refund),
        &StoredRpc(payload),
    )
    .unwrap();
    assert_eq!(
        hex::encode(attestation.payload_sha256),
        fill["near_payload_sha256"].as_str().unwrap()
    );
}

#[test]
fn fill_and_refund_refund_address_stays_off_the_fill_side() {
    let refund = record("refund.json");
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
    let fill = record("fill.json");
    let refund = record("refund.json");
    assert_eq!(fill["deadline_refused_release"], Value::Bool(true));
    assert_eq!(refund["fill_package_still_refused"], Value::Bool(true));
    assert_eq!(refund["deadline_signed_after_expiry"], Value::Bool(true));
    for r in [&fill, &refund] {
        let broadcast = r["broadcast"].as_str().unwrap();
        assert!(broadcast == "sent" || broadcast == "blocked", "{broadcast}");
        if broadcast == "sent" {
            assert!(r["fund_mined_height"].as_u64().is_some());
            assert!(r["spend_mined_height"].as_u64().is_some());
        }
    }
}
