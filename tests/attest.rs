//! `attest` against fixture NEAR responses. Run with `cargo test attest`.
//!
//! The fixtures are `tx` results in the shape `receipt-chain.md` records: an
//! `ft_transfer` on `wrap.testnet` with the quote id as memo, and the NEP-297
//! event log. `near_banned.json` plants a `utest1` address in a log, and
//! `near_gas.json` puts the escrow's zatoshi amount in `gas` and `gas_burnt`.

use std::path::PathBuf;

use ironwood_intent_escrow::attest::{attest, check_payload, Banned, NearRpc, NearTxPointer};
use ironwood_intent_escrow::quote::{Quote, QuoteId};
use ironwood_intent_escrow::Error;
use serde_json::Value;
use sha2::{Digest, Sha256};
use zcash_primitives::transaction::TxId;

const ESCROW_ZATOSHIS: u64 = 3_990_000;

struct FixtureRpc(Vec<u8>);

impl NearRpc for FixtureRpc {
    fn url(&self) -> &str {
        "fixture://near"
    }
    fn tx(&self, _hash: &str, _sender: &str) -> Result<Vec<u8>, Error> {
        Ok(self.0.clone())
    }
}

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(path).unwrap()
}

fn quote() -> Quote {
    Quote {
        id: QuoteId::from_hex("3f9a1c7e5b2d4086a1f3c5e7092b4d6f8a0c2e4f6183a5c7e9fb1d3f5a7c9e0b")
            .unwrap(),
        destination_account: "payer-ironwood.testnet".into(),
        asset: "wrap.testnet".into(),
        amount: 250_000_000_000_000_000_000_000,
        expiry_unix: 1_792_800_000,
    }
}

fn pointer() -> NearTxPointer {
    NearTxPointer {
        hash: "4wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vigw".into(),
        sender: "solver-ironwood.testnet".into(),
    }
}

const FUND_TXID: [u8; 32] = [0x11; 32];

fn banned() -> Banned {
    Banned::new()
        .zatoshis(ESCROW_ZATOSHIS)
        .txid(&TxId::from_bytes(FUND_TXID))
}

/// `near_ok.json` with one more log line.
fn ok_with_log(line: &str) -> Vec<u8> {
    let mut doc: Value = serde_json::from_slice(&fixture("near_ok.json")).unwrap();
    doc["result"]["receipts_outcome"][0]["outcome"]["logs"]
        .as_array_mut()
        .unwrap()
        .push(Value::String(line.into()));
    serde_json::to_vec(&doc).unwrap()
}

#[test]
fn attest_banned_fixture_returns_banned_field() {
    let rpc = FixtureRpc(fixture("near_banned.json"));
    let err = attest(&quote(), &pointer(), &banned(), &rpc).unwrap_err();
    assert!(matches!(err, Error::BannedField(_)), "{err}");
    assert!(
        !err.to_string().contains("utest1"),
        "the error names the value: {err}"
    );
}

#[test]
fn attest_bans_known_values_in_the_logs() {
    for line in [
        format!("escrow {ESCROW_ZATOSHIS}"),
        format!("fund {}", hex::encode(FUND_TXID)),
    ] {
        let err = check_payload(&quote(), &pointer(), &banned(), &ok_with_log(&line)).unwrap_err();
        assert!(matches!(err, Error::BannedField(_)), "{line}: {err}");
    }
    // A prefix is not an address: a NEAR account and a short tm token pass.
    let fine = ok_with_log("tmp t2-escrow.testnet tm1234");
    check_payload(&quote(), &pointer(), &banned(), &fine).unwrap();
}

#[test]
fn attest_refuses_a_wrong_amount_or_a_missing_event_memo() {
    let mut wrong = quote();
    wrong.amount += 1;
    let err = check_payload(&wrong, &pointer(), &banned(), &fixture("near_ok.json")).unwrap_err();
    assert!(
        matches!(err, Error::MissingField(ref f) if f == "args.amount"),
        "{err}"
    );

    let mut doc: Value = serde_json::from_slice(&fixture("near_ok.json")).unwrap();
    doc["result"]["receipts_outcome"][0]["outcome"]["logs"] = Value::Array(vec![]);
    let err = check_payload(
        &quote(),
        &pointer(),
        &banned(),
        &serde_json::to_vec(&doc).unwrap(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::MissingField(_)), "{err}");
}

#[test]
fn attest_refuses_an_rpc_error_and_a_different_transaction() {
    let error = br#"{"jsonrpc":"2.0","id":"dontcare","error":{"name":"HANDLER_ERROR","cause":{"name":"UNKNOWN_TRANSACTION"}}}"#;
    let err = check_payload(&quote(), &pointer(), &banned(), error).unwrap_err();
    assert!(matches!(err, Error::Attestation(_)), "{err}");

    let mut other = pointer();
    other.hash = "11111111111111111111111111111111".into();
    let err = check_payload(&quote(), &other, &banned(), &fixture("near_ok.json")).unwrap_err();
    assert!(
        matches!(err, Error::MissingField(ref f) if f == "transaction.hash"),
        "{err}"
    );
}

#[test]
fn attest_gas_fixture_is_not_searched() {
    let rpc = FixtureRpc(fixture("near_gas.json"));
    attest(&quote(), &pointer(), &banned(), &rpc).unwrap();
}

#[test]
fn attest_ok_fixture_returns_a_payload_hash() {
    let payload = fixture("near_ok.json");
    let rpc = FixtureRpc(payload.clone());
    let attestation = attest(&quote(), &pointer(), &banned(), &rpc).unwrap();
    assert_eq!(attestation.rpc_url, "fixture://near");
    assert_eq!(attestation.tx_hash, pointer().hash);
    assert_eq!(attestation.sender, pointer().sender);
    assert_eq!(attestation.payload, payload);
    let expected: [u8; 32] = Sha256::digest(&payload).into();
    assert_eq!(attestation.payload_sha256, expected);
    // The review re-runs the check from the stored bytes alone.
    check_payload(&quote(), &pointer(), &banned(), &attestation.payload).unwrap();
}
