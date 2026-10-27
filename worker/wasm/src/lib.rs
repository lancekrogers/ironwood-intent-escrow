//! The same read-only checks as the CLI, with public records embedded and
//! network responses supplied by the Worker. No wallet or signing code is built.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use ironwood_intent_escrow::verify::*;
use serde::Deserialize;
use serde_json::{json, Value};
use wasm_bindgen::prelude::*;

fn records() -> Records {
    macro_rules! files {
        ($($name:literal),+ $(,)?) => {
            BTreeMap::from([$(($name.to_owned(), include_bytes!(concat!("../../../runs/", $name)).to_vec())),+])
        };
    }
    Records::from_files(files!(
        "fill.json",
        "refund.json",
        "fill.quote.json",
        "refund.quote.json",
        "fill.near.json",
        "fill.fund.tx",
        "fill.spend.tx",
        "refund.fund.tx",
        "refund.spend.tx",
    ))
    .expect("embedded public run records must parse")
}

// These bytes are embedded in the deployed module and never change. Prepare their
// cryptographic checks during Worker startup, outside the per-request CPU budget.
// Live responses may reuse a result only after exact byte equality; changed bytes
// still go through the original checker and failed fetches never reuse a pass.
struct PreparedTx {
    bytes: Vec<u8>,
    txid: Check,
    zec: Check,
}

struct Prepared {
    records: Records,
    transactions: Vec<PreparedTx>,
}

fn prepared() -> &'static Prepared {
    static PREPARED: OnceLock<Prepared> = OnceLock::new();
    PREPARED.get_or_init(|| {
        let records = records();
        let transactions = ZEC_TXS
            .iter()
            .map(|tx| {
                let bytes = records.bytes(tx.file).expect("embedded transaction");
                PreparedTx {
                    txid: txid_check(&records, tx),
                    zec: zec_check(tx, Some(&bytes)),
                    bytes,
                }
            })
            .collect();
        Prepared {
            records,
            transactions,
        }
    })
}

/// Fixed upstream requests. The HTTP handler accepts no transaction IDs or URLs.
#[wasm_bindgen]
pub fn request_spec() -> String {
    let records = &prepared().records;
    let pointer = records.pointer().expect("recorded NEAR pointer");
    json!({
        "zcash_url": records.light_server().expect("recorded light server"),
        "transactions": ZEC_TXS.iter().map(|tx| json!({
            "file": tx.file,
            "txid": records.txid(tx).expect("recorded txid").to_string(),
        })).collect::<Vec<_>>(),
        "near_url": records.near_rpc_url().expect("recorded archival RPC"),
        "near_hash": pointer.hash,
        "near_sender": pointer.sender,
    })
    .to_string()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fetched {
    data: Option<String>,
    height: Option<u64>,
    error: Option<String>,
}

impl Fetched {
    fn decode(self) -> Result<(Vec<u8>, u64), String> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let bytes = hex::decode(self.data.ok_or("missing fetched bytes")?)
            .map_err(|e| format!("invalid fetched bytes: {e}"))?;
        Ok((bytes, self.height.ok_or("missing mined height")?))
    }
}

fn check_responses(zcash: &str, near: &[u8], near_error: &str) -> Result<Value, String> {
    let mut fetched: BTreeMap<String, Fetched> = serde_json::from_str(zcash)
        .map_err(|e| format!("invalid fetched transaction response: {e}"))?;
    let prepared = prepared();
    let records = &prepared.records;
    let mut checks = Vec::new();
    for (tx, cached) in ZEC_TXS.iter().zip(&prepared.transactions) {
        checks.push(cached.txid.clone());
        let response = fetched
            .remove(tx.file)
            .ok_or_else(|| "no response from light server".to_owned())
            .and_then(Fetched::decode);
        checks.push(fetched_check(records, tx, &response));
        let bytes = response.as_ref().ok().map(|(bytes, _)| bytes.as_slice());
        checks.push(if bytes == Some(cached.bytes.as_slice()) {
            cached.zec.clone()
        } else {
            zec_check(tx, bytes)
        });
    }
    if !fetched.is_empty() {
        return Err("unexpected fetched transaction".into());
    }
    let payload = if near_error.is_empty() {
        Ok(near.to_vec())
    } else {
        Err(near_error.to_owned())
    };
    checks.push(near_recorded_check(records));
    checks.push(near_fetched_check(records, &payload));
    checks.push(near_attests_check(records, payload.as_deref().ok()));
    checks.push(refund_address_check(records));
    checks.push(policy_check(records));
    checks.push(broadcast_check(records));
    let passed = all_passed(&checks);
    let checks: Vec<_> = checks
        .into_iter()
        .map(|check| {
            let scope = if check.name.ends_with(" fetched") {
                "network"
            } else if matches!(
                check.name.as_str(),
                "policy outcomes recorded" | "broadcast sent"
            ) {
                "recorded"
            } else {
                "validation"
            };
            let (status, detail) = match check.outcome {
                Outcome::Pass => ("pass", String::new()),
                Outcome::Fail(reason) => ("fail", reason),
                Outcome::Skipped => ("skip", String::new()),
            };
            json!({"name": check.name, "status": status, "detail": detail, "scope": scope})
        })
        .collect();
    Ok(json!({"status": if passed { "passed" } else { "failed" }, "checks": checks}))
}

/// Return all 18 checks, including failures. Transport failure never becomes a pass.
#[wasm_bindgen]
pub fn verify_responses(zcash: &str, near: &[u8], near_error: &str) -> Result<String, JsValue> {
    check_responses(zcash, near, near_error)
        .map(|report| report.to_string())
        .map_err(|error| JsValue::from_str(&error))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn responses() -> Value {
        let records = records();
        let mut fetched = serde_json::Map::new();
        for tx in &ZEC_TXS {
            fetched.insert(
                tx.file.into(),
                json!({
                    "data": hex::encode(records.bytes(tx.file).unwrap()),
                    "height": records.record(tx)[tx.height_field],
                }),
            );
        }
        Value::Object(fetched)
    }

    #[test]
    fn recorded_responses_pass_all_eighteen_checks() {
        let report =
            check_responses(&responses().to_string(), &records().near_payload, "").unwrap();
        assert_eq!(report["status"], "passed");
        assert_eq!(report["checks"].as_array().unwrap().len(), 18);
    }

    #[test]
    fn wrong_height_and_missing_receipt_fail() {
        let mut fetched = responses();
        fetched["fill.fund.tx"]["height"] = json!(0);
        let report = check_responses(&fetched.to_string(), &[], "RPC unavailable").unwrap();
        assert_eq!(report["status"], "failed");
        let failed: Vec<_> = report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["status"] == "fail")
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            failed,
            [
                "fill.fund.tx fetched",
                "near payment fetched",
                "near payment attests"
            ]
        );
    }

    #[test]
    fn missing_or_corrupt_transactions_never_pass() {
        let mut fetched = responses();
        fetched.as_object_mut().unwrap().remove("refund.spend.tx");
        fetched["fill.spend.tx"]["data"] = json!("00");
        let report = check_responses(&fetched.to_string(), &records().near_payload, "").unwrap();
        assert_eq!(report["status"], "failed");
        assert_eq!(
            report["checks"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|c| c["status"] == "fail")
                .count(),
            4
        );
        assert!(check_responses("not json", &[], "").is_err());
    }
}
