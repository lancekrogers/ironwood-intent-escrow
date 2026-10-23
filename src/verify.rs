//! The judge's check of the two recorded runs, shared by the `verify`
//! binary and the tests.
//!
//! Everything here reads only a records directory, the repository's `runs/`
//! by default: the two run records, the two quotes, the four raw Zcash
//! transactions, and the fetched NEAR payload. Nothing reads
//! `~/.ironwood-intent-escrow`, and nothing here touches the network; the
//! binary fetches and hands the fetched bytes to these checks.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::BranchId;

use crate::attest::{check_payload, Banned, NearTxPointer};
use crate::checker::check_zec;
use crate::error::Error;
use crate::quote::Quote;
use crate::run::sha256;

/// One recorded Zcash transaction: its file and where its record keeps its
/// id and height.
#[derive(Clone, Copy, Debug)]
pub struct ZecTx {
    /// The raw transaction file in the records directory.
    pub file: &'static str,
    /// The run record that names it.
    pub record: &'static str,
    /// The record field holding its display txid.
    pub txid_field: &'static str,
    /// The record field holding the height it was mined at.
    pub height_field: &'static str,
}

/// The four transactions of the two runs, in the order they were mined.
pub const ZEC_TXS: [ZecTx; 4] = [
    zec_tx("fill.fund.tx", "fill.json", "fund"),
    zec_tx("fill.spend.tx", "fill.json", "spend"),
    zec_tx("refund.fund.tx", "refund.json", "fund"),
    zec_tx("refund.spend.tx", "refund.json", "spend"),
];

const fn zec_tx(file: &'static str, record: &'static str, step: &'static str) -> ZecTx {
    let (txid_field, height_field) = match step.as_bytes() {
        b"fund" => ("fund_txid", "fund_mined_height"),
        _ => ("spend_txid", "spend_mined_height"),
    };
    ZecTx {
        file,
        record,
        txid_field,
        height_field,
    }
}

/// The records directory, loaded.
pub struct Records {
    dir: PathBuf,
    /// `fill.json`.
    pub fill: Value,
    /// `refund.json`.
    pub refund: Value,
    /// `fill.quote.json`, the quote the solver paid.
    pub fill_quote: Quote,
    /// `fill.near.json`, the NEAR payload as the payer fetched it.
    pub near_payload: Vec<u8>,
}

impl Records {
    /// Reads the records in `dir`. A missing or unreadable file is an error.
    pub fn load(dir: &Path) -> Result<Self, Error> {
        let json = |name: &str| -> Result<Value, Error> {
            serde_json::from_slice(&read(dir, name)?)
                .map_err(|e| Error::Checker(format!("{name}: {e}")))
        };
        let quote_text = String::from_utf8(read(dir, "fill.quote.json")?)
            .map_err(|e| Error::Checker(format!("fill.quote.json: {e}")))?;
        Ok(Records {
            dir: dir.to_path_buf(),
            fill: json("fill.json")?,
            refund: json("refund.json")?,
            fill_quote: Quote::parse(&quote_text)?,
            near_payload: read(dir, "fill.near.json")?,
        })
    }

    /// A file in the records directory.
    pub fn bytes(&self, name: &str) -> Result<Vec<u8>, Error> {
        read(&self.dir, name)
    }

    /// The run record a transaction belongs to.
    pub fn record(&self, tx: &ZecTx) -> &Value {
        if tx.record == "fill.json" {
            &self.fill
        } else {
            &self.refund
        }
    }

    /// The txid the record names for `tx`.
    pub fn txid(&self, tx: &ZecTx) -> Result<TxId, Error> {
        let text = text(self.record(tx), tx.txid_field)?;
        TxId::from_hex(text).ok_or_else(|| {
            Error::Checker(format!("{}: {} is not a txid", tx.record, tx.txid_field))
        })
    }

    /// The light server the runs broadcast through, from `fill.json`.
    pub fn light_server(&self) -> Result<&str, Error> {
        text(&self.fill, "light_server")
    }

    /// The archival NEAR RPC the payer fetched from, from `fill.json`.
    pub fn near_rpc_url(&self) -> Result<&str, Error> {
        text(&self.fill, "near_rpc_url")
    }

    /// The NEAR transaction the solver named: its hash and sender.
    pub fn pointer(&self) -> Result<NearTxPointer, Error> {
        Ok(NearTxPointer {
            hash: text(&self.fill, "near_tx_hash")?.to_string(),
            sender: text(&self.fill, "near_sender")?.to_string(),
        })
    }

    /// The banned set from both records: the escrow address, the refund
    /// address, all four Zcash transaction ids, and the escrow zatoshi
    /// amount.
    pub fn banned(&self) -> Result<Banned, Error> {
        let mut banned = Banned::new()
            .address(text(&self.fill, "escrow_address")?)
            .address(text(&self.refund, "escrow_address")?)
            .address(text(&self.refund, "refund_address")?);
        for tx in &ZEC_TXS {
            banned = banned.txid(&self.txid(tx)?);
        }
        let zatoshis = self.fill["escrow_zatoshis"]
            .as_u64()
            .ok_or_else(|| Error::Checker("fill.json: escrow_zatoshis".into()))?;
        Ok(banned.zatoshis(zatoshis))
    }
}

/// The txid of raw transaction bytes.
pub fn txid_of(bytes: &[u8]) -> Result<TxId, Error> {
    Transaction::read(bytes, BranchId::Nu7)
        .map(|tx| tx.txid())
        .map_err(|e| Error::Checker(format!("the bytes are not a transaction: {e}")))
}

/// What one check found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The check passed.
    Pass,
    /// The check failed, with the reason.
    Fail(String),
    /// A live check not run under `--offline`.
    Skipped,
}

/// One printed line of the verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    /// What was checked, such as `fill.fund.tx fetched`.
    pub name: String,
    /// What it found.
    pub outcome: Outcome,
}

impl Check {
    /// `Pass` for `Ok`, `Fail` with the reason for `Err`.
    pub fn new(name: impl Into<String>, result: Result<(), String>) -> Self {
        Check {
            name: name.into(),
            outcome: match result {
                Ok(()) => Outcome::Pass,
                Err(reason) => Outcome::Fail(reason),
            },
        }
    }

    /// A live check skipped under `--offline`.
    pub fn skipped(name: impl Into<String>) -> Self {
        Check {
            name: name.into(),
            outcome: Outcome::Skipped,
        }
    }

    /// `PASS <name>`, `FAIL <name>: <reason>`, or `SKIP <name> (offline)`.
    pub fn line(&self) -> String {
        match &self.outcome {
            Outcome::Pass => format!("PASS {}", self.name),
            Outcome::Fail(reason) => format!("FAIL {}: {reason}", self.name),
            Outcome::Skipped => format!("SKIP {} (offline)", self.name),
        }
    }
}

/// `<n> passed, <m> failed, <k> skipped (offline)`.
pub fn summary(checks: &[Check]) -> String {
    let count = |want: fn(&Outcome) -> bool| checks.iter().filter(|c| want(&c.outcome)).count();
    format!(
        "{} passed, {} failed, {} skipped (offline)",
        count(|o| *o == Outcome::Pass),
        count(|o| matches!(o, Outcome::Fail(_))),
        count(|o| *o == Outcome::Skipped),
    )
}

/// True only when every check passed: a skipped check is not a pass.
pub fn all_passed(checks: &[Check]) -> bool {
    !checks.is_empty() && checks.iter().all(|c| c.outcome == Outcome::Pass)
}

/// `<file> txid`: the stored bytes parse, and their txid is the record's.
pub fn txid_check(records: &Records, tx: &ZecTx) -> Check {
    let result = (|| {
        let recorded = records.txid(tx).map_err(|e| e.to_string())?;
        let stored = records.bytes(tx.file).map_err(|e| e.to_string())?;
        let actual = txid_of(&stored).map_err(|e| e.to_string())?;
        if actual == recorded {
            Ok(())
        } else {
            Err(format!(
                "the bytes hash to {actual}, the record says {recorded}"
            ))
        }
    })();
    Check::new(format!("{} txid", tx.file), result)
}

/// `<file> fetched`: the light server's bytes are the stored file's, and
/// the height it reports is the record's.
pub fn fetched_check(
    records: &Records,
    tx: &ZecTx,
    fetched: &Result<(Vec<u8>, u64), String>,
) -> Check {
    let result = (|| {
        let (bytes, height) = fetched.as_ref().map_err(String::clone)?;
        let stored = records.bytes(tx.file).map_err(|e| e.to_string())?;
        if sha256(bytes) != sha256(&stored) {
            return Err(format!(
                "the server's bytes hash to {}, the stored file to {}",
                hex::encode(sha256(bytes)),
                hex::encode(sha256(&stored))
            ));
        }
        let recorded = records.record(tx)[tx.height_field].as_u64();
        if recorded != Some(*height) {
            return Err(format!("mined at {height}, the record says {recorded:?}"));
        }
        Ok(())
    })();
    Check::new(format!("{} fetched", tx.file), result)
}

/// `<file> check_zec`: no transparent part and no output under the zero
/// outgoing viewing key, on the bytes given.
pub fn zec_check(tx: &ZecTx, bytes: Option<&[u8]>) -> Check {
    let result = match bytes {
        Some(bytes) => check_zec(bytes).map_err(|e| e.to_string()),
        None => Err("no bytes to check".into()),
    };
    Check::new(format!("{} check_zec", tx.file), result)
}

/// `near payment recorded`: the stored payload's SHA-256 is the record's.
pub fn near_recorded_check(records: &Records) -> Check {
    Check::new(
        "near payment recorded",
        payload_hash_matches(records, &records.near_payload),
    )
}

/// `near payment fetched`: the archival RPC's payload hashes to the
/// record's `near_payload_sha256`.
pub fn near_fetched_check(records: &Records, fetched: &Result<Vec<u8>, String>) -> Check {
    let result = fetched
        .as_ref()
        .map_err(String::clone)
        .and_then(|payload| payload_hash_matches(records, payload));
    Check::new("near payment fetched", result)
}

/// `near payment attests`: `check_payload` with the fill quote, the
/// recorded pointer, and the banned set from both records.
pub fn near_attests_check(records: &Records, payload: Option<&[u8]>) -> Check {
    let result = (|| {
        let payload = payload.ok_or("no payload to check")?;
        let pointer = records.pointer().map_err(|e| e.to_string())?;
        let banned = records.banned().map_err(|e| e.to_string())?;
        check_payload(&records.fill_quote, &pointer, &banned, payload).map_err(|e| e.to_string())
    })();
    Check::new("near payment attests", result)
}

/// `refund address absent`: the refund address is in neither quote, the
/// fill record, nor the NEAR payload, and the record says it was not in the
/// refund quote.
pub fn refund_address_check(records: &Records) -> Check {
    let result = (|| {
        let address = text(&records.refund, "refund_address").map_err(|e| e.to_string())?;
        if address.is_empty() {
            return Err("refund.json has an empty refund_address".into());
        }
        for name in [
            "fill.quote.json",
            "refund.quote.json",
            "fill.json",
            "fill.near.json",
        ] {
            let bytes = records.bytes(name).map_err(|e| e.to_string())?;
            if bytes
                .windows(address.len())
                .any(|w| w == address.as_bytes())
            {
                return Err(format!("the refund address appears in {name}"));
            }
        }
        if records.refund["refund_address_in_quote"] != Value::Bool(false) {
            return Err("refund.json: refund_address_in_quote is not false".into());
        }
        Ok(())
    })();
    Check::new("refund address absent", result)
}

/// `policy outcomes recorded`: the deadline device refused the release and
/// the fill's package, signed the refund only after expiry under the
/// fill-claim guard, and the guard refused the fill quote as `quote_paid`.
pub fn policy_check(records: &Records) -> Check {
    let flags = [
        (&records.fill, "fill.json", "deadline_refused_release"),
        (&records.refund, "refund.json", "fill_package_still_refused"),
        (
            &records.refund,
            "refund.json",
            "deadline_signed_after_expiry",
        ),
        (&records.refund, "refund.json", "fill_claim_checked"),
    ];
    let mut problems: Vec<String> = flags
        .iter()
        .filter(|(record, _, field)| record[*field] != Value::Bool(true))
        .map(|(_, name, field)| format!("{name}: {field} is not true"))
        .collect();
    let refused = &records.refund["fill_quote_refund_refused"];
    if refused.as_str() != Some("quote_paid") {
        problems.push(format!(
            "refund.json: fill_quote_refund_refused is {refused}, not quote_paid"
        ));
    }
    let result = if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    };
    Check::new("policy outcomes recorded", result)
}

/// `broadcast sent`: both records say `sent`, with non-zero heights.
pub fn broadcast_check(records: &Records) -> Check {
    let mut problems = Vec::new();
    for (record, name) in [
        (&records.fill, "fill.json"),
        (&records.refund, "refund.json"),
    ] {
        if record["broadcast"].as_str() != Some("sent") {
            problems.push(format!("{name}: broadcast is {}", record["broadcast"]));
        }
        for field in ["fund_mined_height", "spend_mined_height"] {
            if record[field].as_u64().unwrap_or(0) == 0 {
                problems.push(format!("{name}: {field} is missing or zero"));
            }
        }
    }
    let result = if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    };
    Check::new("broadcast sent", result)
}

fn payload_hash_matches(records: &Records, payload: &[u8]) -> Result<(), String> {
    let recorded = text(&records.fill, "near_payload_sha256").map_err(|e| e.to_string())?;
    let actual = hex::encode(sha256(payload));
    if actual == recorded {
        Ok(())
    } else {
        Err(format!(
            "the payload hashes to {actual}, the record says {recorded}"
        ))
    }
}

fn read(dir: &Path, name: &str) -> Result<Vec<u8>, Error> {
    let path = dir.join(name);
    fs::read(&path).map_err(|e| Error::io(path, e))
}

fn text<'a>(record: &'a Value, field: &str) -> Result<&'a str, Error> {
    record[field]
        .as_str()
        .ok_or_else(|| Error::Checker(format!("the record has no {field}")))
}
