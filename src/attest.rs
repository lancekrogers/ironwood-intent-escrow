//! The NEAR attestation: the payer's check that the solver paid the quote
//! (`docs/decisions/receipt-chain.md`).
//!
//! The solver hands over a pointer, the transaction hash and the sender, and
//! nothing else. The payer re-fetches the transaction from the archival RPC
//! through [`NearRpc`] and checks the fetched bytes. A blob the solver
//! supplies is never the input.
//!
//! Only two places in the fetched transaction are searched for banned
//! values: the decoded `args` of each `FunctionCall` action, and every log
//! string of every receipt outcome. Block hashes, transaction and receipt
//! hashes, gas, heights, and deposits are never searched, and no arbitrary
//! 32-byte value is banned, because the quote id is one.
//!
//! The transfer itself must be logged by the asset contract's own successful
//! receipt, in the legacy `Transfer`/`Memo:` form `wrap.testnet` emits or as
//! a NEP-297 event.

use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};
use zcash_address::ZcashAddress;
use zcash_primitives::transaction::TxId;

use crate::error::Error;
use crate::quote::Quote;

/// The archival testnet RPC `receipt-chain.md` names.
pub const ARCHIVAL_RPC: &str = "https://archival-rpc.testnet.near.org";

/// What the solver supplies: the NEAR transaction hash and its sender.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NearTxPointer {
    /// The transaction hash, base58.
    pub hash: String,
    /// The account that signed it, the solver's.
    pub sender: String,
}

/// Known values that must never appear in the NEAR receipt: the escrow
/// address, the payer's refund addresses, the fund and spend transaction
/// ids, and the escrow note's zatoshi amount. Any token that decodes as a
/// Zcash address is banned as well, whether or not it is listed here.
#[derive(Clone, Debug, Default)]
pub struct Banned {
    tokens: Vec<String>,
}

impl Banned {
    /// An empty set; only decoded Zcash addresses are banned.
    pub fn new() -> Self {
        Banned::default()
    }

    /// Bans an address string, such as the escrow or a refund address.
    pub fn address(mut self, encoded: impl Into<String>) -> Self {
        self.tokens.push(encoded.into());
        self
    }

    /// Bans a transaction id in both byte orders, as 64 lowercase hex.
    pub fn txid(mut self, txid: &TxId) -> Self {
        let bytes: [u8; 32] = *txid.as_ref();
        let mut reversed = bytes;
        reversed.reverse();
        self.tokens.push(hex::encode(bytes));
        self.tokens.push(hex::encode(reversed));
        self
    }

    /// Bans the zatoshi amount as a decimal token.
    pub fn zatoshis(mut self, amount: u64) -> Self {
        self.tokens.push(amount.to_string());
        self
    }

    fn check(&self, token: &str) -> Result<(), Error> {
        if self.tokens.iter().any(|banned| banned == token) {
            return Err(Error::BannedField(
                "a known Zcash value appears in the receipt".into(),
            ));
        }
        if ZcashAddress::try_from_encoded(token).is_ok() {
            return Err(Error::BannedField(
                "a token in the receipt decodes as a Zcash address".into(),
            ));
        }
        Ok(())
    }
}

/// Fetches one NEAR transaction by hash and sender. The fill run uses the
/// archival RPC; tests pass fixtures.
pub trait NearRpc {
    /// The endpoint, recorded in the attestation.
    fn url(&self) -> &str;
    /// The raw JSON-RPC response body of `tx` with `wait_until: FINAL`.
    fn tx(&self, hash: &str, sender: &str) -> Result<Vec<u8>, Error>;
}

/// What the payer keeps: enough to re-run [`check_payload`] offline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation {
    /// The RPC the payload came from.
    pub rpc_url: String,
    /// The NEAR transaction hash.
    pub tx_hash: String,
    /// The sender the solver named.
    pub sender: String,
    /// SHA-256 of `payload`.
    pub payload_sha256: [u8; 32],
    /// The raw response body as fetched.
    pub payload: Vec<u8>,
}

/// Re-fetches the solver's transaction and checks it against the quote and
/// the banned values.
pub fn attest(
    quote: &Quote,
    pointer: &NearTxPointer,
    banned: &Banned,
    rpc: &dyn NearRpc,
) -> Result<Attestation, Error> {
    let payload = rpc.tx(&pointer.hash, &pointer.sender)?;
    check_payload(quote, pointer, banned, &payload)?;
    Ok(Attestation {
        rpc_url: rpc.url().to_string(),
        tx_hash: pointer.hash.clone(),
        sender: pointer.sender.clone(),
        payload_sha256: Sha256::digest(&payload).into(),
        payload,
    })
}

/// The checks `attest` applies to a fetched payload, without the network.
pub fn check_payload(
    quote: &Quote,
    pointer: &NearTxPointer,
    banned: &Banned,
    payload: &[u8],
) -> Result<(), Error> {
    let body: Value = serde_json::from_slice(payload)
        .map_err(|e| Error::Attestation(format!("the payload is not JSON: {e}")))?;
    if let Some(error) = body.get("error") {
        return Err(Error::Attestation(format!(
            "the RPC returned an error: {error}"
        )));
    }
    let result = body.get("result").ok_or_else(|| missing("result"))?;
    let tx = result
        .get("transaction")
        .ok_or_else(|| missing("transaction"))?;
    if result.pointer("/status/SuccessValue").is_none() {
        return Err(missing("status.SuccessValue"));
    }
    if let Some(status) = result.get("final_execution_status") {
        if status.as_str() != Some("FINAL") {
            return Err(missing("final_execution_status FINAL"));
        }
    }
    require_eq(tx, "/hash", &pointer.hash, "transaction.hash")?;
    require_eq(tx, "/signer_id", &pointer.sender, "transaction.signer_id")?;
    require_eq(tx, "/receiver_id", &quote.asset, "transaction.receiver_id")?;

    let args = transfer_args(tx)?;
    let logs = receipt_logs(result);
    for text in args
        .iter()
        .flat_map(string_leaves)
        .chain(logs.iter().cloned())
    {
        tokens(&text).try_for_each(|token| banned.check(token))?;
    }

    let quote_hex = quote.id.to_hex();
    let call = args
        .iter()
        .find(|a| a.get("memo").and_then(Value::as_str) == Some(quote_hex.as_str()))
        .ok_or_else(|| missing("args.memo with the quote id"))?;
    require_eq(
        call,
        "/receiver_id",
        &quote.destination_account,
        "args.receiver_id",
    )?;
    require_eq(call, "/amount", &quote.amount.to_string(), "args.amount")?;
    if !transfer_logged(result, quote, pointer) {
        return Err(missing(
            "the asset contract's transfer log with the quote id, owners, and amount",
        ));
    }
    Ok(())
}

/// Whether a successful receipt executed by the asset contract itself logs
/// this transfer, in either form NEP-141 contracts emit:
///
/// - the legacy pair `wrap.testnet` emits (measured 2026-10-22, NEAR
///   transaction `7J1bzUpXaJo2oHqtbXHh5sme7FXhucexpiQiQ7fkG7uk`):
///   `Transfer {amount} from {sender} to {destination}` and
///   `Memo: {quote id}`, each matched exactly;
/// - a NEP-297 `ft_transfer` event whose one `data` entry carries the same
///   four values.
///
/// A log from any other executor, or from a failed receipt, never counts.
fn transfer_logged(result: &Value, quote: &Quote, pointer: &NearTxPointer) -> bool {
    let transfer = format!(
        "Transfer {} from {} to {}",
        quote.amount, pointer.sender, quote.destination_account
    );
    let memo = format!("Memo: {}", quote.id.to_hex());
    result
        .get("receipts_outcome")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|r| r.get("outcome"))
        .filter(|o| o.get("executor_id").and_then(Value::as_str) == Some(quote.asset.as_str()))
        .filter(|o| o.pointer("/status/SuccessValue").is_some())
        .any(|o| {
            let logs: Vec<&str> = o
                .get("logs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::trim)
                .collect();
            let legacy = logs.contains(&transfer.as_str()) && logs.contains(&memo.as_str());
            legacy || logs.iter().any(|log| event_matches(log, quote, pointer))
        })
}

/// The decoded JSON args of every `ft_transfer` call.
fn transfer_args(tx: &Value) -> Result<Vec<Value>, Error> {
    let actions = tx
        .get("actions")
        .and_then(Value::as_array)
        .ok_or_else(|| missing("transaction.actions"))?;
    let mut decoded = Vec::new();
    for call in actions.iter().filter_map(|a| a.get("FunctionCall")) {
        if call.get("method_name").and_then(Value::as_str) != Some("ft_transfer") {
            continue;
        }
        let encoded = call
            .get("args")
            .and_then(Value::as_str)
            .ok_or_else(|| missing("FunctionCall.args"))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| Error::Attestation(format!("args are not base64: {e}")))?;
        decoded.push(
            serde_json::from_slice(&bytes)
                .map_err(|e| Error::Attestation(format!("args are not JSON: {e}")))?,
        );
    }
    if decoded.is_empty() {
        return Err(missing("an ft_transfer FunctionCall"));
    }
    Ok(decoded)
}

/// Every log string of every receipt outcome.
fn receipt_logs(result: &Value) -> Vec<String> {
    result
        .get("receipts_outcome")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|r| r.pointer("/outcome/logs").and_then(Value::as_array))
        .flatten()
        .filter_map(|log| log.as_str().map(str::to_string))
        .collect()
}

/// Whether a log is the NEP-297 `ft_transfer` event for this payment: one
/// `data` entry that carries the quote id as memo, moves the quote amount,
/// and goes from the solver to the destination account.
fn event_matches(log: &str, quote: &Quote, pointer: &NearTxPointer) -> bool {
    let Some(json) = log.strip_prefix("EVENT_JSON:") else {
        return false;
    };
    let Ok(event) = serde_json::from_str::<Value>(json) else {
        return false;
    };
    let amount = quote.amount.to_string();
    let quote_hex = quote.id.to_hex();
    let field = |d: &Value, k: &str| d.get(k).and_then(Value::as_str).map(str::to_string);
    event.get("standard").and_then(Value::as_str) == Some("nep141")
        && event.get("event").and_then(Value::as_str) == Some("ft_transfer")
        && event
            .get("data")
            .and_then(Value::as_array)
            .is_some_and(|data| {
                data.iter().any(|d| {
                    field(d, "memo").as_deref() == Some(quote_hex.as_str())
                        && field(d, "amount").as_deref() == Some(amount.as_str())
                        && field(d, "old_owner_id").as_deref() == Some(pointer.sender.as_str())
                        && field(d, "new_owner_id").as_deref()
                            == Some(quote.destination_account.as_str())
                })
            })
}

/// Every string and number in a JSON value, as text.
fn string_leaves(value: &Value) -> Vec<String> {
    match value {
        Value::String(s) => vec![s.clone()],
        Value::Number(n) => vec![n.to_string()],
        Value::Array(items) => items.iter().flat_map(string_leaves).collect(),
        Value::Object(map) => map.values().flat_map(string_leaves).collect(),
        _ => vec![],
    }
}

/// Maximal runs of ASCII letters and digits. Zcash addresses, transaction
/// ids, and decimal amounts are each one such run.
fn tokens(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
}

fn require_eq(value: &Value, pointer: &str, expected: &str, name: &str) -> Result<(), Error> {
    match value.pointer(pointer).and_then(Value::as_str) {
        Some(actual) if actual == expected => Ok(()),
        _ => Err(missing(name)),
    }
}

fn missing(name: &str) -> Error {
    Error::MissingField(name.to_string())
}
