//! The quote and its id.
//!
//! A quote names what the solver pays on NEAR and when the offer expires. It
//! has no refund address: the refund address is made inside the payer's
//! wallet when a refund is built (product rule 4), and `Quote::parse`
//! refuses any input that tries to carry one.
//!
//! The quote id is 32 random bytes the payer draws for one quote.
//!
//! It is the only value that links the NEAR payment to the ZEC spend
//! (`docs/decisions/receipt-chain.md`): 64 lowercase hex characters in the
//! NEAR `ft_transfer` memo, and the same 64 characters as the ZIP 302 text
//! memo of the escrow spend's output.

use std::fmt;

use rand::rngs::SysRng;
use rand::TryRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zcash_protocol::memo::{Memo, MemoBytes};

use crate::error::Error;

/// One quote's id.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct QuoteId([u8; 32]);

impl QuoteId {
    /// A fresh id from the OS RNG.
    pub fn random() -> Result<Self, Error> {
        let mut bytes = [0u8; 32];
        SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(|e| Error::InvalidQuoteId(format!("rng: {e}")))?;
        Ok(QuoteId(bytes))
    }

    /// The id with these bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        QuoteId(bytes)
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 64 lowercase hex characters, the form the NEAR memo and the ZEC memo
    /// carry.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parses exactly 64 lowercase hex characters and nothing else.
    pub fn from_hex(text: &str) -> Result<Self, Error> {
        let canonical = text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !canonical {
            return Err(Error::InvalidQuoteId(
                "a quote id is 64 lowercase hex characters".into(),
            ));
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(text, &mut bytes).map_err(|e| Error::InvalidQuoteId(e.to_string()))?;
        Ok(QuoteId(bytes))
    }

    /// The ZIP 302 text memo holding the hex id and nothing else.
    pub fn memo(&self) -> MemoBytes {
        let text: Memo = self
            .to_hex()
            .parse()
            .expect("64 ASCII characters fit a text memo");
        MemoBytes::from(&text)
    }

    /// Reads the id back from a 512-byte memo. Anything but a text memo of
    /// exactly the hex id is refused.
    pub fn from_memo(memo: &[u8; 512]) -> Result<Self, Error> {
        let bytes =
            MemoBytes::from_bytes(memo).map_err(|e| Error::InvalidQuoteId(format!("{e:?}")))?;
        match Memo::try_from(bytes) {
            Ok(Memo::Text(text)) => QuoteId::from_hex(&text),
            _ => Err(Error::InvalidQuoteId("the memo is not a text memo".into())),
        }
    }
}

impl fmt::Display for QuoteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for QuoteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "QuoteId({})", self.to_hex())
    }
}

impl Serialize for QuoteId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for QuoteId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        QuoteId::from_hex(&text).map_err(serde::de::Error::custom)
    }
}

/// The keys a quote must never carry, in any spelling the inputs use.
const REFUND_KEYS: [&str; 3] = ["refund_address", "refund_to", "refundTo"];

/// One quote: what the solver pays on NEAR, to whom, and until when.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quote {
    /// 32 random bytes, drawn once per quote.
    pub id: QuoteId,
    /// The payer's NEAR testnet account that receives the payment.
    pub destination_account: String,
    /// The NEP-141 contract of the asset, `wrap.testnet` for wNEAR.
    pub asset: String,
    /// The amount in the asset's smallest unit, yoctowNEAR. Serialized as a
    /// decimal string, as NEAR amounts are.
    #[serde(with = "decimal_u128")]
    pub amount: u128,
    /// After this Unix time the deadline device may sign a refund.
    pub expiry_unix: u64,
}

impl Quote {
    /// A quote with a fresh id from the OS RNG. A quote id is never reused:
    /// each run builds its own quote.
    pub fn new(
        destination_account: impl Into<String>,
        asset: impl Into<String>,
        amount: u128,
        expiry_unix: u64,
    ) -> Result<Self, Error> {
        Ok(Quote {
            id: QuoteId::random()?,
            destination_account: destination_account.into(),
            asset: asset.into(),
            amount,
            expiry_unix,
        })
    }

    /// Parses a quote from JSON. Any key named for a refund address, at any
    /// depth, is `refund_field_rejected`; any other unknown key is refused
    /// too.
    pub fn parse(json: &str) -> Result<Self, Error> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| Error::InvalidQuote(e.to_string()))?;
        if let Some(key) = refund_key_in(&value) {
            return Err(Error::RefundFieldRejected(key));
        }
        serde_json::from_value(value).map_err(|e| Error::InvalidQuote(e.to_string()))
    }

    /// The quote as JSON, the form it is stored in.
    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string_pretty(self).map_err(|e| Error::InvalidQuote(e.to_string()))
    }
}

fn refund_key_in(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => map.iter().find_map(|(key, inner)| {
            REFUND_KEYS
                .iter()
                .find(|banned| key.eq_ignore_ascii_case(banned))
                .map(|_| key.clone())
                .or_else(|| refund_key_in(inner))
        }),
        serde_json::Value::Array(items) => items.iter().find_map(refund_key_in),
        _ => None,
    }
}

mod decimal_u128 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(serde::de::Error::custom("an amount is a decimal string"));
        }
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_id_refuses_anything_but_64_lowercase_hex() {
        let id = QuoteId::random().unwrap();
        for bad in [
            id.to_hex().to_uppercase(),
            id.to_hex()[..63].to_string(),
            format!("{} ", id.to_hex()),
            format!("0x{}", &id.to_hex()[2..]),
        ] {
            assert!(QuoteId::from_hex(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn quote_id_round_trips_through_memo_and_json() {
        let id = QuoteId::random().unwrap();
        let memo = id.memo();
        assert_eq!(QuoteId::from_memo(memo.as_array()).unwrap(), id);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{}\"", id.to_hex()));
        assert_eq!(serde_json::from_str::<QuoteId>(&json).unwrap(), id);
        assert!(QuoteId::from_memo(MemoBytes::empty().as_array()).is_err());
    }

    fn clean_json(id: &QuoteId) -> String {
        format!(
            r#"{{"id":"{id}","destination_account":"payer-ironwood.testnet","asset":"wrap.testnet","amount":"250000000000000000000000","expiry_unix":1792800000}}"#
        )
    }

    #[test]
    fn quote_rejects_refund_to() {
        let id = QuoteId::random().unwrap();
        let with_refund = clean_json(&id).replace(
            r#""expiry_unix""#,
            r#""refundTo":"utest1notarealaddress","expiry_unix""#,
        );
        let err = Quote::parse(&with_refund).unwrap_err();
        assert!(
            matches!(err, Error::RefundFieldRejected(ref k) if k == "refundTo"),
            "{err}"
        );
        assert!(err.to_string().starts_with("refund_field_rejected"));
    }

    #[test]
    fn quote_rejects_refund_keys_in_any_spelling_or_depth() {
        let id = QuoteId::random().unwrap();
        for key in ["refund_address", "refund_to", "REFUNDTO"] {
            let json = clean_json(&id)
                .replace(r#""asset""#, &format!(r#""meta":{{"{key}":"x"}},"asset""#));
            let err = Quote::parse(&json).unwrap_err();
            assert!(matches!(err, Error::RefundFieldRejected(_)), "{key}: {err}");
        }
    }

    #[test]
    fn quote_rejects_an_unknown_field_and_a_numeric_amount() {
        let id = QuoteId::random().unwrap();
        let extra = clean_json(&id).replace(r#""asset""#, r#""note":"x","asset""#);
        assert!(matches!(Quote::parse(&extra), Err(Error::InvalidQuote(_))));
        let numeric =
            clean_json(&id).replace(r#""250000000000000000000000""#, "250000000000000000000000");
        assert!(matches!(
            Quote::parse(&numeric),
            Err(Error::InvalidQuote(_))
        ));
    }

    #[test]
    fn quote_round_trips_its_five_fields() {
        let id = QuoteId::random().unwrap();
        let quote = Quote::parse(&clean_json(&id)).unwrap();
        assert_eq!(quote.id, id);
        assert_eq!(quote.destination_account, "payer-ironwood.testnet");
        assert_eq!(quote.asset, "wrap.testnet");
        assert_eq!(quote.amount, 250_000_000_000_000_000_000_000);
        assert_eq!(quote.expiry_unix, 1_792_800_000);
        assert_eq!(Quote::parse(&quote.to_json().unwrap()).unwrap(), quote);
    }

    #[test]
    fn quote_new_draws_a_fresh_id() {
        let a = Quote::new("a.testnet", "wrap.testnet", 1, 2).unwrap();
        let b = Quote::new("a.testnet", "wrap.testnet", 1, 2).unwrap();
        assert_ne!(a.id, b.id);
    }
}
