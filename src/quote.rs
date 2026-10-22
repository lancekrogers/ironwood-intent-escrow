//! The quote id: 32 random bytes the payer draws for one quote.
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
}
