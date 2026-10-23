//! Fill claims: the pointer the solver leaves after it pays a quote on NEAR,
//! so a refund signer can re-fetch the payment before it signs
//! (`docs/decisions/fill-claims.md`).
//!
//! A claim holds a quote id, a NEAR transaction hash, the solver's account,
//! and the RPC the solver used. It holds no Zcash value of any kind and no
//! key material. The refund signer re-fetches from its own RPC and treats
//! `rpc_url` as informational.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::attest::NearTxPointer;
use crate::error::Error;
use crate::files::{private_dir, write_new};
use crate::quote::QuoteId;

/// What the solver writes right after its NEAR payment succeeds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FillClaim {
    /// The quote the payment filled.
    pub quote_id: QuoteId,
    /// The NEAR transaction hash, base58.
    pub near_tx_hash: String,
    /// The account that signed the payment, the solver's.
    pub near_sender: String,
    /// The RPC the solver used. Informational: a refund signer fetches from
    /// its own.
    pub rpc_url: String,
}

impl FillClaim {
    /// The hash and sender a refund signer re-fetches.
    pub fn pointer(&self) -> NearTxPointer {
        NearTxPointer {
            hash: self.near_tx_hash.clone(),
            sender: self.near_sender.clone(),
        }
    }
}

/// Where a refund signer looks for a fill claim.
pub trait ClaimStore {
    /// The claim for `quote_id`, if one was written. A claim that cannot be
    /// read is an error, never `None`.
    fn claim(&self, quote_id: &QuoteId) -> Result<Option<FillClaim>, Error>;
}

/// One JSON file per quote, `<dir>/<quote id hex>.json`.
#[derive(Clone, Debug)]
pub struct DirClaimStore {
    dir: PathBuf,
}

impl DirClaimStore {
    /// The store in `dir`, which need not exist yet.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        DirClaimStore { dir: dir.into() }
    }
}

impl ClaimStore for DirClaimStore {
    fn claim(&self, quote_id: &QuoteId) -> Result<Option<FillClaim>, Error> {
        read_claim(&claim_path(&self.dir, quote_id), quote_id)
    }
}

/// A store with no claims, for the release path and for tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoClaims;

impl ClaimStore for NoClaims {
    fn claim(&self, _quote_id: &QuoteId) -> Result<Option<FillClaim>, Error> {
        Ok(None)
    }
}

/// Writes `claim` into `dir` (mode 0700) as an owner-only file. Writing the
/// same hash again is a no-op, so a resumed run can call it twice; a claim
/// for the same quote with another hash is refused.
pub fn write_claim(dir: &Path, claim: &FillClaim) -> Result<(), Error> {
    private_dir(dir)?;
    let path = claim_path(dir, &claim.quote_id);
    if let Some(existing) = read_claim(&path, &claim.quote_id)? {
        if existing.near_tx_hash == claim.near_tx_hash {
            return Ok(());
        }
        return Err(Error::Claim(format!(
            "{}: a claim with another NEAR hash exists for this quote",
            path.display()
        )));
    }
    let json = serde_json::to_vec_pretty(claim).map_err(|e| Error::Claim(e.to_string()))?;
    write_new(&path, &json)
}

fn claim_path(dir: &Path, quote_id: &QuoteId) -> PathBuf {
    dir.join(format!("{}.json", quote_id.to_hex()))
}

/// A missing file is `None`; a file that does not parse, or that names
/// another quote, is `claim`.
fn read_claim(path: &Path, quote_id: &QuoteId) -> Result<Option<FillClaim>, Error> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::io(path, e)),
    };
    let claim: FillClaim = serde_json::from_slice(&bytes)
        .map_err(|e| Error::Claim(format!("{}: {e}", path.display())))?;
    if claim.quote_id != *quote_id {
        return Err(Error::Claim(format!(
            "{}: the claim names another quote",
            path.display()
        )));
    }
    Ok(Some(claim))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(hash: &str) -> FillClaim {
        FillClaim {
            quote_id: QuoteId::from_bytes([7; 32]),
            near_tx_hash: hash.into(),
            near_sender: "solver.testnet".into(),
            rpc_url: "https://archival-rpc.testnet.near.org".into(),
        }
    }

    #[test]
    fn claims_write_then_read_returns_the_claim() {
        let dir = tempfile::tempdir().unwrap();
        let claims = dir.path().join("claims");
        write_claim(&claims, &claim("HashA")).unwrap();
        let read = DirClaimStore::new(&claims)
            .claim(&QuoteId::from_bytes([7; 32]))
            .unwrap();
        assert_eq!(read, Some(claim("HashA")));
        assert_eq!(read.unwrap().pointer().hash, "HashA");
    }

    #[test]
    fn claims_missing_quote_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let store = DirClaimStore::new(dir.path().join("absent"));
        assert_eq!(store.claim(&QuoteId::from_bytes([1; 32])).unwrap(), None);
        assert_eq!(NoClaims.claim(&QuoteId::from_bytes([1; 32])).unwrap(), None);
    }

    #[test]
    fn claims_refuse_another_hash_for_the_same_quote() {
        let dir = tempfile::tempdir().unwrap();
        write_claim(dir.path(), &claim("HashA")).unwrap();
        let err = write_claim(dir.path(), &claim("HashB")).unwrap_err();
        assert!(matches!(err, Error::Claim(_)), "{err}");
        let kept = DirClaimStore::new(dir.path())
            .claim(&QuoteId::from_bytes([7; 32]))
            .unwrap()
            .unwrap();
        assert_eq!(kept.near_tx_hash, "HashA");
    }

    #[test]
    fn claims_same_hash_again_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        write_claim(dir.path(), &claim("HashA")).unwrap();
        write_claim(dir.path(), &claim("HashA")).unwrap();
    }

    #[test]
    fn claims_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let claims = dir.path().join("claims");
        write_claim(&claims, &claim("HashA")).unwrap();
        let file = claim_path(&claims, &QuoteId::from_bytes([7; 32]));
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&file), 0o600);
        assert_eq!(mode(&claims), 0o700);
    }

    #[test]
    fn claims_refuse_a_file_that_does_not_parse() {
        let dir = tempfile::tempdir().unwrap();
        let quote_id = QuoteId::from_bytes([7; 32]);
        fs::write(claim_path(dir.path(), &quote_id), b"{\"quote_id\": 1").unwrap();
        let err = DirClaimStore::new(dir.path()).claim(&quote_id).unwrap_err();
        assert!(matches!(err, Error::Claim(_)), "{err}");
        let err = write_claim(dir.path(), &claim("HashA")).unwrap_err();
        assert!(matches!(err, Error::Claim(_)), "{err}");
    }

    #[test]
    fn claims_refuse_a_file_that_names_another_quote() {
        let dir = tempfile::tempdir().unwrap();
        write_claim(dir.path(), &claim("HashA")).unwrap();
        let other = QuoteId::from_bytes([9; 32]);
        fs::rename(
            claim_path(dir.path(), &QuoteId::from_bytes([7; 32])),
            claim_path(dir.path(), &other),
        )
        .unwrap();
        let err = DirClaimStore::new(dir.path()).claim(&other).unwrap_err();
        assert!(matches!(err, Error::Claim(_)), "{err}");
    }
}
