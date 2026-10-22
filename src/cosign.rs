//! The co-sign envelope: the messages the signers and the coordinator
//! exchange across the two FROST rounds.
//!
//! This crate defines its own envelope. It does not import another wallet's
//! share or message format (`docs/decisions/shares.md`, "Two signing rounds").
//!
//! 1. Each signer taking part runs round 1 and publishes [`Commitments`].
//! 2. The coordinator builds a [`SigningPackage`] from the PCZT it is signing.
//! 3. Each signer checks the package against the PCZT it holds, applies its
//!    policy, and only then runs round 2 to publish a [`Share`].
//! 4. The coordinator aggregates two shares into a spend authorization.

use std::collections::{BTreeMap, BTreeSet};

use reddsa::frost::redpallas::{
    round1::SigningCommitments, round2::SignatureShare, Identifier, PallasBlake2b512,
};
use serde::{Deserialize, Serialize};

use crate::error::Error;

/// The spend randomizer `alpha` of the escrow action, as FROST takes it.
pub type SpendRandomizer = frost_rerandomized::Randomizer<PallasBlake2b512>;

/// One of the three holders of the escrow's spend authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerId {
    /// The payer. Signs the release after attestation, and the refund.
    Payer,
    /// The solver. Signs the release only.
    Solver,
    /// The payer's second device. Signs the refund only, after expiry.
    Deadline,
}

impl SignerId {
    /// All three holders, in identifier order.
    pub const ALL: [SignerId; 3] = [SignerId::Payer, SignerId::Solver, SignerId::Deadline];

    /// The FROST identifier: payer 1, solver 2, deadline 3.
    pub fn identifier(self) -> Identifier {
        let index: u16 = match self {
            SignerId::Payer => 1,
            SignerId::Solver => 2,
            SignerId::Deadline => 3,
        };
        Identifier::try_from(index).expect("1, 2, and 3 are nonzero identifiers")
    }

    /// The holder that owns a FROST identifier.
    pub fn from_identifier(id: Identifier) -> Result<Self, Error> {
        SignerId::ALL
            .into_iter()
            .find(|signer| signer.identifier() == id)
            .ok_or(Error::UnknownSigner)
    }

    /// The share file this holder keeps: `payer.key`, `solver.key`, or
    /// `deadline.key`.
    pub fn key_file_name(self) -> &'static str {
        match self {
            SignerId::Payer => "payer.key",
            SignerId::Solver => "solver.key",
            SignerId::Deadline => "deadline.key",
        }
    }
}

/// Round 1: the commitments one signer publishes. Its nonces stay in its
/// own memory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commitments {
    /// Who committed.
    pub signer: SignerId,
    /// The FROST round 1 commitments.
    pub commitments: SigningCommitments,
}

/// What the coordinator asks the signers to sign.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningPackage {
    /// The shielded sighash of the PCZT being signed.
    pub sighash: [u8; 32],
    /// The spend randomizer `alpha` of the escrow action, so the aggregate
    /// verifies against the randomized `ak` the transaction carries.
    pub randomizer: SpendRandomizer,
    /// Round 1 from each signer taking part.
    pub commitments: Vec<Commitments>,
    /// The hash of the PCZT the signers inspected, so a round 2 signer can
    /// confirm it signs that PCZT and no other.
    pub pczt_hash: [u8; 32],
}

impl SigningPackage {
    /// The signers taking part. Rejects a signer listed twice, which a map
    /// keyed by identifier would otherwise collapse without a trace.
    pub fn signers(&self) -> Result<BTreeSet<SignerId>, Error> {
        let mut signers = BTreeSet::new();
        for entry in &self.commitments {
            if !signers.insert(entry.signer) {
                return Err(Error::DuplicateSigner(entry.signer));
            }
        }
        Ok(signers)
    }

    /// The package in the form `frost-core` signs and aggregates.
    pub(crate) fn to_frost(&self) -> Result<reddsa::frost::redpallas::SigningPackage, Error> {
        self.signers()?;
        let commitments: BTreeMap<Identifier, SigningCommitments> = self
            .commitments
            .iter()
            .map(|entry| (entry.signer.identifier(), entry.commitments))
            .collect();
        Ok(reddsa::frost::redpallas::SigningPackage::new(
            commitments,
            &self.sighash,
        ))
    }
}

/// Round 2: one signer's signature share.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Share {
    /// Who signed.
    pub signer: SignerId,
    /// The FROST round 2 signature share.
    pub share: SignatureShare,
}

impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Share")
            .field("signer", &self.signer)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    //! The three messages round-trip through serde, and the envelope refuses
    //! a duplicate signer and a field it does not define. Assertions compare
    //! without `Debug`, so a failure prints no signature share.

    use super::*;
    use crate::frost::{keygen, round1, round2, ShareFile};

    fn session() -> (Commitments, SigningPackage, Share) {
        let dir = tempfile::tempdir().unwrap();
        keygen(dir.path()).unwrap();
        let payer = ShareFile::read(&dir.path().join("payer.key")).unwrap();
        let solver = ShareFile::read(&dir.path().join("solver.key")).unwrap();
        let (payer_nonces, payer_commitments) = round1(&payer);
        let (_, solver_commitments) = round1(&solver);
        let mut alpha = [0u8; 32];
        alpha[0] = 9;
        let package = SigningPackage {
            sighash: [0x11; 32],
            randomizer: SpendRandomizer::deserialize(&alpha).unwrap(),
            commitments: vec![payer_commitments.clone(), solver_commitments],
            pczt_hash: [0x22; 32],
        };
        let share = round2(&payer, payer_nonces, &package).unwrap();
        (payer_commitments, package, share)
    }

    fn round_trip<T: Serialize + for<'de> Deserialize<'de>>(value: &T) -> T {
        let json = serde_json::to_string(value).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn cosign_package_rejects_a_duplicate_signer() {
        let (commitments, mut package, _) = session();
        package.commitments.push(commitments);
        let err = package.signers().unwrap_err();
        assert!(
            matches!(err, Error::DuplicateSigner(SignerId::Payer)),
            "{err}"
        );
    }

    #[test]
    fn cosign_package_rejects_an_unknown_field() {
        let (_, package, _) = session();
        let mut json: serde_json::Value = serde_json::to_value(&package).unwrap();
        json["refund_address"] = serde_json::Value::String("not a field".into());
        assert!(serde_json::from_value::<SigningPackage>(json).is_err());
    }

    #[test]
    fn cosign_messages_round_trip() {
        let (commitments, package, share) = session();
        assert!(round_trip(&commitments) == commitments);
        assert!(round_trip(&package) == package);
        assert!(round_trip(&share) == share);
        assert_eq!(
            serde_json::to_string(&SignerId::Deadline).unwrap(),
            "\"deadline\""
        );
    }
}
