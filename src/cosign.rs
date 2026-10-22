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

use reddsa::frost::redpallas::Identifier;
use serde::{Deserialize, Serialize};

use crate::error::Error;

/// One of the three holders of the escrow's spend authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
