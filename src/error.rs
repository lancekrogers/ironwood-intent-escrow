//! The crate's error type.
//!
//! `Display` starts with the snake_case code the festival tasks name, such as
//! `threshold_not_met`, so a caller or a run record can match on it. No
//! variant carries key material.

use std::path::PathBuf;

use crate::cosign::SignerId;

/// Every way this crate refuses or fails.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Fewer than two distinct signers took part.
    #[error("threshold_not_met: {0}")]
    ThresholdNotMet(String),

    /// The same signer appears twice in one signing session.
    #[error("duplicate_signer: {0:?} appears more than once")]
    DuplicateSigner(SignerId),

    /// The signature shares do not come from exactly the signers whose
    /// commitments are in the package.
    #[error("share_set_mismatch: the shares are not from the signers in the package")]
    ShareSetMismatch,

    /// A FROST identifier is not one of the three escrow holders.
    #[error("unknown_signer: the identifier is not payer, solver, or deadline")]
    UnknownSigner,

    /// A share file or `escrow.fvk` does not parse or does not match the escrow.
    #[error("invalid_key_file: {path}: {reason}")]
    InvalidKeyFile {
        /// The file that failed.
        path: PathBuf,
        /// Why it failed. Never the file's contents.
        reason: String,
    },

    /// Derived keys disagree, for example the FROST group key is not `ak`.
    #[error("key_mismatch: {0}")]
    KeyMismatch(&'static str),

    /// The aggregated signature does not verify against the randomized `ak`.
    #[error("invalid_signature: the aggregate does not verify against the randomized ak")]
    InvalidSignature,

    /// A unified address has a receiver other than the Orchard receiver that
    /// Ironwood uses.
    #[error("not_ironwood_only: {0}")]
    NotIronwoodOnly(&'static str),

    /// A unified address string does not decode for the expected network.
    #[error("address_decode: {0}")]
    AddressDecode(String),

    /// The payer wallet holds no Ironwood note that covers the amount.
    #[error("no_spendable_note: the payer wallet has no Ironwood note that covers the amount")]
    NoSpendableNote,

    /// The wallet database failed.
    #[error("wallet: {0}")]
    Wallet(String),

    /// A light server could not be reached or returned unusable data.
    #[error("light_server: {0}")]
    LightServer(String),

    /// An output would be encrypted to the all-zero outgoing viewing key.
    #[error(
        "zero_outgoing_viewing_key: an output would open under the all-zero outgoing viewing key"
    )]
    ZeroOutgoingViewingKey,

    /// The note does not cover the amount plus the fee.
    #[error("insufficient_funds: the note holds {have} zatoshis and the transaction needs {need}")]
    InsufficientFunds {
        /// The note's value.
        have: u64,
        /// The amount plus the fee.
        need: u64,
    },

    /// Building, proving, signing, or extracting a PCZT failed.
    #[error("pczt: {0}")]
    Pczt(String),

    /// An error from the FROST library that has no more specific code.
    #[error("frost: {0}")]
    Frost(String),

    /// A file could not be read or written.
    #[error("io: {path}: {source}")]
    Io {
        /// The file involved.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
}

impl Error {
    /// An I/O error on `path`.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }

    /// A key or wallet file at `path` that is wrong for `reason`.
    pub fn key_file(path: impl Into<PathBuf>, reason: impl Into<String>) -> Self {
        Error::InvalidKeyFile {
            path: path.into(),
            reason: reason.into(),
        }
    }
}

impl From<reddsa::frost::redpallas::Error> for Error {
    fn from(e: reddsa::frost::redpallas::Error) -> Self {
        Error::Frost(e.to_string())
    }
}
