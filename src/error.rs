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
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }

    pub(crate) fn key_file(path: impl Into<PathBuf>, reason: impl Into<String>) -> Self {
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
