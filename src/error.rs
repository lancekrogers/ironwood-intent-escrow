//! The crate's error type.
//!
//! `Display` starts with the snake_case code the festival tasks name, such as
//! `threshold_not_met`, so a caller or a run record can match on it. No
//! variant carries key material.

use std::path::PathBuf;

/// Every way this crate refuses or fails.
#[derive(Debug, thiserror::Error)]
pub enum Error {
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
