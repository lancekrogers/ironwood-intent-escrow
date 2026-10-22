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
    #[error("zero_outgoing_viewing_key: an output opens under the all-zero outgoing viewing key")]
    ZeroOutgoingViewingKey,

    /// A ZEC transaction has a transparent input or output.
    #[error("transparent_output: the transaction has a transparent input or output")]
    TransparentOutput,

    /// The checker could not read its input.
    #[error("checker: {0}")]
    Checker(String),

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

    /// A quote id is not 64 lowercase hex characters, or a memo does not hold one.
    #[error("invalid_quote_id: {0}")]
    InvalidQuoteId(String),

    /// The escrow spend's outputs plus its fee do not equal the note value.
    #[error("value_mismatch: the note holds {note} zatoshis but the outputs and fee total {outputs_and_fee}")]
    ValueMismatch {
        /// The escrow note's value.
        note: u64,
        /// The outputs plus the fee.
        outputs_and_fee: u64,
    },

    /// The memo and the package disagree on the quote id, or the outputs do.
    #[error("quote_id_mismatch: {0}")]
    QuoteIdMismatch(String),

    /// A quote carried a refund-address key.
    #[error("refund_field_rejected: a quote cannot carry `{0}`")]
    RefundFieldRejected(String),

    /// A quote does not parse.
    #[error("invalid_quote: {0}")]
    InvalidQuote(String),

    /// The NEAR receipt carries a Zcash address, a Zcash transaction id, or
    /// the zatoshi amount. The message names the kind, never the value.
    #[error("banned_field: {0}")]
    BannedField(String),

    /// The NEAR receipt lacks a field the quote requires, or it differs.
    #[error("missing_field: {0}")]
    MissingField(String),

    /// The NEAR payload could not be fetched or read.
    #[error("attestation: {0}")]
    Attestation(String),

    /// The coordinator's signing package is not the PCZT's own.
    #[error("package_mismatch: the package {0} is not the PCZT's")]
    PackageMismatch(&'static str),

    /// The deadline device was asked to sign a package that pays the solver.
    #[error("refused_release: the deadline device never signs a payout to the solver")]
    RefusedRelease,

    /// A package presented as a refund is not one.
    #[error("not_a_refund: {0}")]
    NotARefund(String),

    /// A refund was asked for before the quote's expiry.
    #[error("not_expired: the quote expires at {expiry_unix} and it is {now}")]
    NotExpired {
        /// The quote's expiry.
        expiry_unix: u64,
        /// The time the signer was given.
        now: u64,
    },

    /// A package presented as a release does not pay the solver the quote.
    #[error("not_a_release: {0}")]
    NotARelease(String),

    /// A policy signer was handed another holder's share file.
    #[error("wrong_role: expected the {expected:?} share, found the {found:?} share")]
    WrongRole {
        /// The role the signer plays.
        expected: SignerId,
        /// The role the share file belongs to.
        found: SignerId,
    },

    /// An escrow spend pays more in fees than the policy allows.
    #[error("fee_too_high: the package pays {fee} zatoshis in fees, above the {max} cap")]
    FeeTooHigh {
        /// The package's fee.
        fee: u64,
        /// The cap.
        max: u64,
    },

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
