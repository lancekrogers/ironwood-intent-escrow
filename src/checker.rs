//! The checker for the ZEC side (product rules 1, 2, and 8).
//!
//! It runs on raw transaction bytes, so it can check a stored broadcast
//! transaction as well as a freshly built one. The NEAR receipt check is
//! sequence 04's `attest`.

use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

use crate::error::Error;
use crate::note::{no_action_opens_under_zero_ovk, transparent_bundle_is_empty};

/// Fails a ZEC transaction with any transparent input or output
/// (`transparent_output`), or with any Orchard or Ironwood action whose
/// `out_ciphertext` opens under the all-zero outgoing viewing key
/// (`zero_outgoing_viewing_key`). The errors carry no note plaintext and no
/// key.
pub fn check_zec(tx_bytes: &[u8]) -> Result<(), Error> {
    // v5 and v6 transactions carry their consensus branch id in the header;
    // the argument only matters for v4 and earlier, which this crate never
    // builds.
    let tx = Transaction::read(tx_bytes, BranchId::Nu7)
        .map_err(|e| Error::Checker(format!("the bytes are not a transaction: {e}")))?;
    if !transparent_bundle_is_empty(&tx) {
        return Err(Error::TransparentOutput);
    }
    if !no_action_opens_under_zero_ovk(&tx) {
        return Err(Error::ZeroOutgoingViewingKey);
    }
    Ok(())
}
