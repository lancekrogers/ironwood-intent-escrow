//! The checker for the ZEC side (product rules 1, 2, and 8).
//!
//! It runs on raw transaction bytes, so it can check a stored broadcast
//! transaction as well as a freshly built one. The NEAR receipt check is
//! sequence 04's `attest`.

use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

use crate::error::Error;
use orchard::keys::OutgoingViewingKey;

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

/// The all-zero outgoing viewing key. An output encrypted to it can be read
/// by anyone, which is how indexers read bridge payouts. Never used here.
pub const ZERO_OVK: [u8; 32] = [0u8; 32];

/// Whether the transaction has no transparent input and no transparent
/// output.
pub fn transparent_bundle_is_empty(tx: &Transaction) -> bool {
    tx.transparent_bundle()
        .is_none_or(|b| b.vin.is_empty() && b.vout.is_empty())
}

/// The shielded actions, Orchard and Ironwood, whose `out_ciphertext` opens
/// under `ovk`, as `(pool, action index)`. Trial decryption is the only
/// test: the outgoing viewing key is not a transaction field.
pub fn actions_opening_under(
    tx: &Transaction,
    ovk: &OutgoingViewingKey,
) -> Vec<(&'static str, usize)> {
    let pools = [
        ("orchard", tx.orchard_bundle()),
        ("ironwood", tx.ironwood_bundle()),
    ];
    pools
        .into_iter()
        .flat_map(|(pool, bundle)| {
            bundle.into_iter().flat_map(move |b| {
                (0..b.actions().len())
                    .filter(|i| b.recover_output_with_ovk(*i, ovk).is_some())
                    .map(move |i| (pool, i))
            })
        })
        .collect()
}

/// Whether no shielded action opens under the all-zero outgoing viewing key.
pub fn no_action_opens_under_zero_ovk(tx: &Transaction) -> bool {
    actions_opening_under(tx, &OutgoingViewingKey::from(ZERO_OVK)).is_empty()
}
