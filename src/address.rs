//! The escrow's receiving address.
//!
//! Ironwood shares the Orchard receiver in a unified address (zcash_keys
//! 0.17.0, `src/address.rs:847`). The transaction builder picks the Ironwood
//! pool, not the address. So an Ironwood-only unified address is one whose
//! only receiver is Orchard: no transparent receiver, no Sapling receiver,
//! and no receiver of an unknown type.
//!
//! The legacy (`use_qsk = false`) derivation from `docs/decisions/stack.md`
//! applies: the receiver comes from the full viewing key's incoming viewing
//! key, which needs `nk` and `rivk`. `ak` alone cannot derive it.

use orchard::keys::{FullViewingKey, Scope};
use zcash_keys::address::UnifiedAddress;
use zcash_protocol::consensus::Parameters;

use crate::error::Error;

/// The escrow address: the external-scope Orchard receiver at diversifier
/// index 0 of `escrow.fvk`, alone in a unified address.
pub fn escrow_address(fvk: &FullViewingKey) -> UnifiedAddress {
    let receiver = fvk.address_at(0u32, Scope::External);
    UnifiedAddress::from_receivers(Some(receiver), None, None, None, None)
        .expect("a unified address with an Orchard receiver always exists")
}

/// Refuses a unified address with any receiver Ironwood does not use.
pub fn require_ironwood_only(address: &UnifiedAddress) -> Result<(), Error> {
    if address.has_transparent() {
        return Err(Error::NotIronwoodOnly("it has a transparent receiver"));
    }
    if address.has_sapling() {
        return Err(Error::NotIronwoodOnly("it has a Sapling receiver"));
    }
    if !address.unknown().is_empty() {
        return Err(Error::NotIronwoodOnly("it has a receiver of unknown type"));
    }
    if !address.has_orchard() {
        return Err(Error::NotIronwoodOnly("it has no Orchard receiver"));
    }
    Ok(())
}

/// Decodes a unified address for `params`' network and refuses it unless it
/// is Ironwood-only.
pub fn parse_ironwood_address<P: Parameters>(
    params: &P,
    encoded: &str,
) -> Result<UnifiedAddress, Error> {
    let address =
        UnifiedAddress::decode(params, encoded).map_err(|e| Error::AddressDecode(e.to_string()))?;
    require_ironwood_only(&address)?;
    Ok(address)
}
