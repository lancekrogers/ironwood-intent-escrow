//! The two policy signers: round 2 wrappers that refuse before a share
//! exists (`docs/decisions/shares.md`).
//!
//! - The payer signs a release only after re-fetching the NEAR payment
//!   (`attest`), and only for a package that pays the solver the quote.
//! - The deadline device, the payer's second device, never signs a package
//!   that pays the solver. It signs only a refund after the quote's expiry.
//!
//! Each signer first checks the coordinator's `SigningPackage` against the
//! PCZT it holds: the package hash, the sighash, and the randomizer must be
//! the PCZT's own, or the answer is `package_mismatch` before anything else
//! runs, including any RPC call.

use orchard::keys::{FullViewingKey, OutgoingViewingKey, Scope};
use pczt::Pczt;
use reddsa::frost::redpallas::round1::SigningNonces;
use zcash_keys::address::UnifiedAddress;

use crate::address::require_ironwood_only;
use crate::attest::{attest, Attestation, Banned, NearRpc, NearTxPointer};
use crate::cosign::{Commitments, Share, SignerId, SigningPackage};
use crate::error::Error;
use crate::frost::{round2, ShareFile};
use crate::quote::Quote;
use crate::view::{verify_package, CheckerView, PackageFacts};

/// The signing package the coordinator builds from the package facts and
/// the round 1 commitments of the two signers taking part.
pub fn signing_package(facts: &PackageFacts, commitments: Vec<Commitments>) -> SigningPackage {
    SigningPackage {
        sighash: facts.sighash,
        randomizer: facts.randomizer,
        commitments,
        pczt_hash: facts.pczt_hash,
    }
}

/// The payer process: `payer.key`, `escrow.fvk`, and the solver's address.
pub struct PayerSigner {
    share: ShareFile,
    escrow_fvk: FullViewingKey,
    solver: orchard::Address,
}

/// The deadline device: `deadline.key`, `escrow.fvk`, the payer's refund
/// full viewing key, and the solver's address.
pub struct DeadlineSigner {
    #[allow(dead_code)] // signs refunds, which the next task (04_refund_rule) adds
    share: ShareFile,
    escrow_fvk: FullViewingKey,
    #[allow(dead_code)] // recognises refund outputs, added in 04_refund_rule
    refund_fvk: FullViewingKey,
    solver: orchard::Address,
}

impl PayerSigner {
    /// Refuses a share file that is not the payer's.
    pub fn new(
        share: ShareFile,
        escrow_fvk: FullViewingKey,
        solver: &UnifiedAddress,
    ) -> Result<Self, Error> {
        require_role(&share, SignerId::Payer)?;
        Ok(PayerSigner {
            share,
            escrow_fvk,
            solver: ironwood_receiver(solver)?,
        })
    }
}

impl DeadlineSigner {
    /// Refuses a share file that is not the deadline device's.
    pub fn new(
        share: ShareFile,
        escrow_fvk: FullViewingKey,
        refund_fvk: FullViewingKey,
        solver: &UnifiedAddress,
    ) -> Result<Self, Error> {
        require_role(&share, SignerId::Deadline)?;
        Ok(DeadlineSigner {
            share,
            escrow_fvk,
            refund_fvk,
            solver: ironwood_receiver(solver)?,
        })
    }
}

/// The escrow OVK, which a release encrypts its output to.
pub fn release_ovk(escrow_fvk: &FullViewingKey) -> OutgoingViewingKey {
    escrow_fvk.to_ovk(Scope::External)
}

/// The payer's round 2 for a release:
///
/// 1. the package must be this PCZT's (`package_mismatch`), checked before
///    any RPC call;
/// 2. `attest` must accept the NEAR payment the pointer names;
/// 3. the PCZT's single output must pay the solver, with the quote id in
///    its memo (`not_a_release`).
#[allow(clippy::too_many_arguments)]
pub fn payer_release(
    signer: &PayerSigner,
    quote: &Quote,
    pczt: &Pczt,
    pointer: &NearTxPointer,
    banned: &Banned,
    rpc: &dyn NearRpc,
    nonces: SigningNonces,
    package: &SigningPackage,
) -> Result<(Share, Attestation), Error> {
    check_package(pczt, package, &signer.escrow_fvk)?;
    let attestation = attest(quote, pointer, banned, rpc)?;
    let view = CheckerView::new(pczt, &signer.escrow_fvk, &release_ovk(&signer.escrow_fvk))?;
    let pays_solver = matches!(view.outputs.as_slice(), [only] if only.address == signer.solver);
    if !pays_solver {
        return Err(Error::NotARelease(
            "the package does not pay the solver alone".into(),
        ));
    }
    if view.quote_id != quote.id {
        return Err(Error::NotARelease(
            "the memo carries another quote id".into(),
        ));
    }
    Ok((round2(&signer.share, nonces, package)?, attestation))
}

/// The deadline device's round 2. A package that pays the solver is
/// `refused_release`, checked first and unconditionally.
pub fn deadline_sign(
    signer: &DeadlineSigner,
    _quote: &Quote,
    pczt: &Pczt,
    _nonces: SigningNonces,
    package: &SigningPackage,
    _now: u64,
) -> Result<Share, Error> {
    let facts = check_package(pczt, package, &signer.escrow_fvk)?;
    if facts.outputs.iter().any(|o| o.address == signer.solver) {
        return Err(Error::RefusedRelease);
    }
    Err(Error::NotARefund(
        "refund signing is not defined yet".into(),
    ))
}

/// The package must be the PCZT's own: hash, sighash, and randomizer.
fn check_package(
    pczt: &Pczt,
    package: &SigningPackage,
    escrow_fvk: &FullViewingKey,
) -> Result<PackageFacts, Error> {
    let facts = verify_package(pczt, escrow_fvk)?;
    if package.pczt_hash != facts.pczt_hash {
        return Err(Error::PackageMismatch("pczt_hash"));
    }
    if package.sighash != facts.sighash {
        return Err(Error::PackageMismatch("sighash"));
    }
    if package.randomizer != facts.randomizer {
        return Err(Error::PackageMismatch("randomizer"));
    }
    Ok(facts)
}

fn require_role(share: &ShareFile, role: SignerId) -> Result<(), Error> {
    if share.signer() == role {
        Ok(())
    } else {
        Err(Error::WrongRole {
            expected: role,
            found: share.signer(),
        })
    }
}

fn ironwood_receiver(address: &UnifiedAddress) -> Result<orchard::Address, Error> {
    require_ironwood_only(address)?;
    address
        .orchard()
        .copied()
        .ok_or(Error::NotIronwoodOnly("it has no Orchard receiver"))
}
