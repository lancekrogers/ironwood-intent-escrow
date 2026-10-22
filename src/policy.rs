//! The two policy signers: round 2 wrappers that refuse before a share
//! exists (`docs/decisions/shares.md`).
//!
//! - The payer signs a release only after re-fetching the NEAR payment
//!   (`attest`), and only for a package that pays the solver the quote.
//! - The deadline device, the payer's second device, never signs a package
//!   that pays the solver. It signs only a refund after the quote's expiry.
//! - A refund is built inside the payer's wallet: the address is allocated
//!   from the refund key when the package is built, and the output is
//!   encrypted to the refund OVK, which the solver does not hold.
//!
//! - The solver signs only a package that pays the solver alone, for the
//!   quote it filled. Without this, the payer, who coordinates, could hand
//!   the solver a refund to co-sign after the solver paid on NEAR.
//!
//! Each signer first checks the coordinator's `SigningPackage` against the
//! PCZT it holds: the package hash, the sighash, and the randomizer must be
//! the PCZT's own, or the answer is `package_mismatch` before anything else
//! runs, including any RPC call. Every signer also refuses a fee above
//! [`MAX_ESCROW_FEE`].

use orchard::keys::{FullViewingKey, OutgoingViewingKey, Scope};
use pczt::Pczt;
use reddsa::frost::redpallas::round1::SigningNonces;
use zcash_keys::address::UnifiedAddress;
use zcash_protocol::value::Zatoshis;

use crate::address::require_ironwood_only;
use crate::attest::{attest, Attestation, Banned, NearRpc, NearTxPointer};
use crate::cosign::{Commitments, Share, SignerId, SigningPackage};
use crate::error::Error;
use crate::frost::{round2, ShareFile};
use crate::note::{escrow_spend_fee, spend_pczt, EscrowSpend, NoteInputs, SpendOutput};
use crate::quote::Quote;
use crate::view::{verify_package, CheckerView, PackageFacts};
use crate::wallet::PayerWallet;

/// The most an escrow spend may pay in fees. The builder's ZIP 317 fee for
/// the two-action escrow spend is 10,000 zatoshis; a package above this cap
/// would be routing escrow value to the miners.
pub const MAX_ESCROW_FEE: u64 = 100_000;

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

/// The payer process: `payer.key`, `escrow.fvk`, the payer's refund full
/// viewing key, and the solver's address.
pub struct PayerSigner {
    share: ShareFile,
    escrow_fvk: FullViewingKey,
    refund_fvk: FullViewingKey,
    solver: orchard::Address,
}

/// The deadline device: `deadline.key`, `escrow.fvk`, the payer's refund
/// full viewing key, and the solver's address.
pub struct DeadlineSigner {
    share: ShareFile,
    escrow_fvk: FullViewingKey,
    refund_fvk: FullViewingKey,
    solver: orchard::Address,
}

/// The solver process: `solver.key`, `escrow.fvk`, and its own address.
pub struct SolverSigner {
    share: ShareFile,
    escrow_fvk: FullViewingKey,
    solver: orchard::Address,
}

impl SolverSigner {
    /// Refuses a share file that is not the solver's.
    pub fn new(
        share: ShareFile,
        escrow_fvk: FullViewingKey,
        own_address: &UnifiedAddress,
    ) -> Result<Self, Error> {
        require_role(&share, SignerId::Solver)?;
        Ok(SolverSigner {
            share,
            escrow_fvk,
            solver: ironwood_receiver(own_address)?,
        })
    }
}

/// The solver's round 2 for a release: the package must be the PCZT's, the
/// fee within the cap, and the single output must pay the solver, with the
/// quote id the solver filled in its memo (`not_a_release`).
pub fn solver_release(
    signer: &SolverSigner,
    quote: &Quote,
    pczt: &Pczt,
    nonces: SigningNonces,
    package: &SigningPackage,
) -> Result<Share, Error> {
    check_package(pczt, package, &signer.escrow_fvk)?;
    let view = CheckerView::new(pczt, &signer.escrow_fvk, &release_ovk(&signer.escrow_fvk))
        .map_err(|e| {
            Error::NotARelease(format!("the outputs do not open under the escrow key: {e}"))
        })?;
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
    round2(&signer.share, nonces, package)
}

impl PayerSigner {
    /// Refuses a share file that is not the payer's.
    pub fn new(
        share: ShareFile,
        escrow_fvk: FullViewingKey,
        refund_fvk: FullViewingKey,
        solver: &UnifiedAddress,
    ) -> Result<Self, Error> {
        require_role(&share, SignerId::Payer)?;
        Ok(PayerSigner {
            share,
            escrow_fvk,
            refund_fvk,
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

/// The deadline device's round 2, in the order `shares.md` fixes:
///
/// 1. the package must be the PCZT's own (`package_mismatch`);
/// 2. a package that pays the solver is `refused_release`, checked first
///    and unconditionally;
/// 3. the memo quote id must be `quote.id` (`not_a_refund`);
/// 4. `now` must be at or past `quote.expiry_unix`, the expiry of the quote
///    the device was handed, never one read from the memo (`not_expired`);
/// 5. every output must be an address the payer's refund key detects
///    (`not_a_refund`).
pub fn deadline_sign(
    signer: &DeadlineSigner,
    quote: &Quote,
    pczt: &Pczt,
    nonces: SigningNonces,
    package: &SigningPackage,
    now: u64,
) -> Result<Share, Error> {
    let facts = check_package(pczt, package, &signer.escrow_fvk)?;
    if facts.outputs.iter().any(|o| o.address == signer.solver) {
        return Err(Error::RefusedRelease);
    }
    check_refund(quote, pczt, &signer.escrow_fvk, &signer.refund_fvk, now)?;
    round2(&signer.share, nonces, package)
}

/// The payer's round 2 for a refund: the same checks as the deadline
/// device, against the payer's own refund key.
pub fn payer_refund(
    signer: &PayerSigner,
    quote: &Quote,
    pczt: &Pczt,
    nonces: SigningNonces,
    package: &SigningPackage,
    now: u64,
) -> Result<Share, Error> {
    let facts = check_package(pczt, package, &signer.escrow_fvk)?;
    if facts.outputs.iter().any(|o| o.address == signer.solver) {
        return Err(Error::NotARefund("the package pays the solver".into()));
    }
    check_refund(quote, pczt, &signer.escrow_fvk, &signer.refund_fvk, now)?;
    round2(&signer.share, nonces, package)
}

/// The refund OVK: a refund's output opens under it, and the solver does
/// not hold it.
pub fn refund_ovk(refund_fvk: &FullViewingKey) -> OutgoingViewingKey {
    refund_fvk.to_ovk(Scope::External)
}

/// Builds the refund package after expiry: the escrow note, less the fee,
/// to a fresh address from the payer wallet's refund key, encrypted to the
/// refund OVK, with `quote.id` in the memo. The address comes from the
/// wallet, never from the quote, and the quote is not written.
pub fn build_refund(
    quote: &Quote,
    escrow_note: &NoteInputs,
    wallet: &mut PayerWallet,
    now: u64,
) -> Result<EscrowSpend, Error> {
    if now < quote.expiry_unix {
        return Err(Error::NotExpired {
            expiry_unix: quote.expiry_unix,
            now,
        });
    }
    let address = wallet.fresh_refund_address()?;
    let network = wallet.network();
    let fee = escrow_spend_fee(network, escrow_note, 1)?;
    let value = escrow_note
        .note
        .value()
        .inner()
        .checked_sub(fee.into_u64())
        .ok_or(Error::InsufficientFunds {
            have: escrow_note.note.value().inner(),
            need: fee.into_u64(),
        })?;
    let outputs = [SpendOutput {
        address,
        value: Zatoshis::from_u64(value).map_err(|e| Error::Pczt(format!("{e:?}")))?,
    }];
    spend_pczt(
        network,
        escrow_note,
        &outputs,
        &quote.id,
        &refund_ovk(&wallet.refund_fvk()?),
    )
}

/// Steps 3 to 5 of the refund rule.
fn check_refund(
    quote: &Quote,
    pczt: &Pczt,
    escrow_fvk: &FullViewingKey,
    refund_fvk: &FullViewingKey,
    now: u64,
) -> Result<(), Error> {
    let view = CheckerView::new(pczt, escrow_fvk, &refund_ovk(refund_fvk)).map_err(|e| {
        Error::NotARefund(format!("the outputs do not open under the refund key: {e}"))
    })?;
    if view.quote_id != quote.id {
        return Err(Error::NotARefund(
            "the memo carries another quote id".into(),
        ));
    }
    if now < quote.expiry_unix {
        return Err(Error::NotExpired {
            expiry_unix: quote.expiry_unix,
            now,
        });
    }
    if view
        .outputs
        .iter()
        .any(|o| refund_fvk.scope_for_address(&o.address).is_none())
    {
        return Err(Error::NotARefund(
            "an output is not an address the refund key detects".into(),
        ));
    }
    Ok(())
}

/// The package must be the PCZT's own (hash, sighash, and randomizer), and
/// its fee within [`MAX_ESCROW_FEE`].
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
    if facts.fee > MAX_ESCROW_FEE {
        return Err(Error::FeeTooHigh {
            fee: facts.fee,
            max: MAX_ESCROW_FEE,
        });
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
