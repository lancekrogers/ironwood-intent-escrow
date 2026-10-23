//! What a co-signer checks in an escrow spend package before round 2,
//! without holding any share.
//!
//! The view takes the PCZT, `escrow.fvk` (which every holder has), and the
//! outgoing viewing key the package's outputs were encrypted to: the escrow
//! OVK for a release, the refund account's OVK for a refund, which the
//! solver does not hold. It trusts no field of the package it has not
//! checked:
//!
//! - nothing outside one Ironwood bundle: no transparent input or output, no
//!   Sapling spend or output, no Orchard action;
//! - every Ironwood action's value commitment, output note commitment,
//!   nullifier, and `rk` verified, so the values it reports are the values
//!   the transaction moves;
//! - every value-carrying output opened under the given OVK, which refuses
//!   one encrypted to the all-zero key.

use orchard::keys::{FullViewingKey, OutgoingViewingKey};
use orchard::note::ExtractedNoteCommitment;
use orchard::pczt::Bundle;
use pasta_curves::group::ff::PrimeField;
use pczt::roles::signer::Signer;
use pczt::roles::verifier::Verifier;
use pczt::Pczt;
use sha2::{Digest, Sha256};

use crate::cosign::SpendRandomizer;
use crate::error::Error;
use crate::note::QUOTE_ID_KEY;
use crate::quote::QuoteId;

/// One value-carrying output of the escrow spend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewOutput {
    /// The Ironwood action that carries it.
    pub action_index: usize,
    /// Who it pays.
    pub address: orchard::Address,
    /// How much, in zatoshis.
    pub value: u64,
}

/// The facts a round 2 signer compares against its policy.
#[derive(Clone, Debug)]
pub struct CheckerView {
    /// The commitment (`cmx`) of the escrow note being spent.
    pub spent_cmx: [u8; 32],
    /// The escrow note's value.
    pub spent_value: u64,
    /// What the escrow note pays that no output receives: the fee.
    pub fee: u64,
    /// The Ironwood action that spends it.
    pub spend_index: usize,
    /// Every value-carrying output, opened under the escrow OVK.
    pub outputs: Vec<ViewOutput>,
    /// The quote id in every output's memo, equal to the package's copy.
    pub quote_id: QuoteId,
    /// The shielded sighash the FROST signature covers.
    pub sighash: [u8; 32],
    /// The escrow spend's `alpha`, which becomes `SigningPackage.randomizer`.
    pub randomizer: SpendRandomizer,
    /// SHA-256 of the serialized package, which becomes
    /// `SigningPackage.pczt_hash`.
    pub pczt_hash: [u8; 32],
}

/// What the Ironwood bundle yields, before the cross-checks.
#[derive(Default)]
struct Scan {
    spend: Option<(usize, [u8; 32], u64, [u8; 32])>,
    spent_total: u64,
    output_total: u64,
    outputs: Vec<ViewOutput>,
    memo_ids: Vec<QuoteId>,
    problems: Vec<String>,
}

/// What any signer can verify in an escrow spend package without an
/// outgoing viewing key: every field bound to its commitment, and the
/// signing inputs. Output addresses come from the package's own fields,
/// which `verify_action` has bound to each output's note commitment.
#[derive(Clone, Debug)]
pub struct PackageFacts {
    /// The commitment (`cmx`) of the escrow note being spent.
    pub spent_cmx: [u8; 32],
    /// The escrow note's value.
    pub spent_value: u64,
    /// What the escrow note pays that no output receives: the fee.
    pub fee: u64,
    /// The Ironwood action that spends it.
    pub spend_index: usize,
    /// Every value-carrying output.
    pub outputs: Vec<ViewOutput>,
    /// The shielded sighash the FROST signature covers.
    pub sighash: [u8; 32],
    /// The escrow spend's `alpha`.
    pub randomizer: SpendRandomizer,
    /// SHA-256 of the serialized package.
    pub pczt_hash: [u8; 32],
}

/// Verifies an escrow spend package and returns its facts. The deadline
/// signer uses this to refuse a solver payout before it opens any memo.
pub fn verify_package(pczt: &Pczt, escrow_fvk: &FullViewingKey) -> Result<PackageFacts, Error> {
    verify(pczt, escrow_fvk, None).map(|(facts, _)| facts)
}

impl CheckerView {
    /// Reads the view from an IO-finalized escrow spend package whose
    /// outputs were encrypted to `output_ovk`.
    pub fn new(
        pczt: &Pczt,
        escrow_fvk: &FullViewingKey,
        output_ovk: &OutgoingViewingKey,
    ) -> Result<Self, Error> {
        let (facts, memo_ids) = verify(pczt, escrow_fvk, Some(output_ovk))?;
        let quote_id = agreed_quote_id(pczt, &memo_ids)?;
        Ok(CheckerView {
            spent_cmx: facts.spent_cmx,
            spent_value: facts.spent_value,
            fee: facts.fee,
            spend_index: facts.spend_index,
            outputs: facts.outputs,
            quote_id,
            sighash: facts.sighash,
            randomizer: facts.randomizer,
            pczt_hash: facts.pczt_hash,
        })
    }
}

fn verify(
    pczt: &Pczt,
    escrow_fvk: &FullViewingKey,
    output_ovk: Option<&OutgoingViewingKey>,
) -> Result<(PackageFacts, Vec<QuoteId>), Error> {
    refuse_other_pools(pczt)?;
    let pczt_hash = pczt_hash(pczt)?;
    let sighash = Signer::new(pczt.clone())
        .map_err(|e| Error::Pczt(format!("signer: {e:?}")))?
        .shielded_sighash();
    let mut scan = None;
    Verifier::new(pczt.clone())
        .with_ironwood::<(), _>(|bundle| {
            scan = Some(scan_bundle(bundle, escrow_fvk, output_ovk));
            Ok(())
        })
        .map_err(|e| Error::Pczt(format!("verifier: {e:?}")))?;
    let scan = scan.ok_or_else(|| Error::Pczt("no Ironwood bundle".into()))?;
    if let Some(problem) = scan.problems.first() {
        return Err(Error::Pczt(problem.clone()));
    }
    let (spend_index, alpha, spent_value, spent_cmx) = scan
        .spend
        .ok_or_else(|| Error::Pczt("the package spends no escrow note".into()))?;
    let fee = scan
        .spent_total
        .checked_sub(scan.output_total)
        .ok_or_else(|| Error::Pczt("the outputs exceed what the package spends".into()))?;
    let facts = PackageFacts {
        spent_cmx,
        spent_value,
        fee,
        spend_index,
        outputs: scan.outputs,
        sighash,
        randomizer: SpendRandomizer::deserialize(&alpha)?,
        pczt_hash,
    };
    Ok((facts, scan.memo_ids))
}

/// SHA-256 of the package's serialized bytes.
pub fn pczt_hash(pczt: &Pczt) -> Result<[u8; 32], Error> {
    let bytes = pczt
        .clone()
        .serialize()
        .map_err(|e| Error::Pczt(format!("serialize: {e:?}")))?;
    Ok(Sha256::digest(bytes).into())
}

/// An escrow spend has one Ironwood bundle and nothing else.
fn refuse_other_pools(pczt: &Pczt) -> Result<(), Error> {
    let transparent = pczt.transparent();
    if !transparent.inputs().is_empty() || !transparent.outputs().is_empty() {
        return Err(Error::TransparentOutput);
    }
    let sapling = pczt.sapling();
    if !sapling.spends().is_empty() || !sapling.outputs().is_empty() {
        return Err(Error::Pczt("the package has a Sapling part".into()));
    }
    if !pczt.orchard().actions().is_empty() {
        return Err(Error::Pczt("the package has an Orchard action".into()));
    }
    Ok(())
}

fn scan_bundle(
    bundle: &Bundle,
    escrow_fvk: &FullViewingKey,
    ovk: Option<&OutgoingViewingKey>,
) -> Scan {
    let version = *bundle.bundle_version();
    let mut scan = Scan::default();
    for (index, action) in bundle.actions().iter().enumerate() {
        if let Err(e) = verify_action(action, escrow_fvk) {
            scan.problems.push(format!("action {index}: {e}"));
            continue;
        }
        let spend_value = action.spend().value().map(|v| v.inner()).unwrap_or(0);
        let output_value = action.output().value().map(|v| v.inner()).unwrap_or(0);
        scan.spent_total = scan.spent_total.saturating_add(spend_value);
        scan.output_total = scan.output_total.saturating_add(output_value);
        if spend_value > 0 {
            record_spend(&mut scan, index, action, escrow_fvk, spend_value);
        }
        if output_value > 0 {
            record_output(&mut scan, index, action, ovk, version, output_value);
        }
    }
    scan
}

/// The escrow spend, which must be the package's only value-carrying spend.
fn record_spend(
    scan: &mut Scan,
    index: usize,
    action: &orchard::pczt::Action,
    escrow_fvk: &FullViewingKey,
    value: u64,
) {
    match escrow_spend(action, escrow_fvk) {
        Ok((alpha, cmx)) if scan.spend.is_none() => scan.spend = Some((index, alpha, value, cmx)),
        Ok(_) => scan
            .problems
            .push("the package spends more than one note".into()),
        Err(e) => scan.problems.push(e),
    }
}

/// A value-carrying output: its verified recipient field without an OVK,
/// or the note and memo opened under the OVK.
fn record_output(
    scan: &mut Scan,
    index: usize,
    action: &orchard::pczt::Action,
    ovk: Option<&OutgoingViewingKey>,
    version: orchard::bundle::BundleVersion,
    value: u64,
) {
    let Some(ovk) = ovk else {
        match action.output().recipient() {
            Some(address) => scan.outputs.push(ViewOutput {
                action_index: index,
                address: *address,
                value,
            }),
            None => scan
                .problems
                .push(format!("output {index} has no recipient")),
        }
        return;
    };
    match action.recover_output_with_ovk(ovk, version) {
        Ok(Some((note, address, memo))) if note.value().inner() == value => {
            scan.outputs.push(ViewOutput {
                action_index: index,
                address,
                value,
            });
            match QuoteId::from_memo(&memo) {
                Ok(id) => scan.memo_ids.push(id),
                Err(e) => scan.problems.push(format!("output {index}: {e}")),
            }
        }
        _ => scan.problems.push(format!(
            "output {index} does not open under the given outgoing viewing key"
        )),
    }
}

/// Binds every field the view reads to the action's commitments. A spend
/// with value must belong to `escrow.fvk`; a zero-valued dummy spend may
/// carry its own key.
fn verify_action(
    action: &orchard::pczt::Action,
    escrow_fvk: &FullViewingKey,
) -> Result<(), String> {
    action
        .verify_cv_net()
        .map_err(|e| format!("value commitment: {e:?}"))?;
    action
        .output()
        .verify_note_commitment(action.spend())
        .map_err(|e| format!("output note commitment: {e:?}"))?;
    action
        .spend()
        .verify_nullifier(Some(escrow_fvk))
        .map_err(|e| format!("nullifier: {e:?}"))?;
    action
        .spend()
        .verify_rk(Some(escrow_fvk))
        .map_err(|e| format!("rk: {e:?}"))
}

/// The escrow spend's `alpha` and spent `cmx`, after checking that `rk` and
/// the nullifier come from `escrow.fvk`.
fn escrow_spend(
    action: &orchard::pczt::Action,
    fvk: &FullViewingKey,
) -> Result<([u8; 32], [u8; 32]), String> {
    let spend = action.spend();
    spend
        .verify_rk(Some(fvk))
        .map_err(|e| format!("the spend is not authorized by escrow.fvk: {e:?}"))?;
    spend
        .verify_nullifier(Some(fvk))
        .map_err(|e| format!("the nullifier is not escrow.fvk's: {e:?}"))?;
    let alpha = spend.alpha().ok_or("the spend has no alpha")?.to_repr();
    let (Some(recipient), Some(value), Some(rho), Some(rseed)) =
        (spend.recipient(), spend.value(), spend.rho(), spend.rseed())
    else {
        return Err("the spend does not carry its note".into());
    };
    let note = Option::<orchard::Note>::from(orchard::Note::from_parts(
        *recipient,
        *value,
        *rho,
        *rseed,
        *spend.note_version(),
    ))
    .ok_or("the spent note is invalid")?;
    Ok((
        alpha,
        ExtractedNoteCommitment::from(note.commitment()).to_bytes(),
    ))
}

/// The memo quote id, which every output must share and the package's
/// proprietary copy must equal.
fn agreed_quote_id(pczt: &Pczt, memo_ids: &[QuoteId]) -> Result<QuoteId, Error> {
    let first = *memo_ids
        .first()
        .ok_or_else(|| Error::Pczt("no output carries a quote id".into()))?;
    if memo_ids.iter().any(|id| *id != first) {
        return Err(Error::QuoteIdMismatch(
            "the outputs carry different quote ids".into(),
        ));
    }
    let carried = pczt
        .global()
        .proprietary()
        .get(QUOTE_ID_KEY)
        .ok_or_else(|| Error::QuoteIdMismatch("the package carries no quote id".into()))?;
    let carried = std::str::from_utf8(carried)
        .map_err(|_| Error::QuoteIdMismatch("the package quote id is not text".into()))
        .and_then(QuoteId::from_hex)?;
    if carried != first {
        return Err(Error::QuoteIdMismatch(
            "the memo and the package carry different quote ids".into(),
        ));
    }
    Ok(first)
}
