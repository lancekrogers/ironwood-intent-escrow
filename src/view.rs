//! What a co-signer checks in an escrow spend package before round 2,
//! without holding any share.
//!
//! The view needs the PCZT and `escrow.fvk`, which every holder has. The
//! memo is inside the encrypted output, and the escrow spend encrypts its
//! outputs to the escrow's own outgoing viewing key, so `escrow.fvk` opens
//! them. An output that does not open under it, including one encrypted to
//! the all-zero key, makes the view fail.

use orchard::keys::{FullViewingKey, Scope};
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
struct Scan {
    spend: Option<(usize, [u8; 32], u64, [u8; 32])>,
    outputs: Vec<ViewOutput>,
    memo_ids: Vec<QuoteId>,
    problems: Vec<String>,
}

impl CheckerView {
    /// Reads the view from an IO-finalized escrow spend package.
    pub fn new(pczt: &Pczt, escrow_fvk: &FullViewingKey) -> Result<Self, Error> {
        let pczt_hash = pczt_hash(pczt)?;
        let sighash = Signer::new(pczt.clone())
            .map_err(|e| Error::Pczt(format!("signer: {e:?}")))?
            .shielded_sighash();
        let mut scan = None;
        Verifier::new(pczt.clone())
            .with_ironwood::<(), _>(|bundle| {
                scan = Some(scan_bundle(bundle, escrow_fvk));
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
        let quote_id = agreed_quote_id(pczt, &scan.memo_ids)?;
        Ok(CheckerView {
            spent_cmx,
            spent_value,
            spend_index,
            outputs: scan.outputs,
            quote_id,
            sighash,
            randomizer: SpendRandomizer::deserialize(&alpha)?,
            pczt_hash,
        })
    }
}

/// SHA-256 of the package's serialized bytes.
pub fn pczt_hash(pczt: &Pczt) -> Result<[u8; 32], Error> {
    let bytes = pczt
        .clone()
        .serialize()
        .map_err(|e| Error::Pczt(format!("serialize: {e:?}")))?;
    Ok(Sha256::digest(bytes).into())
}

fn scan_bundle(bundle: &Bundle, escrow_fvk: &FullViewingKey) -> Scan {
    let ovk = escrow_fvk.to_ovk(Scope::External);
    let version = *bundle.bundle_version();
    let mut scan = Scan {
        spend: None,
        outputs: vec![],
        memo_ids: vec![],
        problems: vec![],
    };
    for (index, action) in bundle.actions().iter().enumerate() {
        let spend = action.spend();
        let spend_value = spend.value().map(|v| v.inner()).unwrap_or(0);
        if spend_value > 0 {
            match escrow_spend(action, escrow_fvk) {
                Ok((alpha, cmx)) if scan.spend.is_none() => {
                    scan.spend = Some((index, alpha, spend_value, cmx))
                }
                Ok(_) => scan
                    .problems
                    .push("the package spends more than one note".into()),
                Err(e) => scan.problems.push(e),
            }
        }
        let output_value = action.output().value().map(|v| v.inner()).unwrap_or(0);
        if output_value == 0 {
            continue;
        }
        match action.recover_output_with_ovk(&ovk, version) {
            Ok(Some((note, address, memo))) if note.value().inner() == output_value => {
                scan.outputs.push(ViewOutput {
                    action_index: index,
                    address,
                    value: output_value,
                });
                match QuoteId::from_memo(&memo) {
                    Ok(id) => scan.memo_ids.push(id),
                    Err(e) => scan.problems.push(format!("output {index}: {e}")),
                }
            }
            _ => scan.problems.push(format!(
                "output {index} does not open under the escrow outgoing viewing key"
            )),
        }
    }
    scan
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
