//! The ZEC transactions: the payer's funding transaction, and the escrow
//! spend package.
//!
//! Both go through the ZIP 374 PCZT roles, so the escrow spend can take a
//! FROST signature the same way the funding takes the payer's own:
//! `zcash_primitives`' builder, then Creator, IO Finalizer, Prover, Signer,
//! and Transaction Extractor. The Signer step lives with whoever holds the
//! key: the payer wallet for the funding, the FROST rounds for the escrow.
//!
//! The Ironwood pool permits cross-address transfers (orchard 0.16.0,
//! `BundleVersion::permits_cross_address_transfers`); only the Orchard pool
//! under protocol version 3 forbids them. So the funding output can pay the
//! escrow address directly.

use std::sync::OnceLock;

use orchard::circuit::{OrchardCircuitVersion, ProvingKey};
use orchard::keys::{FullViewingKey, OutgoingViewingKey, Scope};
use orchard::tree::{Anchor, MerklePath};
use pczt::roles::creator::Creator;
use pczt::roles::io_finalizer::IoFinalizer;
use pczt::roles::prover::Prover;
use pczt::roles::tx_extractor::TransactionExtractor;
use pczt::roles::updater::Updater;
use pczt::Pczt;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use zcash_keys::address::UnifiedAddress;
use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding, PcztParts};
use zcash_primitives::transaction::fees::zip317::FeeRule;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, Network};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;

use crate::address::require_ironwood_only;
use crate::error::Error;
use crate::quote::QuoteId;
use crate::wallet::PayerWallet;

/// The all-zero outgoing viewing key. An output encrypted to it can be read
/// by anyone, which is how indexers read bridge payouts. Never used here.
pub const ZERO_OVK: [u8; 32] = [0u8; 32];

/// What a transaction spends: one Ironwood note, the full viewing key that
/// owns it, and its Merkle path to `anchor`. The funding transaction spends
/// the payer's note; the escrow spend spends the escrow note under
/// `escrow.fvk`.
#[derive(Clone, Debug)]
pub struct NoteInputs {
    /// The payer's funding full viewing key, which owns `note`.
    pub fvk: FullViewingKey,
    /// The note being spent. Must be an Ironwood (V3) note.
    pub note: orchard::Note,
    /// The note's path to `anchor`.
    pub merkle_path: MerklePath,
    /// The Ironwood note commitment tree root the spend proves against.
    pub anchor: Anchor,
    /// The height the transaction targets.
    pub target_height: BlockHeight,
}

/// A funding PCZT, IO-finalized and ready to prove and sign.
pub struct FundPczt {
    /// The package.
    pub pczt: Pczt,
    /// The Ironwood action that spends the payer's note.
    pub spend_index: usize,
    /// The ZIP 317 fee the builder charged.
    pub fee: Zatoshis,
    /// The change returned to the payer's internal address.
    pub change: Zatoshis,
}

/// Builds the funding PCZT: the payer's note in, `amount` to the escrow
/// address and the change to the payer's internal address out, each output
/// encrypted to a real outgoing viewing key. No transparent bundle.
///
/// Refuses an escrow address with any receiver but Orchard, and the
/// all-zero `ovk`.
pub fn fund_pczt(
    network: Network,
    inputs: &NoteInputs,
    escrow: &UnifiedAddress,
    amount: Zatoshis,
    ovk: OutgoingViewingKey,
) -> Result<FundPczt, Error> {
    require_ironwood_only(escrow)?;
    if ovk.as_ref() == &ZERO_OVK {
        return Err(Error::ZeroOutgoingViewingKey);
    }
    let recipient = *escrow
        .orchard()
        .ok_or(Error::NotIronwoodOnly("it has no Orchard receiver"))?;
    let fee_rule = FeeRule::standard();
    // The fee depends on the action count, not on values, so a probe with
    // zero change prices the real transaction.
    let probe = fund_builder(network, inputs, recipient, amount, &ovk, Zatoshis::ZERO)?;
    let fee = probe.get_fee(&fee_rule).map_err(builder_err)?;
    let have = inputs.note.value().inner();
    let need = amount.into_u64().saturating_add(fee.into_u64());
    let change = have
        .checked_sub(need)
        .and_then(|c| Zatoshis::from_u64(c).ok())
        .ok_or(Error::InsufficientFunds { have, need })?;
    let builder = fund_builder(network, inputs, recipient, amount, &ovk, change)?;
    let built = builder
        .build_for_pczt(rng(), &fee_rule)
        .map_err(builder_err)?;
    let spend_index = built
        .ironwood_meta
        .spend_action_index(0)
        .ok_or_else(|| Error::Pczt("the funding bundle has no spend".into()))?;
    let pczt = Creator::build_from_parts(built.pczt_parts)
        .ok_or_else(|| Error::Pczt("the transaction version has no PCZT form".into()))?;
    let pczt = IoFinalizer::new(pczt)
        .finalize_io(rng())
        .map_err(|e| Error::Pczt(format!("io finalizer: {e:?}")))?;
    Ok(FundPczt {
        pczt,
        spend_index,
        fee,
        change,
    })
}

fn fund_builder(
    network: Network,
    inputs: &NoteInputs,
    recipient: orchard::Address,
    amount: Zatoshis,
    ovk: &OutgoingViewingKey,
    change: Zatoshis,
) -> Result<Builder<Network, ()>, Error> {
    let mut builder = Builder::new(
        network,
        inputs.target_height,
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(inputs.anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_ironwood_spend::<std::convert::Infallible>(
            inputs.fvk.clone(),
            inputs.note,
            inputs.merkle_path.clone(),
        )
        .map_err(builder_err)?;
    builder
        .add_ironwood_output::<std::convert::Infallible>(
            Some(ovk.clone()),
            recipient,
            amount,
            MemoBytes::empty(),
        )
        .map_err(builder_err)?;
    builder
        .add_ironwood_output::<std::convert::Infallible>(
            Some(inputs.fvk.to_ovk(Scope::Internal)),
            inputs.fvk.address_at(0u32, Scope::Internal),
            change,
            MemoBytes::empty(),
        )
        .map_err(builder_err)?;
    Ok(builder)
}

/// The proprietary PCZT key under which the escrow spend package carries the
/// quote id in the clear, beside the encrypted memo. `CheckerView` requires
/// the two to agree.
pub const QUOTE_ID_KEY: &str = "ironwood-intent-escrow:quote_id";

/// One output of the escrow spend: the solver's address on a release, or a
/// fresh payer address on a refund.
#[derive(Clone, Debug)]
pub struct SpendOutput {
    /// Must be Ironwood-only.
    pub address: UnifiedAddress,
    /// What the output receives.
    pub value: Zatoshis,
}

/// An escrow spend package, IO-finalized, unproven, and unsigned.
pub struct EscrowSpend {
    /// The ZIP 374 package.
    pub pczt: Pczt,
    /// The Ironwood action that spends the escrow note.
    pub spend_index: usize,
    /// The ZIP 317 fee.
    pub fee: Zatoshis,
}

/// The fee an escrow spend with `outputs` outputs pays, so a caller can set
/// the output value to the note value minus this.
pub fn escrow_spend_fee(
    network: Network,
    inputs: &NoteInputs,
    outputs: usize,
) -> Result<Zatoshis, Error> {
    let placeholder = orchard_receiver_of(inputs);
    let mut builder = escrow_builder(network, inputs)?;
    for _ in 0..outputs {
        builder
            .add_ironwood_output::<std::convert::Infallible>(
                None,
                placeholder,
                Zatoshis::ZERO,
                MemoBytes::empty(),
            )
            .map_err(builder_err)?;
    }
    builder.get_fee(&FeeRule::standard()).map_err(builder_err)
}

/// Builds the escrow spend package: the escrow note in, `outputs` out, each
/// encrypted to `ovk` and carrying the quote id as its memo. There is no
/// field named for a refund address.
///
/// `ovk` decides who can read the outputs back: the escrow OVK for a
/// release, which every holder has; the refund account's OVK for a refund,
/// which the payer and the deadline device have and the solver does not.
/// The all-zero key is refused. The outputs plus the fee must equal the note
/// value exactly.
pub fn spend_pczt(
    network: Network,
    inputs: &NoteInputs,
    outputs: &[SpendOutput],
    quote_id: &QuoteId,
    ovk: &OutgoingViewingKey,
) -> Result<EscrowSpend, Error> {
    spend_pczt_with_rng(network, inputs, outputs, quote_id, ovk, &mut rng())
}

/// [`spend_pczt`] with the caller's RNG, which fixes every randomizer the
/// builder draws: `alpha`, the value commitment trapdoors, and the output
/// notes' seeds.
pub fn spend_pczt_with_rng<R: rand::CryptoRng>(
    network: Network,
    inputs: &NoteInputs,
    outputs: &[SpendOutput],
    quote_id: &QuoteId,
    ovk: &OutgoingViewingKey,
    rng: &mut R,
) -> Result<EscrowSpend, Error> {
    if ovk.as_ref() == &ZERO_OVK {
        return Err(Error::ZeroOutgoingViewingKey);
    }
    let fee = require_balanced(network, inputs, outputs)?;
    let mut builder = escrow_builder(network, inputs)?;
    for output in outputs {
        require_ironwood_only(&output.address)?;
        let recipient = *output
            .address
            .orchard()
            .ok_or(Error::NotIronwoodOnly("it has no Orchard receiver"))?;
        builder
            .add_ironwood_output::<std::convert::Infallible>(
                Some(ovk.clone()),
                recipient,
                output.value,
                quote_id.memo(),
            )
            .map_err(builder_err)?;
    }
    let built = builder
        .build_for_pczt(&mut *rng, &FeeRule::standard())
        .map_err(builder_err)?;
    let spend_index = built
        .ironwood_meta
        .spend_action_index(0)
        .ok_or_else(|| Error::Pczt("the escrow bundle has no spend".into()))?;
    let pczt = finalize_with_quote_id(built.pczt_parts, quote_id, rng)?;
    Ok(EscrowSpend {
        pczt,
        spend_index,
        fee,
    })
}

/// The fee, once the outputs plus the fee equal the escrow note exactly.
fn require_balanced(
    network: Network,
    inputs: &NoteInputs,
    outputs: &[SpendOutput],
) -> Result<Zatoshis, Error> {
    if outputs.is_empty() {
        return Err(Error::Pczt("an escrow spend needs an output".into()));
    }
    let fee = escrow_spend_fee(network, inputs, outputs.len())?;
    let total = outputs
        .iter()
        .try_fold(fee.into_u64(), |sum, o| sum.checked_add(o.value.into_u64()));
    if total != Some(inputs.note.value().inner()) {
        return Err(Error::ValueMismatch {
            note: inputs.note.value().inner(),
            outputs_and_fee: total.unwrap_or(u64::MAX),
        });
    }
    Ok(fee)
}

/// Creator, IO Finalizer, then the Updater writing the quote id into the
/// package's proprietary field.
fn finalize_with_quote_id<R: rand::CryptoRng>(
    parts: PcztParts<Network>,
    quote_id: &QuoteId,
    rng: &mut R,
) -> Result<Pczt, Error> {
    let pczt = Creator::build_from_parts(parts)
        .ok_or_else(|| Error::Pczt("the transaction version has no PCZT form".into()))?;
    let pczt = IoFinalizer::new(pczt)
        .finalize_io(&mut *rng)
        .map_err(|e| Error::Pczt(format!("io finalizer: {e:?}")))?;
    Ok(Updater::new(pczt)
        .update_global_with(|mut global| {
            global.set_proprietary(QUOTE_ID_KEY.to_string(), quote_id.to_hex().into_bytes())
        })
        .finish())
}

fn escrow_builder(network: Network, inputs: &NoteInputs) -> Result<Builder<Network, ()>, Error> {
    let mut builder = Builder::new(
        network,
        inputs.target_height,
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(inputs.anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_ironwood_spend::<std::convert::Infallible>(
            inputs.fvk.clone(),
            inputs.note,
            inputs.merkle_path.clone(),
        )
        .map_err(builder_err)?;
    Ok(builder)
}

fn orchard_receiver_of(inputs: &NoteInputs) -> orchard::Address {
    inputs.fvk.address_at(0u32, Scope::External)
}

/// Builds, proves, and signs the funding transaction from the payer's
/// spendable Ironwood note: `amount` to `escrow`, encrypted to the payer's
/// outgoing viewing key. It does not broadcast.
pub fn fund_escrow(
    escrow: &UnifiedAddress,
    amount: Zatoshis,
    wallet: &mut PayerWallet,
) -> Result<Transaction, Error> {
    let inputs = wallet.funding_input(amount)?;
    let ovk = wallet.outgoing_viewing_key()?;
    let fund = fund_pczt(wallet.network(), &inputs, escrow, amount, ovk)?;
    let pczt = prove(fund.pczt)?;
    let pczt = wallet.sign_funding_spend(pczt, fund.spend_index)?;
    extract(pczt)
}

/// The Ironwood proving key, built once per process (stack.md, Prover).
pub fn proving_key() -> &'static ProvingKey {
    static KEY: OnceLock<ProvingKey> = OnceLock::new();
    KEY.get_or_init(|| ProvingKey::build(OrchardCircuitVersion::PostNu6_3))
}

/// Adds the Ironwood proof to an IO-finalized PCZT.
pub fn prove(pczt: Pczt) -> Result<Pczt, Error> {
    Ok(Prover::new(pczt)
        .create_ironwood_proof(rng(), proving_key())
        .map_err(|e| Error::Pczt(format!("prover: {e:?}")))?
        .finish())
}

/// Extracts the finished transaction from a proved and signed PCZT. The
/// extractor checks the proof and every signature.
pub fn extract(pczt: Pczt) -> Result<Transaction, Error> {
    TransactionExtractor::new(pczt)
        .extract(rng())
        .map_err(|e| Error::Pczt(format!("extractor: {e:?}")))
}

/// The raw bytes of a transaction, as broadcast and as stored in `runs/`.
pub fn tx_bytes(tx: &Transaction) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    tx.write(&mut bytes)
        .map_err(|e| Error::Pczt(format!("serialize: {e}")))?;
    Ok(bytes)
}

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

fn rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

fn builder_err(e: impl std::fmt::Debug) -> Error {
    Error::Pczt(format!("builder: {e:?}"))
}
