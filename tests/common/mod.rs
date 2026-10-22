//! Shared fixtures for the funding and checker tests: a synthetic payer, an
//! Ironwood note alone in a one-leaf tree, and funding transactions built
//! with or without the library's guards.

#![allow(dead_code)] // each test binary uses a different subset

use incrementalmerkletree::{Hashable, Level};
use ironwood_intent_escrow::address::escrow_address;
use ironwood_intent_escrow::frost::keygen;
use ironwood_intent_escrow::note::{extract, prove, NoteInputs};
use orchard::keys::{FullViewingKey, OutgoingViewingKey, Scope, SpendAuthorizingKey, SpendingKey};
use orchard::note::{NoteVersion, RandomSeed, Rho};
use orchard::tree::{MerkleHashOrchard, MerklePath};
use orchard::value::NoteValue;
use pczt::roles::creator::Creator;
use pczt::roles::io_finalizer::IoFinalizer;
use pczt::roles::signer::Signer;
use pczt::Pczt;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use rand::TryRng;
use zcash_keys::address::UnifiedAddress;
use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
use zcash_primitives::transaction::fees::zip317::FeeRule;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, Network};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::TransparentAddress;

pub const NOTE_VALUE: u64 = 12_500_000;
pub const AMOUNT: u64 = 4_000_000;
pub const TARGET: u32 = 4_530_500;

pub struct Payer {
    pub sk: SpendingKey,
    pub fvk: FullViewingKey,
}

pub fn random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    SysRng.try_fill_bytes(&mut bytes).unwrap();
    bytes
}

pub fn payer() -> Payer {
    let sk = loop {
        if let Some(sk) = Option::from(SpendingKey::from_bytes(random_bytes())) {
            break sk;
        }
    };
    let fvk = FullViewingKey::from(&sk);
    Payer { sk, fvk }
}

/// One V3 note to the payer, alone in a one-leaf tree at position 0.
pub fn inputs(payer: &Payer) -> NoteInputs {
    let rho = loop {
        if let Some(rho) = Option::from(Rho::from_bytes(&random_bytes())) {
            break rho;
        }
    };
    let rseed = loop {
        if let Some(rseed) = Option::from(RandomSeed::from_bytes(random_bytes(), &rho)) {
            break rseed;
        }
    };
    let note = orchard::Note::from_parts(
        payer.fvk.address_at(0u32, Scope::External),
        NoteValue::from_raw(NOTE_VALUE),
        rho,
        rseed,
        NoteVersion::V3,
    )
    .unwrap();
    let auth_path: [MerkleHashOrchard; 32] =
        std::array::from_fn(|level| MerkleHashOrchard::empty_root(Level::from(level as u8)));
    let merkle_path = MerklePath::from_parts(0, auth_path);
    let anchor = merkle_path.root(note.commitment().into());
    NoteInputs {
        fvk: payer.fvk.clone(),
        note,
        merkle_path,
        anchor,
        target_height: BlockHeight::from_u32(TARGET),
    }
}

pub fn escrow() -> UnifiedAddress {
    let dir = tempfile::tempdir().unwrap();
    escrow_address(&keygen(dir.path()).unwrap())
}

pub fn sign_prove_extract(payer: &Payer, pczt: Pczt, spend_index: usize) -> Transaction {
    let pczt = prove(pczt).unwrap();
    let mut signer = Signer::new(pczt).unwrap();
    signer
        .sign_ironwood(
            UnwrapErr(SysRng),
            spend_index,
            &SpendAuthorizingKey::from(&payer.sk),
        )
        .unwrap();
    extract(signer.finish()).unwrap()
}

/// A funding transaction built outside the library's guards, for the two
/// negative fixtures: an escrow output to `escrow_ovk`, and optionally a
/// transparent output.
pub fn fixture(payer: &Payer, escrow_ovk: [u8; 32], transparent: bool) -> Transaction {
    let inputs = inputs(payer);
    let escrow = *escrow().orchard().unwrap();
    let transparent_value = if transparent { 1_000_000 } else { 0 };
    let assemble = |change: u64| {
        let mut builder = Builder::new(
            Network::TestNetwork,
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
                payer.fvk.clone(),
                inputs.note,
                inputs.merkle_path.clone(),
            )
            .unwrap();
        builder
            .add_ironwood_output::<std::convert::Infallible>(
                Some(OutgoingViewingKey::from(escrow_ovk)),
                escrow,
                Zatoshis::const_from_u64(AMOUNT),
                MemoBytes::empty(),
            )
            .unwrap();
        if transparent {
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKeyHash([0x11; 20]),
                    Zatoshis::const_from_u64(transparent_value),
                )
                .unwrap();
        }
        builder
            .add_ironwood_output::<std::convert::Infallible>(
                Some(payer.fvk.to_ovk(Scope::Internal)),
                payer.fvk.address_at(0u32, Scope::Internal),
                Zatoshis::const_from_u64(change),
                MemoBytes::empty(),
            )
            .unwrap();
        builder
    };
    let fee = assemble(0)
        .get_fee(&FeeRule::standard())
        .unwrap()
        .into_u64();
    let built = assemble(NOTE_VALUE - AMOUNT - transparent_value - fee)
        .build_for_pczt(UnwrapErr(SysRng), &FeeRule::standard())
        .unwrap();
    let spend_index = built.ironwood_meta.spend_action_index(0).unwrap();
    let pczt = Creator::build_from_parts(built.pczt_parts).unwrap();
    let pczt = IoFinalizer::new(pczt)
        .finalize_io(UnwrapErr(SysRng))
        .unwrap();
    sign_prove_extract(payer, pczt, spend_index)
}

/// The escrow note's value in the escrow-spend and policy tests.
pub const ESCROW_VALUE: u64 = 3_990_000;

/// A `keygen` escrow key in `dir`, and a synthetic escrow note it owns,
/// alone in a one-leaf tree.
pub fn escrow_note(dir: &std::path::Path) -> NoteInputs {
    let fvk = keygen(dir).unwrap();
    let rho = loop {
        if let Some(rho) = Option::from(Rho::from_bytes(&random_bytes())) {
            break rho;
        }
    };
    let rseed = loop {
        if let Some(r) = Option::from(RandomSeed::from_bytes(random_bytes(), &rho)) {
            break r;
        }
    };
    let note = orchard::Note::from_parts(
        fvk.address_at(0u32, Scope::External),
        NoteValue::from_raw(ESCROW_VALUE),
        rho,
        rseed,
        NoteVersion::V3,
    )
    .unwrap();
    let auth_path: [MerkleHashOrchard; 32] =
        std::array::from_fn(|l| MerkleHashOrchard::empty_root(Level::from(l as u8)));
    let merkle_path = MerklePath::from_parts(0, auth_path);
    let anchor = merkle_path.root(note.commitment().into());
    NoteInputs {
        fvk,
        note,
        merkle_path,
        anchor,
        target_height: BlockHeight::from_u32(4_530_600),
    }
}

/// A throwaway full viewing key, for a stand-in solver or refund account.
pub fn throwaway_fvk() -> FullViewingKey {
    FullViewingKey::from(&payer().sk)
}

/// A throwaway Ironwood-only address.
pub fn throwaway_address() -> UnifiedAddress {
    escrow_address(&throwaway_fvk())
}

/// A NEAR RPC that returns a fixture file and counts its calls.
pub struct FixtureRpc {
    pub payload: Vec<u8>,
    pub calls: std::cell::Cell<usize>,
}

impl FixtureRpc {
    pub fn new(name: &str) -> Self {
        FixtureRpc {
            payload: fixture_bytes(name),
            calls: std::cell::Cell::new(0),
        }
    }
}

impl ironwood_intent_escrow::attest::NearRpc for FixtureRpc {
    fn url(&self) -> &str {
        "fixture://near"
    }
    fn tx(&self, _hash: &str, _sender: &str) -> Result<Vec<u8>, ironwood_intent_escrow::Error> {
        self.calls.set(self.calls.get() + 1);
        Ok(self.payload.clone())
    }
}

pub fn fixture_bytes(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(path).unwrap()
}

/// The quote the NEAR fixtures pay.
pub fn fixture_quote() -> ironwood_intent_escrow::quote::Quote {
    use ironwood_intent_escrow::quote::{Quote, QuoteId};
    Quote {
        id: QuoteId::from_hex("3f9a1c7e5b2d4086a1f3c5e7092b4d6f8a0c2e4f6183a5c7e9fb1d3f5a7c9e0b")
            .unwrap(),
        destination_account: "payer-ironwood.testnet".into(),
        asset: "wrap.testnet".into(),
        amount: 250_000_000_000_000_000_000_000,
        expiry_unix: 1_792_800_000,
    }
}

/// The pointer the NEAR fixtures answer.
pub fn fixture_pointer() -> ironwood_intent_escrow::attest::NearTxPointer {
    ironwood_intent_escrow::attest::NearTxPointer {
        hash: "4wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vigw".into(),
        sender: "solver-ironwood.testnet".into(),
    }
}
