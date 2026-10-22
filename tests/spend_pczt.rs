//! The escrow spend package and what a co-signer reads from it. Run with
//! `cargo test pczt`; every test sits in `mod pczt` so that filter finds it.
//!
//! The escrow note is synthetic, alone in a one-leaf tree, and owned by a
//! `keygen` escrow key, so the FROST shares in the end-to-end test are real.

mod pczt {
    use std::path::Path;

    use incrementalmerkletree::{Hashable, Level};
    use ironwood_intent_escrow::address::escrow_address;
    use ironwood_intent_escrow::cosign::SigningPackage;
    use ironwood_intent_escrow::frost::{aggregate, keygen, round1, round2, ShareFile};
    use ironwood_intent_escrow::note::{
        escrow_spend_fee, extract, no_action_opens_under_zero_ovk, prove, spend_pczt,
        spend_pczt_with_rng, transparent_bundle_is_empty, NoteInputs, SpendOutput, QUOTE_ID_KEY,
    };
    use ironwood_intent_escrow::quote::QuoteId;
    use ironwood_intent_escrow::view::CheckerView;
    use ironwood_intent_escrow::Error;
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};
    use orchard::note::{NoteVersion, RandomSeed, Rho};
    use orchard::tree::{MerkleHashOrchard, MerklePath};
    use orchard::value::NoteValue;
    use pasta_curves::group::ff::PrimeField;
    use pczt::roles::signer::Signer;
    use pczt::roles::updater::Updater;
    use pczt::roles::verifier::Verifier;
    use rand::rngs::{StdRng, SysRng};
    use rand::{SeedableRng, TryRng};
    use zcash_keys::address::UnifiedAddress;
    use zcash_protocol::consensus::{BlockHeight, Network};
    use zcash_protocol::value::Zatoshis;

    const ESCROW_VALUE: u64 = 3_990_000;
    const NETWORK: Network = Network::TestNetwork;

    fn random_bytes() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        SysRng.try_fill_bytes(&mut bytes).unwrap();
        bytes
    }

    /// An escrow key in `dir`, and the escrow note it owns.
    fn escrow_note(dir: &Path) -> NoteInputs {
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

    /// A throwaway Ironwood-only address standing in for the solver.
    fn solver_address() -> UnifiedAddress {
        let sk = loop {
            if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(random_bytes())) {
                break sk;
            }
        };
        escrow_address(&FullViewingKey::from(&sk))
    }

    /// The whole note, less the fee, to one output.
    fn one_output(inputs: &NoteInputs, address: UnifiedAddress) -> Vec<SpendOutput> {
        let fee = escrow_spend_fee(NETWORK, inputs, 1).unwrap().into_u64();
        vec![SpendOutput {
            address,
            value: Zatoshis::const_from_u64(ESCROW_VALUE - fee),
        }]
    }

    #[test]
    fn pczt_refuses_outputs_that_do_not_spend_the_whole_note() {
        let dir = tempfile::tempdir().unwrap();
        let inputs = escrow_note(dir.path());
        let short = vec![SpendOutput {
            address: solver_address(),
            value: Zatoshis::const_from_u64(1_000),
        }];
        let err = spend_pczt(NETWORK, &inputs, &short, &QuoteId::random().unwrap())
            .err()
            .unwrap();
        assert!(matches!(err, Error::ValueMismatch { .. }), "{err}");
    }

    #[test]
    fn pczt_checker_view_refuses_a_swapped_quote_id() {
        let dir = tempfile::tempdir().unwrap();
        let inputs = escrow_note(dir.path());
        let outputs = one_output(&inputs, solver_address());
        let spend = spend_pczt(NETWORK, &inputs, &outputs, &QuoteId::random().unwrap()).unwrap();
        let other = QuoteId::random().unwrap();
        let tampered = Updater::new(spend.pczt)
            .update_global_with(|mut g| {
                g.set_proprietary(QUOTE_ID_KEY.into(), other.to_hex().into_bytes())
            })
            .finish();
        let err = CheckerView::new(&tampered, &inputs.fvk).unwrap_err();
        assert!(matches!(err, Error::QuoteIdMismatch(_)), "{err}");
    }

    #[test]
    fn pczt_checker_view_refuses_a_different_escrow_key() {
        let dir = tempfile::tempdir().unwrap();
        let other_dir = tempfile::tempdir().unwrap();
        let inputs = escrow_note(dir.path());
        let outputs = one_output(&inputs, solver_address());
        let spend = spend_pczt(NETWORK, &inputs, &outputs, &QuoteId::random().unwrap()).unwrap();
        let stranger = keygen(other_dir.path()).unwrap();
        assert!(CheckerView::new(&spend.pczt, &stranger).is_err());
    }

    #[test]
    fn pczt_has_no_refund_field() {
        let dir = tempfile::tempdir().unwrap();
        let inputs = escrow_note(dir.path());
        let quote_id = QuoteId::random().unwrap();
        let outputs = one_output(&inputs, solver_address());
        let spend = spend_pczt(NETWORK, &inputs, &outputs, &quote_id).unwrap();
        let bytes = spend.pczt.serialize().unwrap();
        let contains = |needle: &[u8]| {
            bytes
                .windows(needle.len())
                .any(|w| w.eq_ignore_ascii_case(needle))
        };
        for banned in ["refund", "refund_to", "refund_address", "refundTo"] {
            assert!(
                !contains(banned.as_bytes()),
                "the package contains {banned}"
            );
        }
        assert!(contains(QUOTE_ID_KEY.as_bytes()));
        assert!(contains(quote_id.to_hex().as_bytes()));
    }

    #[test]
    fn pczt_sighash_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let inputs = escrow_note(dir.path());
        let quote_id = QuoteId::random().unwrap();
        let outputs = one_output(&inputs, solver_address());
        let sighash = |seed: u8| {
            let mut rng = StdRng::from_seed([seed; 32]);
            let spend =
                spend_pczt_with_rng(NETWORK, &inputs, &outputs, &quote_id, &mut rng).unwrap();
            CheckerView::new(&spend.pczt, &inputs.fvk).unwrap().sighash
        };
        assert_eq!(sighash(7), sighash(7));
        assert_ne!(sighash(7), sighash(8));

        // A co-signer that parses the serialized package computes the same
        // sighash as the coordinator.
        let spend = spend_pczt(NETWORK, &inputs, &outputs, &quote_id).unwrap();
        let coordinator = CheckerView::new(&spend.pczt, &inputs.fvk).unwrap();
        let parsed = pczt::Pczt::parse(&spend.pczt.serialize().unwrap()).unwrap();
        assert_eq!(
            Signer::new(parsed).unwrap().shielded_sighash(),
            coordinator.sighash
        );
    }

    #[test]
    fn checker_view_has_randomizer() {
        let dir = tempfile::tempdir().unwrap();
        let inputs = escrow_note(dir.path());
        let quote_id = QuoteId::random().unwrap();
        let solver = solver_address();
        let outputs = one_output(&inputs, solver.clone());
        let spend = spend_pczt(NETWORK, &inputs, &outputs, &quote_id).unwrap();
        let view = CheckerView::new(&spend.pczt, &inputs.fvk).unwrap();

        let mut alpha = None;
        Verifier::new(spend.pczt.clone())
            .with_ironwood::<(), _>(|bundle| {
                alpha = bundle.actions()[spend.spend_index]
                    .spend()
                    .alpha()
                    .map(|a| a.to_repr());
                Ok(())
            })
            .unwrap();
        assert_eq!(view.randomizer.serialize(), alpha.unwrap().to_vec());
        assert_eq!(view.spend_index, spend.spend_index);
        assert_eq!(view.spent_value, ESCROW_VALUE);
        assert_eq!(view.quote_id, quote_id);
        assert_eq!(view.outputs.len(), 1);
        assert_eq!(view.outputs[0].address, *solver.orchard().unwrap());
        assert_eq!(view.outputs[0].value, outputs[0].value.into_u64());
        let cmx: [u8; 32] =
            orchard::note::ExtractedNoteCommitment::from(inputs.note.commitment()).to_bytes();
        assert_eq!(view.spent_cmx, cmx);
    }

    #[test]
    fn pczt_frost_signed_spend_extracts() {
        let dir = tempfile::tempdir().unwrap();
        let inputs = escrow_note(dir.path());
        let quote_id = QuoteId::random().unwrap();
        let outputs = one_output(&inputs, solver_address());
        let spend = spend_pczt(NETWORK, &inputs, &outputs, &quote_id).unwrap();
        let view = CheckerView::new(&spend.pczt, &inputs.fvk).unwrap();

        let payer = ShareFile::read(&dir.path().join("payer.key")).unwrap();
        let solver = ShareFile::read(&dir.path().join("solver.key")).unwrap();
        let (payer_nonces, payer_commitments) = round1(&payer);
        let (solver_nonces, solver_commitments) = round1(&solver);
        let package = SigningPackage {
            sighash: view.sighash,
            randomizer: view.randomizer,
            commitments: vec![payer_commitments, solver_commitments],
            pczt_hash: view.pczt_hash,
        };
        let shares = [
            round2(&payer, payer_nonces, &package).unwrap(),
            round2(&solver, solver_nonces, &package).unwrap(),
        ];
        let signature = aggregate(&package, &shares, &inputs.fvk).unwrap();

        let mut signer = Signer::new(prove(spend.pczt).unwrap()).unwrap();
        signer
            .apply_ironwood_signature(view.spend_index, signature)
            .unwrap();
        let tx = extract(signer.finish()).unwrap();
        assert!(transparent_bundle_is_empty(&tx));
        assert!(no_action_opens_under_zero_ovk(&tx));
        println!(
            "escrow spend: {} Ironwood actions, fee {}",
            tx.ironwood_bundle().unwrap().actions().len(),
            spend.fee.into_u64()
        );
    }
}
