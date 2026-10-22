//! The escrow spend package and what a co-signer reads from it. Run with
//! `cargo test pczt`; every test sits in `mod pczt` so that filter finds it.
//!
//! The escrow note is synthetic, alone in a one-leaf tree, and owned by a
//! `keygen` escrow key, so the FROST shares in the end-to-end test are real.

mod common;

mod pczt {
    use crate::common::{escrow_note, throwaway_address, throwaway_fvk, ESCROW_VALUE};

    use ironwood_intent_escrow::address::escrow_address;
    use ironwood_intent_escrow::cosign::SigningPackage;
    use ironwood_intent_escrow::frost::{aggregate, keygen, round1, round2, ShareFile};
    use ironwood_intent_escrow::note::{
        escrow_spend_fee, extract, no_action_opens_under_zero_ovk, prove, spend_pczt,
        spend_pczt_with_rng, transparent_bundle_is_empty, NoteInputs, SpendOutput, QUOTE_ID_KEY,
        ZERO_OVK,
    };
    use ironwood_intent_escrow::quote::QuoteId;
    use ironwood_intent_escrow::view::CheckerView;
    use ironwood_intent_escrow::Error;
    use orchard::keys::{OutgoingViewingKey, Scope};
    use pasta_curves::group::ff::PrimeField;
    use pczt::roles::creator::Creator;
    use pczt::roles::io_finalizer::IoFinalizer;
    use pczt::roles::redactor::Redactor;
    use pczt::roles::signer::Signer;
    use pczt::roles::updater::Updater;
    use pczt::roles::verifier::Verifier;
    use rand::rand_core::UnwrapErr;
    use rand::rngs::{StdRng, SysRng};
    use rand::SeedableRng;
    use std::convert::Infallible;
    use zcash_keys::address::UnifiedAddress;
    use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
    use zcash_primitives::transaction::fees::zip317::FeeRule;
    use zcash_protocol::consensus::Network;
    use zcash_protocol::value::Zatoshis;
    use zcash_transparent::address::TransparentAddress;

    const NETWORK: Network = Network::TestNetwork;

    /// A release encrypts its outputs to the escrow's own OVK.
    fn release_ovk(inputs: &NoteInputs) -> OutgoingViewingKey {
        inputs.fvk.to_ovk(Scope::External)
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
            address: throwaway_address(),
            value: Zatoshis::const_from_u64(1_000),
        }];
        let err = spend_pczt(
            NETWORK,
            &inputs,
            &short,
            &QuoteId::random().unwrap(),
            &release_ovk(&inputs),
        )
        .err()
        .unwrap();
        assert!(matches!(err, Error::ValueMismatch { .. }), "{err}");
    }

    #[test]
    fn pczt_checker_view_refuses_a_swapped_quote_id() {
        let dir = tempfile::tempdir().unwrap();
        let inputs = escrow_note(dir.path());
        let outputs = one_output(&inputs, throwaway_address());
        let spend = spend_pczt(
            NETWORK,
            &inputs,
            &outputs,
            &QuoteId::random().unwrap(),
            &release_ovk(&inputs),
        )
        .unwrap();
        let other = QuoteId::random().unwrap();
        let tampered = Updater::new(spend.pczt)
            .update_global_with(|mut g| {
                g.set_proprietary(QUOTE_ID_KEY.into(), other.to_hex().into_bytes())
            })
            .finish();
        let err = CheckerView::new(&tampered, &inputs.fvk, &release_ovk(&inputs)).unwrap_err();
        assert!(matches!(err, Error::QuoteIdMismatch(_)), "{err}");
    }

    #[test]
    fn pczt_checker_view_refuses_a_different_escrow_key() {
        let dir = tempfile::tempdir().unwrap();
        let other_dir = tempfile::tempdir().unwrap();
        let inputs = escrow_note(dir.path());
        let outputs = one_output(&inputs, throwaway_address());
        let spend = spend_pczt(
            NETWORK,
            &inputs,
            &outputs,
            &QuoteId::random().unwrap(),
            &release_ovk(&inputs),
        )
        .unwrap();
        let stranger = keygen(other_dir.path()).unwrap();
        assert!(
            CheckerView::new(&spend.pczt, &stranger, &stranger.to_ovk(Scope::External)).is_err()
        );
    }

    #[test]
    fn pczt_checker_view_refuses_a_value_it_cannot_verify() {
        let dir = tempfile::tempdir().unwrap();
        let inputs = escrow_note(dir.path());
        let outputs = one_output(&inputs, throwaway_address());
        let spend = spend_pczt(
            NETWORK,
            &inputs,
            &outputs,
            &QuoteId::random().unwrap(),
            &release_ovk(&inputs),
        )
        .unwrap();
        let view = CheckerView::new(&spend.pczt, &inputs.fvk, &release_ovk(&inputs)).unwrap();
        let output_action = view.outputs[0].action_index;
        let redacted = Redactor::new(spend.pczt)
            .redact_ironwood_with(|mut bundle| {
                bundle.redact_action(output_action, |mut action| action.clear_output_value())
            })
            .finish();
        let err = CheckerView::new(&redacted, &inputs.fvk, &release_ovk(&inputs)).unwrap_err();
        assert!(err.to_string().contains("value commitment"), "{err}");
    }

    #[test]
    fn pczt_checker_view_refuses_a_transparent_output() {
        let dir = tempfile::tempdir().unwrap();
        let inputs = escrow_note(dir.path());
        let quote_id = QuoteId::random().unwrap();
        let solver = *throwaway_address().orchard().unwrap();
        let assemble = |ironwood_value: u64| {
            let mut builder = Builder::new(
                NETWORK,
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
                .add_ironwood_spend::<Infallible>(
                    inputs.fvk.clone(),
                    inputs.note,
                    inputs.merkle_path.clone(),
                )
                .unwrap();
            builder
                .add_ironwood_output::<Infallible>(
                    Some(release_ovk(&inputs)),
                    solver,
                    Zatoshis::const_from_u64(ironwood_value),
                    quote_id.memo(),
                )
                .unwrap();
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKeyHash([0x22; 20]),
                    Zatoshis::const_from_u64(1_000_000),
                )
                .unwrap();
            builder
        };
        let fee = assemble(0)
            .get_fee(&FeeRule::standard())
            .unwrap()
            .into_u64();
        let built = assemble(ESCROW_VALUE - 1_000_000 - fee)
            .build_for_pczt(UnwrapErr(SysRng), &FeeRule::standard())
            .unwrap();
        let pczt = Creator::build_from_parts(built.pczt_parts).unwrap();
        let pczt = IoFinalizer::new(pczt)
            .finalize_io(UnwrapErr(SysRng))
            .unwrap();
        let pczt = Updater::new(pczt)
            .update_global_with(|mut g| {
                g.set_proprietary(QUOTE_ID_KEY.into(), quote_id.to_hex().into_bytes())
            })
            .finish();
        let err = CheckerView::new(&pczt, &inputs.fvk, &release_ovk(&inputs)).unwrap_err();
        assert!(matches!(err, Error::TransparentOutput), "{err}");
    }

    #[test]
    fn pczt_refund_does_not_open_under_the_escrow_ovk() {
        let dir = tempfile::tempdir().unwrap();
        let inputs = escrow_note(dir.path());
        let refund_fvk = throwaway_fvk();
        let refund_ovk = refund_fvk.to_ovk(Scope::External);
        let outputs = one_output(&inputs, escrow_address(&refund_fvk));
        let spend = spend_pczt(
            NETWORK,
            &inputs,
            &outputs,
            &QuoteId::random().unwrap(),
            &refund_ovk,
        )
        .unwrap();
        // The solver holds escrow.fvk, so the escrow OVK is what it could try.
        assert!(CheckerView::new(&spend.pczt, &inputs.fvk, &release_ovk(&inputs)).is_err());
        let view = CheckerView::new(&spend.pczt, &inputs.fvk, &refund_ovk).unwrap();
        assert_eq!(
            view.outputs[0].address,
            refund_fvk.address_at(0u32, Scope::External)
        );
        assert_eq!(view.fee, spend.fee.into_u64());
    }

    #[test]
    fn pczt_refuses_the_zero_ovk() {
        let dir = tempfile::tempdir().unwrap();
        let inputs = escrow_note(dir.path());
        let outputs = one_output(&inputs, throwaway_address());
        let err = spend_pczt(
            NETWORK,
            &inputs,
            &outputs,
            &QuoteId::random().unwrap(),
            &OutgoingViewingKey::from(ZERO_OVK),
        )
        .err()
        .unwrap();
        assert!(matches!(err, Error::ZeroOutgoingViewingKey), "{err}");
    }

    #[test]
    fn pczt_has_no_refund_field() {
        let dir = tempfile::tempdir().unwrap();
        let inputs = escrow_note(dir.path());
        let quote_id = QuoteId::random().unwrap();
        let outputs = one_output(&inputs, throwaway_address());
        let spend =
            spend_pczt(NETWORK, &inputs, &outputs, &quote_id, &release_ovk(&inputs)).unwrap();
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
        let outputs = one_output(&inputs, throwaway_address());
        let sighash = |seed: u8| {
            let mut rng = StdRng::from_seed([seed; 32]);
            let spend = spend_pczt_with_rng(
                NETWORK,
                &inputs,
                &outputs,
                &quote_id,
                &release_ovk(&inputs),
                &mut rng,
            )
            .unwrap();
            CheckerView::new(&spend.pczt, &inputs.fvk, &release_ovk(&inputs))
                .unwrap()
                .sighash
        };
        assert_eq!(sighash(7), sighash(7));
        assert_ne!(sighash(7), sighash(8));

        // A co-signer that parses the serialized package computes the same
        // sighash as the coordinator.
        let spend =
            spend_pczt(NETWORK, &inputs, &outputs, &quote_id, &release_ovk(&inputs)).unwrap();
        let coordinator =
            CheckerView::new(&spend.pczt, &inputs.fvk, &release_ovk(&inputs)).unwrap();
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
        let solver = throwaway_address();
        let outputs = one_output(&inputs, solver.clone());
        let spend =
            spend_pczt(NETWORK, &inputs, &outputs, &quote_id, &release_ovk(&inputs)).unwrap();
        let view = CheckerView::new(&spend.pczt, &inputs.fvk, &release_ovk(&inputs)).unwrap();

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
        assert_eq!(view.fee, spend.fee.into_u64());
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
        let outputs = one_output(&inputs, throwaway_address());
        let spend =
            spend_pczt(NETWORK, &inputs, &outputs, &quote_id, &release_ovk(&inputs)).unwrap();
        let view = CheckerView::new(&spend.pczt, &inputs.fvk, &release_ovk(&inputs)).unwrap();

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
