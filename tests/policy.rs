//! The release side of the policy signers. Run with `cargo test policy`;
//! every test sits in `mod policy` so that filter finds it.
//!
//! The escrow key comes from `keygen`, the escrow note is synthetic, and the
//! NEAR payment is the fixture `attest` reads, so the quote here is the one
//! the fixtures pay. The refund side is in `tests/policy_refund.rs`.

mod common;

mod policy {
    use ironwood_intent_escrow::cosign::SigningPackage;
    use ironwood_intent_escrow::frost::{aggregate, ak_bytes, round1, round2, verify_spend_auth};
    use ironwood_intent_escrow::policy::{
        build_refund, deadline_sign, payer_release, release_ovk, signing_package, solver_release,
        DeadlineSigner, PayerSigner, MAX_ESCROW_FEE,
    };
    use ironwood_intent_escrow::view::verify_package;
    use ironwood_intent_escrow::Error;
    use zcash_protocol::value::Zatoshis;

    use crate::common::policy::*;
    use crate::common::{
        fixture_pointer, fixture_quote, throwaway_address, FixtureRpc, ESCROW_VALUE,
    };

    #[test]
    fn policy_refuses_a_share_of_another_role() {
        let e = escrow();
        let err = PayerSigner::new(
            share(&e, "solver.key"),
            e.inputs.fvk.clone(),
            e.refund_fvk.clone(),
            &e.solver,
        )
        .err()
        .unwrap();
        assert!(matches!(err, Error::WrongRole { .. }), "{err}");
        let err = DeadlineSigner::new(
            share(&e, "payer.key"),
            e.inputs.fvk.clone(),
            e.refund_fvk.clone(),
            &e.solver,
        )
        .err()
        .unwrap();
        assert!(matches!(err, Error::WrongRole { .. }), "{err}");
    }

    #[test]
    fn deadline_refuses_solver_output() {
        let e = escrow();
        let quote = fixture_quote();
        let (spend, facts) = release_to(&e, &e.solver, &quote);
        let (deadline_nonces, deadline_commitments) = round1(&share(&e, "deadline.key"));
        let (_, payer_commitments) = round1(&share(&e, "payer.key"));
        let package = signing_package(&facts, vec![payer_commitments, deadline_commitments]);
        let err = deadline_sign(
            &deadline(&e),
            &quote,
            &spend.pczt,
            deadline_nonces,
            &package,
            u64::MAX,
            &no_claims_guard(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::RefusedRelease), "{err}");
    }

    #[test]
    fn payer_release_checks_package() {
        let e = escrow();
        let quote = fixture_quote();
        let (spend, facts) = release_to(&e, &e.solver, &quote);
        let (nonces, payer_commitments) = round1(&share(&e, "payer.key"));
        let (_, solver_commitments) = round1(&share(&e, "solver.key"));
        let honest = signing_package(&facts, vec![payer_commitments, solver_commitments]);
        let rpc = FixtureRpc::new("near_ok.json");

        let wrong_hash = SigningPackage {
            pczt_hash: [0u8; 32],
            ..honest.clone()
        };
        let err = payer_release(
            &payer(&e),
            &quote,
            &spend.pczt,
            &fixture_pointer(),
            &banned(),
            &rpc,
            nonces,
            &wrong_hash,
        )
        .unwrap_err();
        assert!(matches!(err, Error::PackageMismatch("pczt_hash")), "{err}");
        assert_eq!(rpc.calls.get(), 0, "the RPC ran before the package check");

        let (nonces, _) = round1(&share(&e, "payer.key"));
        let mut alpha = [0u8; 32];
        alpha[0] = 5;
        let wrong_randomizer = SigningPackage {
            randomizer: ironwood_intent_escrow::cosign::SpendRandomizer::deserialize(&alpha)
                .unwrap(),
            ..honest
        };
        let err = payer_release(
            &payer(&e),
            &quote,
            &spend.pczt,
            &fixture_pointer(),
            &banned(),
            &rpc,
            nonces,
            &wrong_randomizer,
        )
        .unwrap_err();
        assert!(matches!(err, Error::PackageMismatch("randomizer")), "{err}");
        assert_eq!(rpc.calls.get(), 0);
    }

    #[test]
    fn payer_release_requires_attestation() {
        let e = escrow();
        let quote = fixture_quote();
        let (spend, facts) = release_to(&e, &e.solver, &quote);
        let (nonces, payer_commitments) = round1(&share(&e, "payer.key"));
        let (_, solver_commitments) = round1(&share(&e, "solver.key"));
        let package = signing_package(&facts, vec![payer_commitments, solver_commitments]);
        let rpc = FixtureRpc::new("near_banned.json");
        let result = payer_release(
            &payer(&e),
            &quote,
            &spend.pczt,
            &fixture_pointer(),
            &banned(),
            &rpc,
            nonces,
            &package,
        );
        assert!(
            matches!(result, Err(Error::BannedField(_))),
            "{:?}",
            result.err()
        );
        assert_eq!(rpc.calls.get(), 1);
    }

    #[test]
    fn payer_release_refuses_a_package_that_pays_someone_else() {
        let e = escrow();
        let quote = fixture_quote();
        let (spend, facts) = release_to(&e, &throwaway_address(), &quote);
        let (nonces, payer_commitments) = round1(&share(&e, "payer.key"));
        let (_, solver_commitments) = round1(&share(&e, "solver.key"));
        let package = signing_package(&facts, vec![payer_commitments, solver_commitments]);
        let rpc = FixtureRpc::new("near_ok.json");
        let err = payer_release(
            &payer(&e),
            &quote,
            &spend.pczt,
            &fixture_pointer(),
            &banned(),
            &rpc,
            nonces,
            &package,
        )
        .unwrap_err();
        assert!(matches!(err, Error::NotARelease(_)), "{err}");
    }

    #[test]
    fn payer_release_signs_after_attestation() {
        let e = escrow();
        let quote = fixture_quote();
        let (spend, facts) = release_to(&e, &e.solver, &quote);
        let solver_share_file = share(&e, "solver.key");
        let (payer_nonces, payer_commitments) = round1(&share(&e, "payer.key"));
        let (solver_nonces, solver_commitments) = round1(&solver_share_file);
        let package = signing_package(&facts, vec![payer_commitments, solver_commitments]);
        let rpc = FixtureRpc::new("near_ok.json");
        let (payer_share, attestation) = payer_release(
            &payer(&e),
            &quote,
            &spend.pczt,
            &fixture_pointer(),
            &banned(),
            &rpc,
            payer_nonces,
            &package,
        )
        .unwrap();
        assert_eq!(attestation.tx_hash, fixture_pointer().hash);
        let solver_share = round2(&solver_share_file, solver_nonces, &package).unwrap();
        let signature = aggregate(&package, &[payer_share, solver_share], &e.inputs.fvk).unwrap();
        let bytes: [u8; 64] = (&signature).into();
        verify_spend_auth(
            &ak_bytes(&e.inputs.fvk),
            &facts.randomizer,
            &facts.sighash,
            &bytes,
        )
        .unwrap();
    }

    #[test]
    fn solver_refuses_a_refund_shaped_package() {
        let mut e = escrow();
        let quote = quote_expiring(EXPIRY);
        // The payer, as coordinator, builds a refund to itself and asks the
        // solver to co-sign it in place of the release.
        let refund = build_refund(&quote, &e.inputs, &mut e.wallet, EXPIRY).unwrap();
        let facts = verify_package(&refund.pczt, &e.inputs.fvk).unwrap();
        let (nonces, solver_commitments) = round1(&share(&e, "solver.key"));
        let (_, payer_commitments) = round1(&share(&e, "payer.key"));
        let package = signing_package(&facts, vec![payer_commitments, solver_commitments]);
        let err = solver_release(&solver(&e), &quote, &refund.pczt, nonces, &package).unwrap_err();
        assert!(matches!(err, Error::NotARelease(_)), "{err}");

        // A release under the escrow key that pays someone else is refused too.
        let (other, facts) = release_to(&e, &throwaway_address(), &quote);
        let (nonces, solver_commitments) = round1(&share(&e, "solver.key"));
        let (_, payer_commitments) = round1(&share(&e, "payer.key"));
        let package = signing_package(&facts, vec![payer_commitments, solver_commitments]);
        let err = solver_release(&solver(&e), &quote, &other.pczt, nonces, &package).unwrap_err();
        assert!(matches!(err, Error::NotARelease(_)), "{err}");
    }

    #[test]
    fn solver_and_payer_sign_the_release() {
        let e = escrow();
        let quote = fixture_quote();
        let (spend, facts) = release_to(&e, &e.solver, &quote);
        let (payer_nonces, payer_commitments) = round1(&share(&e, "payer.key"));
        let (solver_nonces, solver_commitments) = round1(&share(&e, "solver.key"));
        let package = signing_package(&facts, vec![payer_commitments, solver_commitments]);
        let rpc = FixtureRpc::new("near_ok.json");
        let (payer_share, _) = payer_release(
            &payer(&e),
            &quote,
            &spend.pczt,
            &fixture_pointer(),
            &banned(),
            &rpc,
            payer_nonces,
            &package,
        )
        .unwrap();
        let solver_share =
            solver_release(&solver(&e), &quote, &spend.pczt, solver_nonces, &package).unwrap();
        let signature = aggregate(&package, &[payer_share, solver_share], &e.inputs.fvk).unwrap();
        let bytes: [u8; 64] = (&signature).into();
        verify_spend_auth(
            &ak_bytes(&e.inputs.fvk),
            &facts.randomizer,
            &facts.sighash,
            &bytes,
        )
        .unwrap();
    }

    #[test]
    fn policy_refuses_a_fee_above_the_cap() {
        use pczt::roles::creator::Creator;
        use pczt::roles::io_finalizer::IoFinalizer;
        use pczt::roles::updater::Updater;
        use rand::rand_core::UnwrapErr;
        use rand::rngs::SysRng;
        use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
        use zcash_primitives::transaction::fees::transparent::InputSize;
        use zcash_primitives::transaction::fees::FeeRule;
        use zcash_protocol::consensus::{BlockHeight, Parameters};

        /// A fee rule that charges a flat, oversized fee.
        struct HighFee(Zatoshis);
        impl FeeRule for HighFee {
            type Error = std::convert::Infallible;
            fn fee_required<P: Parameters>(
                &self,
                _: &P,
                _: BlockHeight,
                _: impl IntoIterator<Item = InputSize>,
                _: impl IntoIterator<Item = usize>,
                _: usize,
                _: usize,
                _: usize,
                _: usize,
            ) -> Result<Zatoshis, Self::Error> {
                Ok(self.0)
            }
        }

        let e = escrow();
        let quote = fixture_quote();
        let fee = 1_000_000;
        let mut builder = Builder::new(
            NETWORK,
            e.inputs.target_height,
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: Some(e.inputs.anchor),
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        builder
            .add_ironwood_spend::<std::convert::Infallible>(
                e.inputs.fvk.clone(),
                e.inputs.note,
                e.inputs.merkle_path.clone(),
            )
            .unwrap();
        builder
            .add_ironwood_output::<std::convert::Infallible>(
                Some(release_ovk(&e.inputs.fvk)),
                *e.solver.orchard().unwrap(),
                Zatoshis::const_from_u64(ESCROW_VALUE - fee),
                quote.id.memo(),
            )
            .unwrap();
        let built = builder
            .build_for_pczt(UnwrapErr(SysRng), &HighFee(Zatoshis::const_from_u64(fee)))
            .unwrap();
        let pczt = Creator::build_from_parts(built.pczt_parts).unwrap();
        let pczt = IoFinalizer::new(pczt)
            .finalize_io(UnwrapErr(SysRng))
            .unwrap();
        let pczt = Updater::new(pczt)
            .update_global_with(|mut g| {
                g.set_proprietary(
                    ironwood_intent_escrow::note::QUOTE_ID_KEY.into(),
                    quote.id.to_hex().into_bytes(),
                )
            })
            .finish();
        let facts = verify_package(&pczt, &e.inputs.fvk).unwrap();
        assert_eq!(facts.fee, fee);
        assert!(fee > MAX_ESCROW_FEE);
        let (nonces, solver_commitments) = round1(&share(&e, "solver.key"));
        let (_, payer_commitments) = round1(&share(&e, "payer.key"));
        let package = signing_package(&facts, vec![payer_commitments, solver_commitments]);
        let err = solver_release(&solver(&e), &quote, &pczt, nonces, &package).unwrap_err();
        assert!(matches!(err, Error::FeeTooHigh { .. }), "{err}");
    }
}
