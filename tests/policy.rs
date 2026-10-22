//! The policy signers. Run with `cargo test policy`; every test sits in
//! `mod policy` so that filter finds it.
//!
//! The escrow key comes from `keygen`, the escrow note is synthetic, and the
//! NEAR payment is the fixture `attest` reads, so the quote here is the one
//! the fixtures pay.

mod common;

mod policy {
    use ironwood_intent_escrow::attest::Banned;
    use ironwood_intent_escrow::cosign::SigningPackage;
    use ironwood_intent_escrow::frost::{
        aggregate, ak_bytes, round1, round2, verify_spend_auth, ShareFile,
    };
    use ironwood_intent_escrow::note::{
        escrow_spend_fee, spend_pczt, EscrowSpend, NoteInputs, SpendOutput,
    };
    use ironwood_intent_escrow::policy::{
        deadline_sign, payer_release, release_ovk, signing_package, DeadlineSigner, PayerSigner,
    };
    use ironwood_intent_escrow::quote::Quote;
    use ironwood_intent_escrow::view::{verify_package, PackageFacts};
    use ironwood_intent_escrow::Error;
    use orchard::keys::FullViewingKey;
    use tempfile::TempDir;
    use zcash_keys::address::UnifiedAddress;
    use zcash_protocol::consensus::Network;
    use zcash_protocol::value::Zatoshis;

    use crate::common::{
        escrow_note, fixture_pointer, fixture_quote, throwaway_address, throwaway_fvk, FixtureRpc,
        ESCROW_VALUE,
    };

    const NETWORK: Network = Network::TestNetwork;

    struct Escrow {
        dir: TempDir,
        inputs: NoteInputs,
        solver: UnifiedAddress,
        refund_fvk: FullViewingKey,
    }

    fn escrow() -> Escrow {
        let dir = tempfile::tempdir().unwrap();
        let inputs = escrow_note(dir.path());
        Escrow {
            dir,
            inputs,
            solver: throwaway_address(),
            refund_fvk: throwaway_fvk(),
        }
    }

    fn share(e: &Escrow, name: &str) -> ShareFile {
        ShareFile::read(&e.dir.path().join(name)).unwrap()
    }

    fn payer(e: &Escrow) -> PayerSigner {
        PayerSigner::new(share(e, "payer.key"), e.inputs.fvk.clone(), &e.solver).unwrap()
    }

    fn deadline(e: &Escrow) -> DeadlineSigner {
        DeadlineSigner::new(
            share(e, "deadline.key"),
            e.inputs.fvk.clone(),
            e.refund_fvk.clone(),
            &e.solver,
        )
        .unwrap()
    }

    /// The whole escrow note, less the fee, to `to`, under the escrow OVK.
    fn release_to(e: &Escrow, to: &UnifiedAddress, quote: &Quote) -> (EscrowSpend, PackageFacts) {
        let fee = escrow_spend_fee(NETWORK, &e.inputs, 1).unwrap().into_u64();
        let outputs = [SpendOutput {
            address: to.clone(),
            value: Zatoshis::const_from_u64(ESCROW_VALUE - fee),
        }];
        let spend = spend_pczt(
            NETWORK,
            &e.inputs,
            &outputs,
            &quote.id,
            &release_ovk(&e.inputs.fvk),
        )
        .unwrap();
        let facts = verify_package(&spend.pczt, &e.inputs.fvk).unwrap();
        (spend, facts)
    }

    fn banned() -> Banned {
        Banned::new().zatoshis(ESCROW_VALUE)
    }

    #[test]
    fn policy_refuses_a_share_of_another_role() {
        let e = escrow();
        let err = PayerSigner::new(share(&e, "solver.key"), e.inputs.fvk.clone(), &e.solver)
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
}
