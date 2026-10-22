//! One share cannot authorize a spend, and two can. Run with
//! `cargo test one_share_does_not_verify`.
//!
//! The sighash and randomizer are fixed test values, not a Zcash
//! transaction. Sequence 03 supplies a real sighash and `alpha` from a PCZT.

use ironwood_intent_escrow::cosign::{Commitments, SigningPackage, SpendRandomizer};
use ironwood_intent_escrow::frost::{
    aggregate, ak_bytes, keygen, round1, round2, verify_spend_auth, ShareFile,
};
use ironwood_intent_escrow::Error;
use orchard::primitives::redpallas::{SpendAuth, VerificationKey};

const SIGHASH: [u8; 32] = [0x5a; 32];
const PCZT_HASH: [u8; 32] = [0xa5; 32];

/// A fixed, nonzero randomizer: the scalar 7. With zero, `rk` would equal
/// `ak` and the test would prove nothing about re-randomization.
fn randomizer() -> SpendRandomizer {
    let mut bytes = [0u8; 32];
    bytes[0] = 7;
    SpendRandomizer::deserialize(&bytes).unwrap()
}

fn package(commitments: Vec<Commitments>) -> SigningPackage {
    SigningPackage {
        sighash: SIGHASH,
        randomizer: randomizer(),
        commitments,
        pczt_hash: PCZT_HASH,
    }
}

#[test]
fn one_share_does_not_verify() {
    let dir = tempfile::tempdir().unwrap();
    let fvk = keygen(dir.path()).unwrap();
    let payer = ShareFile::read(&dir.path().join("payer.key")).unwrap();
    let solver = ShareFile::read(&dir.path().join("solver.key")).unwrap();

    // 1. A package with only the payer's round 1. frost-core refuses round 2
    //    (round2.rs:130), so a lone holder cannot even produce a share.
    let (nonces, commitments) = round1(&payer);
    let err = round2(&payer, nonces, &package(vec![commitments])).unwrap_err();
    assert!(matches!(err, Error::ThresholdNotMet(_)), "{err}");

    // 2. A two-signer package, but only the payer's share reaches the
    //    coordinator.
    let (payer_nonces, payer_commitments) = round1(&payer);
    let (solver_nonces, solver_commitments) = round1(&solver);
    let both = package(vec![payer_commitments, solver_commitments]);
    let payer_share = round2(&payer, payer_nonces, &both).unwrap();
    let err = aggregate(&both, std::slice::from_ref(&payer_share), &fvk).unwrap_err();
    assert!(matches!(err, Error::ThresholdNotMet(_)), "{err}");
    assert!(err.to_string().starts_with("threshold_not_met"));

    //    The same share twice is still one signer.
    let twice = [payer_share.clone(), payer_share.clone()];
    let err = aggregate(&both, &twice, &fvk).unwrap_err();
    assert!(matches!(err, Error::DuplicateSigner(_)), "{err}");

    // 3. Payer and solver together verify against the randomized ak from
    //    escrow.fvk, checked with orchard's RedPallas as the chain checks it.
    let solver_share = round2(&solver, solver_nonces, &both).unwrap();
    let signature = aggregate(&both, &[payer_share, solver_share], &fvk).unwrap();
    let bytes: [u8; 64] = (&signature).into();
    let ak = ak_bytes(&fvk);
    verify_spend_auth(&ak, &randomizer(), &SIGHASH, &bytes).unwrap();

    //    It does not verify against the unrandomized ak, or for another
    //    sighash, so the randomizer and the message both took effect.
    let unrandomized = VerificationKey::<SpendAuth>::try_from(ak).unwrap();
    assert!(unrandomized.verify(&SIGHASH, &signature).is_err());
    let err = verify_spend_auth(&ak, &randomizer(), &[0u8; 32], &bytes).unwrap_err();
    assert!(matches!(err, Error::InvalidSignature), "{err}");
}

#[test]
fn one_share_does_not_verify_with_shares_from_outside_the_package() {
    let dir = tempfile::tempdir().unwrap();
    let fvk = keygen(dir.path()).unwrap();
    let payer = ShareFile::read(&dir.path().join("payer.key")).unwrap();
    let solver = ShareFile::read(&dir.path().join("solver.key")).unwrap();
    let deadline = ShareFile::read(&dir.path().join("deadline.key")).unwrap();

    // Payer and solver committed, but the deadline holder's share arrives in
    // place of the solver's. It was signed over a different package.
    let (payer_nonces, payer_commitments) = round1(&payer);
    let (_, solver_commitments) = round1(&solver);
    let release = package(vec![payer_commitments.clone(), solver_commitments]);
    let payer_share = round2(&payer, payer_nonces, &release).unwrap();

    let (other_payer_nonces, other_payer_commitments) = round1(&payer);
    let (deadline_nonces, deadline_commitments) = round1(&deadline);
    let refund = package(vec![other_payer_commitments, deadline_commitments]);
    drop(other_payer_nonces);
    let deadline_share = round2(&deadline, deadline_nonces, &refund).unwrap();

    let err = aggregate(&release, &[payer_share, deadline_share], &fvk).unwrap_err();
    assert!(matches!(err, Error::ShareSetMismatch), "{err}");
}
