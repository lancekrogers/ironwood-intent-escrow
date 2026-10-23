//! The refund side of the policy signers. Run with `cargo test policy`.
//!
//! The refund key and addresses are an offline payer wallet's, so the
//! deadline device recognises outputs with the real refund key. The
//! fill-claim tests use the recorded fill quote and NEAR payment from
//! `runs/` through stub RPCs and an in-memory claim store; none of them
//! opens a socket.

mod common;

mod policy {
    use ironwood_intent_escrow::frost::{aggregate, ak_bytes, round1, verify_spend_auth};
    use ironwood_intent_escrow::note::{escrow_spend_fee, spend_pczt, SpendOutput};
    use ironwood_intent_escrow::policy::{
        build_refund, deadline_sign, payer_refund, refund_ovk, signing_package,
    };
    use ironwood_intent_escrow::view::verify_package;
    use ironwood_intent_escrow::Error;
    use zcash_keys::address::UnifiedAddress;
    use zcash_protocol::value::Zatoshis;

    use crate::common::policy::*;
    use crate::common::{
        runs_file, throwaway_address, FailingRpc, MemClaims, PanickingRpc, StoredRpc, ESCROW_VALUE,
    };
    use ironwood_intent_escrow::attest::{check_payload, NearRpc};
    use ironwood_intent_escrow::claims::{ClaimStore, FillClaim, NoClaims};
    use ironwood_intent_escrow::cosign::Share;
    use ironwood_intent_escrow::policy::RefundGuard;
    use ironwood_intent_escrow::quote::QuoteId;
    use serde_json::Value;

    #[test]
    fn build_refund_refuses_before_expiry() {
        let mut e = escrow();
        let quote = quote_expiring(EXPIRY);
        let err = build_refund(&quote, &e.inputs, &mut e.wallet, EXPIRY - 1)
            .err()
            .unwrap();
        assert!(matches!(err, Error::NotExpired { .. }), "{err}");
    }

    #[test]
    fn refund_address_is_not_in_the_quote() {
        let mut e = escrow();
        let quote = quote_expiring(EXPIRY);
        let quote_file = e.dir.path().join("quote.json");
        std::fs::write(&quote_file, quote.to_json().unwrap()).unwrap();
        let before = std::fs::read(&quote_file).unwrap();

        let refund = build_refund(&quote, &e.inputs, &mut e.wallet, EXPIRY).unwrap();

        let after = std::fs::read(&quote_file).unwrap();
        assert_eq!(before, after, "the quote file changed");
        let view = ironwood_intent_escrow::view::CheckerView::new(
            &refund.pczt,
            &e.inputs.fvk,
            &refund_ovk(&e.refund_fvk),
        )
        .unwrap();
        let address = view.outputs[0].address;
        assert!(e.refund_fvk.scope_for_address(&address).is_some());
        let encoded = escrow_address_of(address).encode(&NETWORK);
        let raw = hex::encode(address.to_raw_address_bytes());
        for needle in [encoded.as_bytes(), raw.as_bytes()] {
            assert!(!after.windows(needle.len()).any(|w| w == needle));
        }
    }

    fn escrow_address_of(address: orchard::Address) -> UnifiedAddress {
        UnifiedAddress::from_receivers(Some(address), None, None, None, None).unwrap()
    }

    #[test]
    fn deadline_refuses_a_refund_the_refund_key_does_not_detect() {
        let e = escrow();
        let quote = quote_expiring(EXPIRY);
        let fee = escrow_spend_fee(NETWORK, &e.inputs, 1).unwrap().into_u64();
        let stranger = [SpendOutput {
            address: throwaway_address(),
            value: Zatoshis::const_from_u64(ESCROW_VALUE - fee),
        }];
        let spend = spend_pczt(
            NETWORK,
            &e.inputs,
            &stranger,
            &quote.id,
            &refund_ovk(&e.refund_fvk),
        )
        .unwrap();
        let facts = verify_package(&spend.pczt, &e.inputs.fvk).unwrap();
        let (nonces, deadline_commitments) = round1(&share(&e, "deadline.key"));
        let (_, payer_commitments) = round1(&share(&e, "payer.key"));
        let package = signing_package(&facts, vec![payer_commitments, deadline_commitments]);
        let err = deadline_sign(
            &deadline(&e),
            &quote,
            &spend.pczt,
            nonces,
            &package,
            EXPIRY,
            &no_claims_guard(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::NotARefund(_)), "{err}");
    }

    #[test]
    fn deadline_refuses_a_refund_for_another_quote() {
        let mut e = escrow();
        let quote = quote_expiring(EXPIRY);
        let refund = build_refund(&quote, &e.inputs, &mut e.wallet, EXPIRY).unwrap();
        let facts = verify_package(&refund.pczt, &e.inputs.fvk).unwrap();
        let (nonces, deadline_commitments) = round1(&share(&e, "deadline.key"));
        let (_, payer_commitments) = round1(&share(&e, "payer.key"));
        let package = signing_package(&facts, vec![payer_commitments, deadline_commitments]);
        let other = quote_expiring(EXPIRY);
        let err = deadline_sign(
            &deadline(&e),
            &other,
            &refund.pczt,
            nonces,
            &package,
            EXPIRY,
            &no_claims_guard(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::NotARefund(_)), "{err}");
    }

    #[test]
    fn deadline_signs_only_after_expiry() {
        let mut e = escrow();
        let quote = quote_expiring(EXPIRY);
        let refund = build_refund(&quote, &e.inputs, &mut e.wallet, EXPIRY).unwrap();
        let facts = verify_package(&refund.pczt, &e.inputs.fvk).unwrap();
        let deadline_file = share(&e, "deadline.key");
        let payer_file = share(&e, "payer.key");

        let (early_nonces, early_deadline) = round1(&deadline_file);
        let (_, early_payer) = round1(&payer_file);
        let early = signing_package(&facts, vec![early_payer, early_deadline]);
        let err = deadline_sign(
            &deadline(&e),
            &quote,
            &refund.pczt,
            early_nonces,
            &early,
            EXPIRY - 1,
            &no_claims_guard(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::NotExpired { .. }), "{err}");

        let (deadline_nonces, deadline_commitments) = round1(&deadline_file);
        let (payer_nonces, payer_commitments) = round1(&payer_file);
        let package = signing_package(&facts, vec![payer_commitments, deadline_commitments]);
        let deadline_share = deadline_sign(
            &deadline(&e),
            &quote,
            &refund.pczt,
            deadline_nonces,
            &package,
            EXPIRY,
            &no_claims_guard(),
        )
        .unwrap();
        let payer_share = payer_refund(
            &payer(&e),
            &quote,
            &refund.pczt,
            payer_nonces,
            &package,
            EXPIRY,
            &no_claims_guard(),
        )
        .unwrap();
        let signature = aggregate(&package, &[payer_share, deadline_share], &e.inputs.fvk).unwrap();
        let bytes: [u8; 64] = (&signature).into();
        verify_spend_auth(
            &ak_bytes(&e.inputs.fvk),
            &facts.randomizer,
            &facts.sighash,
            &bytes,
        )
        .unwrap();
    }

    /// The refusal, or a panic if the signer produced a share.
    fn refused(result: Result<Share, Error>) -> Error {
        match result {
            Ok(_) => panic!("the signer produced a share"),
            Err(e) => e,
        }
    }

    /// The fill run's NEAR payment, as fetched and recorded.
    fn recorded_payment() -> StoredRpc {
        StoredRpc(runs_file("fill.near.json"))
    }

    #[test]
    fn refund_refused_when_the_quote_was_paid() {
        let mut e = escrow();
        let quote = recorded_fill_quote(1);
        let (refund, facts) = refund_for(&mut e, &quote, EXPIRY);
        let claims = MemClaims::with(recorded_claim(&quote));
        let rpc = recorded_payment();
        let guard = RefundGuard {
            claims: &claims,
            rpc: &rpc,
            banned: recorded_refund_banned(),
        };
        let (deadline, payer) = refund_round2(&e, &quote, &refund, &facts, EXPIRY, &guard);
        for err in [refused(deadline), refused(payer)] {
            assert!(matches!(err, Error::QuotePaid), "{err}");
            assert!(err.to_string().starts_with("quote_paid"), "{err}");
        }
    }

    #[test]
    fn refund_signs_with_no_claim() {
        let mut e = escrow();
        let quote = recorded_fill_quote(1);
        let (refund, facts) = refund_for(&mut e, &quote, EXPIRY);
        // With no claim the RPC is never called: this one panics if it is.
        let guard = RefundGuard {
            claims: &NoClaims,
            rpc: &PanickingRpc,
            banned: recorded_refund_banned(),
        };
        let (deadline, payer) = refund_round2(&e, &quote, &refund, &facts, EXPIRY, &guard);
        assert!(deadline.is_ok() && payer.is_ok());
    }

    #[test]
    fn refund_refused_when_the_claim_cannot_be_fetched() {
        // The archival node's answer to a hash it has not observed, measured
        // 2026-10-22 (docs/decisions/fill-claims.md), and a rate limiter's
        // plain-text body: neither says the quote was not paid.
        let timeout = br#"{"jsonrpc":"2.0","error":{"name":"HANDLER_ERROR","cause":{"info":{"cause":"NOT_OBSERVED"},"name":"TIMEOUT_ERROR"},"code":-32000,"message":"Server error","data":"Timeout"},"id":"x"}"#;
        let rpcs: [&dyn NearRpc; 3] = [
            &FailingRpc,
            &StoredRpc(timeout.to_vec()),
            &StoredRpc(b"Too Many Requests".to_vec()),
        ];
        for rpc in rpcs {
            let mut e = escrow();
            let quote = recorded_fill_quote(1);
            let (refund, facts) = refund_for(&mut e, &quote, EXPIRY);
            let claims = MemClaims::with(recorded_claim(&quote));
            let guard = RefundGuard {
                claims: &claims,
                rpc,
                banned: recorded_refund_banned(),
            };
            let (deadline, payer) = refund_round2(&e, &quote, &refund, &facts, EXPIRY, &guard);
            for err in [refused(deadline), refused(payer)] {
                assert!(matches!(err, Error::ClaimUnverified(_)), "{err}");
            }
        }
    }

    #[test]
    fn refund_signs_when_the_claim_is_false() {
        // A claim pointing at a real payment of another quote: the memo
        // carries the fill quote's id, not this one.
        let other = quote_expiring(1);
        // A claim whose fetched payment carries a Zcash address: the release
        // path refuses that payment, so it is no fill.
        let fill_quote = recorded_fill_quote(1);
        let mut planted: Value = serde_json::from_slice(&runs_file("fill.near.json")).unwrap();
        let escrow_address = fill_record()["escrow_address"]
            .as_str()
            .unwrap()
            .to_string();
        planted["result"]["receipts_outcome"][0]["outcome"]["logs"]
            .as_array_mut()
            .unwrap()
            .push(Value::String(format!("to {escrow_address}")));
        let cases = [
            (other, recorded_payment()),
            (fill_quote, StoredRpc(serde_json::to_vec(&planted).unwrap())),
        ];
        for (quote, rpc) in cases {
            let claim = recorded_claim(&quote);
            let check = check_payload(&quote, &claim.pointer(), &recorded_refund_banned(), &rpc.0);
            assert!(
                matches!(
                    check,
                    Err(Error::MissingField(_)) | Err(Error::BannedField(_))
                ),
                "{check:?}"
            );
            let mut e = escrow();
            let (refund, facts) = refund_for(&mut e, &quote, EXPIRY);
            let claims = MemClaims::with(claim);
            let guard = RefundGuard {
                claims: &claims,
                rpc: &rpc,
                banned: recorded_refund_banned(),
            };
            let (deadline, payer) = refund_round2(&e, &quote, &refund, &facts, EXPIRY, &guard);
            assert!(deadline.is_ok() && payer.is_ok());
        }
    }

    /// A claim store that cannot be read.
    struct UnreadableClaims;

    impl ClaimStore for UnreadableClaims {
        fn claim(&self, _quote_id: &QuoteId) -> Result<Option<FillClaim>, Error> {
            Err(Error::Claim("unreadable".into()))
        }
    }

    #[test]
    fn refund_refused_when_the_claim_store_cannot_be_read() {
        let mut e = escrow();
        let quote = recorded_fill_quote(1);
        let (refund, facts) = refund_for(&mut e, &quote, EXPIRY);
        let guard = RefundGuard {
            claims: &UnreadableClaims,
            rpc: &PanickingRpc,
            banned: recorded_refund_banned(),
        };
        let (deadline, payer) = refund_round2(&e, &quote, &refund, &facts, EXPIRY, &guard);
        for err in [refused(deadline), refused(payer)] {
            assert!(matches!(err, Error::Claim(_)), "{err}");
        }
    }

    #[test]
    fn refund_claim_is_read_after_the_expiry_check() {
        let mut e = escrow();
        let quote = recorded_fill_quote(EXPIRY);
        let (refund, facts) = refund_for(&mut e, &quote, EXPIRY);
        let claims = MemClaims::with(recorded_claim(&quote));
        // A claim exists, but an unexpired quote is refused before it is
        // read: the RPC panics if either signer fetches.
        let guard = RefundGuard {
            claims: &claims,
            rpc: &PanickingRpc,
            banned: recorded_refund_banned(),
        };
        let (deadline, payer) = refund_round2(&e, &quote, &refund, &facts, EXPIRY - 1, &guard);
        for err in [refused(deadline), refused(payer)] {
            assert!(matches!(err, Error::NotExpired { .. }), "{err}");
        }
    }
}
