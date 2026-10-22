//! The refund side of the policy signers. Run with `cargo test policy`.
//!
//! The refund key and addresses are an offline payer wallet's, so the
//! deadline device recognises outputs with the real refund key.

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
    use crate::common::{throwaway_address, ESCROW_VALUE};

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
        let err = deadline_sign(&deadline(&e), &quote, &spend.pczt, nonces, &package, EXPIRY)
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
        )
        .unwrap();
        let payer_share = payer_refund(
            &payer(&e),
            &quote,
            &refund.pczt,
            payer_nonces,
            &package,
            EXPIRY,
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
}
