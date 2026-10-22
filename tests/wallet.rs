//! The payer wallet, offline. Run with `cargo test wallet`.
//!
//! The birthday is Ironwood activation with an empty chain state, so no
//! test talks to a light server. Scanning a live server is not a unit test.

use std::path::Path;

use ironwood_intent_escrow::address::require_ironwood_only;
use ironwood_intent_escrow::wallet::{
    PayerWallet, PAYER_KEY_FILE, REFUND_KEY_FILE, WALLET_DB_FILE,
};
use ironwood_intent_escrow::Error;
use orchard::keys::Scope;
use zcash_client_backend::data_api::chain::ChainState;
use zcash_client_backend::data_api::AccountBirthday;
use zcash_keys::address::UnifiedAddress;
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::{Network, NetworkUpgrade, Parameters};
use zcash_protocol::value::Zatoshis;

fn offline_birthday() -> AccountBirthday {
    let activation = Network::TestNetwork
        .activation_height(NetworkUpgrade::Nu6_3)
        .unwrap();
    AccountBirthday::from_parts(ChainState::empty(activation - 1, BlockHash([0; 32])), None)
}

fn new_wallet(dir: &Path) -> PayerWallet {
    PayerWallet::create(dir, Network::TestNetwork, &offline_birthday()).unwrap()
}

fn orchard_receiver(address: &UnifiedAddress) -> orchard::Address {
    *address.orchard().expect("an Orchard receiver")
}

#[test]
fn wallet_empty_has_no_spendable_note() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = new_wallet(dir.path());
    let err = wallet
        .spendable_note(Zatoshis::const_from_u64(1))
        .unwrap_err();
    assert!(matches!(err, Error::NoSpendableNote), "{err}");
    assert!(err.to_string().starts_with("no_spendable_note"));
}

#[test]
fn wallet_refuses_to_overwrite_its_keys() {
    let dir = tempfile::tempdir().unwrap();
    new_wallet(dir.path());
    let before = std::fs::read(dir.path().join(PAYER_KEY_FILE)).unwrap();
    let err =
        PayerWallet::create(dir.path(), Network::TestNetwork, &offline_birthday()).unwrap_err();
    assert!(
        matches!(&err, Error::Io { source, .. } if source.kind() == std::io::ErrorKind::AlreadyExists),
        "{err}"
    );
    assert_eq!(
        std::fs::read(dir.path().join(PAYER_KEY_FILE)).unwrap(),
        before
    );
}

#[test]
fn wallet_refund_addresses_are_fresh_and_ironwood_only() {
    let dir = tempfile::tempdir().unwrap();
    let mut wallet = new_wallet(dir.path());
    let first = wallet.fresh_refund_address().unwrap();
    let second = wallet.fresh_refund_address().unwrap();

    let network = Network::TestNetwork;
    assert_ne!(first.encode(&network), second.encode(&network));
    for address in [&first, &second] {
        require_ironwood_only(address).unwrap();
        assert!(!address.has_transparent());
        assert!(address.encode(&network).starts_with("utest1"));
    }

    // The deadline signer's key recognises both; the funding key does not.
    let refund_fvk = wallet.refund_fvk().unwrap();
    for address in [&first, &second] {
        let receiver = orchard_receiver(address);
        assert_eq!(
            refund_fvk.scope_for_address(&receiver),
            Some(Scope::External)
        );
    }
    let payer_receiver = orchard_receiver(&wallet.payer_address().unwrap());
    assert_eq!(refund_fvk.scope_for_address(&payer_receiver), None);
    assert_ne!(payer_receiver, orchard_receiver(&first));
}

#[test]
fn wallet_payer_address_is_ironwood_only() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = new_wallet(dir.path());
    let address = wallet.payer_address().unwrap();
    require_ironwood_only(&address).unwrap();
    assert!(!address.has_transparent());
    assert!(!address.has_sapling());
    assert!(address.has_orchard());
    assert!(address.encode(&Network::TestNetwork).starts_with("utest1"));
}

#[cfg(unix)]
#[test]
fn wallet_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    new_wallet(dir.path());
    for name in [PAYER_KEY_FILE, REFUND_KEY_FILE, WALLET_DB_FILE] {
        let mode = std::fs::metadata(dir.path().join(name))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{name}");
    }
}

#[test]
fn wallet_outgoing_viewing_key_is_not_zero() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = new_wallet(dir.path());
    let ovk = wallet.outgoing_viewing_key().unwrap();
    assert_ne!(ovk.as_ref(), &[0u8; 32]);
}

#[test]
fn wallet_reopens_with_the_same_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let (payer, first_refund) = {
        let mut wallet = new_wallet(dir.path());
        (
            wallet
                .payer_address()
                .unwrap()
                .encode(&Network::TestNetwork),
            wallet
                .fresh_refund_address()
                .unwrap()
                .encode(&Network::TestNetwork),
        )
    };
    let mut reopened = PayerWallet::open(dir.path(), Network::TestNetwork).unwrap();
    assert_eq!(
        reopened
            .payer_address()
            .unwrap()
            .encode(&Network::TestNetwork),
        payer
    );
    let next_refund = reopened.fresh_refund_address().unwrap();
    assert_ne!(next_refund.encode(&Network::TestNetwork), first_refund);
    assert!(dir.path().join(REFUND_KEY_FILE).exists());
}

#[test]
fn wallet_escrow_account_imports_once_and_holds_no_note_before_a_scan() {
    let dir = tempfile::tempdir().unwrap();
    let keys = tempfile::tempdir().unwrap();
    let escrow_fvk = ironwood_intent_escrow::frost::keygen(keys.path()).unwrap();
    let ufvk =
        ironwood_intent_escrow::escrow_account::escrow_ufvk(&Network::TestNetwork, &escrow_fvk)
            .unwrap();
    assert_eq!(ufvk.orchard(), Some(&escrow_fvk));
    assert!(ufvk.sapling().is_none());

    let mut wallet = new_wallet(dir.path());
    assert!(wallet.escrow_account(&escrow_fvk).unwrap().is_none());
    let first = wallet
        .ensure_escrow_account(&escrow_fvk, &offline_birthday())
        .unwrap();
    let again = wallet
        .ensure_escrow_account(&escrow_fvk, &offline_birthday())
        .unwrap();
    assert_eq!(first, again);

    let reopened = PayerWallet::open(dir.path(), Network::TestNetwork).unwrap();
    assert_eq!(reopened.escrow_account(&escrow_fvk).unwrap(), Some(first));
    let err = wallet
        .escrow_input(
            &escrow_fvk,
            &zcash_primitives::transaction::TxId::from_bytes([7; 32]),
        )
        .unwrap_err();
    assert!(matches!(err, Error::NoSpendableNote), "{err}");
}
