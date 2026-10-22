//! The escrow address derived from `escrow.fvk` is an Ironwood-only unified
//! address, and the decoder refuses one with any other receiver. Run with
//! `cargo test escrow_address -- --nocapture` to see the address.

use ironwood_intent_escrow::address::{escrow_address, parse_ironwood_address};
use ironwood_intent_escrow::frost::{keygen, read_fvk, FVK_FILE};
use ironwood_intent_escrow::Error;
use orchard::keys::{FullViewingKey, Scope};
use zcash_address::unified::{self, Container, Encoding, Receiver, Revision, Uitem};
use zcash_protocol::consensus::{Network, NetworkType};

fn escrow_fvk() -> FullViewingKey {
    let dir = tempfile::tempdir().unwrap();
    keygen(dir.path()).unwrap();
    read_fvk(&dir.path().join(FVK_FILE)).unwrap()
}

fn encode_with(receivers: Vec<Receiver>, network: NetworkType) -> String {
    let items = receivers.into_iter().map(Uitem::Data).collect();
    unified::Address::try_from_items(Revision::R0, items)
        .unwrap()
        .encode(&network)
}

fn orchard_receiver(fvk: &FullViewingKey) -> Receiver {
    Receiver::Orchard(fvk.address_at(0u32, Scope::External).to_raw_address_bytes())
}

#[test]
fn escrow_address_rejects_a_transparent_receiver() {
    let fvk = escrow_fvk();
    let encoded = encode_with(
        vec![orchard_receiver(&fvk), Receiver::P2pkh([0x11; 20])],
        NetworkType::Test,
    );
    let err = parse_ironwood_address(&Network::TestNetwork, &encoded).unwrap_err();
    assert!(matches!(err, Error::NotIronwoodOnly(_)), "{err}");
    assert_eq!(
        err.to_string(),
        "not_ironwood_only: it has a transparent receiver"
    );
}

#[test]
fn escrow_address_rejects_an_unknown_receiver() {
    let fvk = escrow_fvk();
    let encoded = encode_with(
        vec![
            orchard_receiver(&fvk),
            Receiver::Unknown {
                typecode: 0x30,
                data: vec![0x22; 32],
            },
        ],
        NetworkType::Test,
    );
    let err = parse_ironwood_address(&Network::TestNetwork, &encoded).unwrap_err();
    assert!(matches!(err, Error::NotIronwoodOnly(_)), "{err}");
}

#[test]
fn escrow_address_rejects_the_wrong_network() {
    let fvk = escrow_fvk();
    let mainnet = encode_with(vec![orchard_receiver(&fvk)], NetworkType::Main);
    let err = parse_ironwood_address(&Network::TestNetwork, &mainnet).unwrap_err();
    assert!(matches!(err, Error::AddressDecode(_)), "{err}");
}

#[test]
fn escrow_address_is_ironwood_only() {
    let fvk = escrow_fvk();
    let encoded = escrow_address(&fvk).encode(&Network::TestNetwork);
    println!("escrow address: {encoded}");
    assert!(encoded.starts_with("utest1"), "{encoded}");

    let decoded = parse_ironwood_address(&Network::TestNetwork, &encoded).unwrap();
    assert!(!decoded.has_transparent());
    assert!(!decoded.has_sapling());
    assert_eq!(
        decoded.orchard().copied(),
        Some(fvk.address_at(0u32, Scope::External))
    );

    let (_, _, raw) = unified::Address::decode(&encoded).unwrap();
    assert_eq!(raw.items(), vec![orchard_receiver(&fvk)]);
}
