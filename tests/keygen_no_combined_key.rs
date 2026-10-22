//! `keygen` writes three shares and `escrow.fvk`, and no file it writes holds
//! the combined key. Run with `cargo test keygen_no_combined_key`.
//!
//! "Holds the combined key" means some 32-byte window of a file decodes as
//! either form the key could take:
//! - an Orchard spending key whose full viewing key is the escrow's, or
//! - a RedPallas scalar whose public key is `ak` or `-ak`, that is, `ask`
//!   before or after Orchard's sign adjustment.
//!
//! Every byte offset of every file is tried. The planted-key tests show the
//! scan finds both forms, so a clean result means something.

use std::fs;
use std::path::Path;

use ironwood_intent_escrow::frost::{ak_bytes, keygen, read_fvk, ShareFile, FVK_FILE};
use ironwood_intent_escrow::Error;
use orchard::keys::{FullViewingKey, SpendAuthorizingKey, SpendingKey};
use pasta_curves::group::ff::{Field, PrimeField};
use pasta_curves::pallas;
use rand_core::{OsRng, RngCore};
use reddsa::frost::redpallas::{SigningKey, VerifyingKey};

const EXPECTED_FILES: [&str; 4] = ["deadline.key", "escrow.fvk", "payer.key", "solver.key"];

fn file_holding_combined_key(dir: &Path, fvk: &FullViewingKey) -> Option<String> {
    let ak = ak_bytes(fvk);
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let bytes = fs::read(entry.path()).unwrap();
        if bytes.windows(32).any(|w| is_combined_key(w, fvk, &ak)) {
            return Some(entry.file_name().to_string_lossy().into_owned());
        }
    }
    None
}

fn is_combined_key(window: &[u8], fvk: &FullViewingKey, ak: &[u8; 32]) -> bool {
    let bytes: [u8; 32] = window.try_into().unwrap();
    let public_key = SigningKey::deserialize(&bytes)
        .ok()
        .and_then(|k| VerifyingKey::from(&k).serialize().ok());
    // Compare the x-coordinate only, so ask and -ask both match.
    let is_ask =
        public_key.is_some_and(|pk| pk[..31] == ak[..31] && pk[31] & 0x7f == ak[31] & 0x7f);
    is_ask
        || Option::<SpendingKey>::from(SpendingKey::from_bytes(bytes))
            .is_some_and(|sk| FullViewingKey::from(&sk) == *fvk)
}

fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn throwaway_spending_key() -> SpendingKey {
    loop {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(bytes)) {
            return sk;
        }
    }
}

fn plant(dir: &Path, fvk: &FullViewingKey, name: &str, key: &[u8; 32]) {
    fs::write(dir.join(FVK_FILE), fvk.to_bytes()).unwrap();
    let mut leak = vec![0x5a; 7];
    leak.extend_from_slice(key);
    leak.extend_from_slice(&[0xa5; 9]);
    fs::write(dir.join(name), leak).unwrap();
}

#[test]
fn keygen_no_combined_key_scan_finds_a_planted_spending_key() {
    let dir = tempfile::tempdir().unwrap();
    let sk = throwaway_spending_key();
    let fvk = FullViewingKey::from(&sk);
    plant(dir.path(), &fvk, "leak.bin", sk.to_bytes());
    assert_eq!(
        file_holding_combined_key(dir.path(), &fvk).as_deref(),
        Some("leak.bin")
    );
}

#[test]
fn keygen_no_combined_key_scan_finds_a_planted_ask_either_sign() {
    let sk = throwaway_spending_key();
    let fvk = FullViewingKey::from(&sk);
    let ask = SpendAuthorizingKey::from(&sk)
        .randomize(&pallas::Scalar::ZERO)
        .to_bytes();
    let negated = (-pallas::Scalar::from_repr(ask).unwrap()).to_repr();
    for key in [ask, negated] {
        let dir = tempfile::tempdir().unwrap();
        plant(dir.path(), &fvk, "leak.bin", &key);
        assert_eq!(
            file_holding_combined_key(dir.path(), &fvk).as_deref(),
            Some("leak.bin")
        );
    }
}

#[test]
fn keygen_no_combined_key_refuses_to_overwrite_a_share() {
    let dir = tempfile::tempdir().unwrap();
    keygen(dir.path()).unwrap();
    let before = fs::read(dir.path().join("payer.key")).unwrap();
    let err = keygen(dir.path()).unwrap_err();
    assert!(
        matches!(&err, Error::Io { source, .. } if source.kind() == std::io::ErrorKind::AlreadyExists),
        "{err}"
    );
    assert_eq!(fs::read(dir.path().join("payer.key")).unwrap(), before);
}

#[test]
fn keygen_no_combined_key() {
    let dir = tempfile::tempdir().unwrap();
    let fvk = keygen(dir.path()).unwrap();

    let files = listing(dir.path());
    println!("keygen wrote: {}", files.join(", "));
    assert_eq!(files, EXPECTED_FILES);

    assert_eq!(read_fvk(&dir.path().join(FVK_FILE)).unwrap(), fvk);
    let ak = ak_bytes(&fvk);
    for name in ["payer.key", "solver.key", "deadline.key"] {
        let share = ShareFile::read(&dir.path().join(name)).unwrap();
        assert_eq!(share.signer().key_file_name(), name);
        assert_eq!(share.group_key_bytes().unwrap(), ak);
    }

    #[cfg(unix)]
    for name in EXPECTED_FILES {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(dir.path().join(name))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{name}");
    }

    assert_eq!(file_holding_combined_key(dir.path(), &fvk), None);
}
