//! Spend authority over the escrow note: a 2-of-3 FROST key on RedPallas.
//!
//! Key generation here is a trusted dealer, not distributed key generation.
//! `docs/decisions/stack.md` opens with `Blocked`: a full viewing key cannot
//! be derived for a FROST-generated Ironwood key until zips#895 lands in
//! ZIP 2005 and in `orchard`. Until then the dealer derives a normal Orchard
//! spending key in memory, splits its `ask`, writes the three shares and
//! `escrow.fvk`, and drops everything else. [`keygen`] keeps its signature so
//! the distributed path can replace its body without changing callers.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use orchard::keys::{FullViewingKey, SpendAuthorizingKey, SpendingKey};
use pasta_curves::group::ff::Field;
use pasta_curves::pallas;
use rand_core::{OsRng, RngCore};
use reddsa::frost::redpallas::keys::{self, IdentifierList, KeyPackage};
use reddsa::frost::redpallas::SigningKey;
use zeroize::{Zeroize, Zeroizing};

use crate::cosign::SignerId;
use crate::error::Error;

/// Signatures needed to spend: two of the three holders.
pub const THRESHOLD: u16 = 2;
/// Holders of a share: payer, solver, and deadline.
pub const SIGNERS: u16 = 3;
/// The escrow full viewing key file: `ak`, `nk`, and `rivk`, 96 bytes.
pub const FVK_FILE: &str = "escrow.fvk";

/// Generates the escrow key with a trusted dealer and writes `payer.key`,
/// `solver.key`, `deadline.key`, and `escrow.fvk` into `out_dir`.
///
/// No other file is written, and the combined spending key is neither
/// written nor returned. Refuses to overwrite an existing file.
pub fn keygen(out_dir: &Path) -> Result<FullViewingKey, Error> {
    let sk = random_spending_key();
    let fvk = FullViewingKey::from(&sk);
    let key_packages = split_ask(&sk, &fvk)?;
    drop(sk);

    for (signer, key_package) in &key_packages {
        let bytes = Zeroizing::new(key_package.serialize()?);
        write_new(&out_dir.join(signer.key_file_name()), &bytes)?;
    }
    write_new(&out_dir.join(FVK_FILE), &fvk.to_bytes())?;
    Ok(fvk)
}

/// `ak`, the first 32 bytes of the full viewing key. It is also the FROST
/// group verifying key.
pub fn ak_bytes(fvk: &FullViewingKey) -> [u8; 32] {
    let mut ak = [0u8; 32];
    ak.copy_from_slice(&fvk.to_bytes()[..32]);
    ak
}

/// Reads `escrow.fvk`.
pub fn read_fvk(path: &Path) -> Result<FullViewingKey, Error> {
    let bytes = fs::read(path).map_err(|e| Error::io(path, e))?;
    let bytes: [u8; 96] = bytes
        .try_into()
        .map_err(|_| Error::key_file(path, "a full viewing key is 96 bytes"))?;
    FullViewingKey::from_bytes(&bytes)
        .ok_or_else(|| Error::key_file(path, "not a valid Orchard full viewing key"))
}

/// One holder's share, read from its `*.key` file.
///
/// `Debug` prints the holder and nothing else.
pub struct ShareFile {
    signer: SignerId,
    key_package: KeyPackage,
}

impl ShareFile {
    /// Reads and checks a share file written by [`keygen`].
    pub fn read(path: &Path) -> Result<Self, Error> {
        let bytes = Zeroizing::new(fs::read(path).map_err(|e| Error::io(path, e))?);
        let key_package = KeyPackage::deserialize(&bytes)
            .map_err(|_| Error::key_file(path, "not a FROST RedPallas key package"))?;
        if *key_package.min_signers() != THRESHOLD {
            return Err(Error::key_file(path, "threshold is not two"));
        }
        let signer = SignerId::from_identifier(*key_package.identifier())?;
        Ok(ShareFile {
            signer,
            key_package,
        })
    }

    /// The holder this share belongs to.
    pub fn signer(&self) -> SignerId {
        self.signer
    }

    /// The group verifying key this share signs for, which is `ak`.
    pub fn group_key_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.key_package.verifying_key().serialize()?)
    }
}

impl std::fmt::Debug for ShareFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareFile")
            .field("signer", &self.signer)
            .finish_non_exhaustive()
    }
}

/// A uniformly random Orchard spending key. This is the body of
/// `SpendingKey::random`, which is `pub(crate)` in orchard 0.16.0.
fn random_spending_key() -> SpendingKey {
    loop {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let sk = SpendingKey::from_bytes(bytes);
        bytes.zeroize();
        if let Some(sk) = Option::<SpendingKey>::from(sk) {
            return sk;
        }
    }
}

/// Splits `ask` into three shares, threshold two, and checks that the group
/// verifying key is the `ak` in `fvk`.
fn split_ask(
    sk: &SpendingKey,
    fvk: &FullViewingKey,
) -> Result<BTreeMap<SignerId, KeyPackage>, Error> {
    // orchard 0.16.0 has no accessor for ask's bytes. Randomizing by zero
    // returns ask itself, already negated so that ak has ỹ = 0.
    let mut ask_bytes = SpendAuthorizingKey::from(sk)
        .randomize(&pallas::Scalar::ZERO)
        .to_bytes();
    let ask = SigningKey::deserialize(&ask_bytes);
    ask_bytes.zeroize();
    let ask = ask?;

    let identifiers = SignerId::ALL.map(SignerId::identifier);
    let (shares, public_key_package) = keys::split(
        &ask,
        SIGNERS,
        THRESHOLD,
        IdentifierList::Custom(&identifiers),
        &mut OsRng,
    )?;
    drop(ask);

    if public_key_package.verifying_key().serialize()? != ak_bytes(fvk) {
        return Err(Error::KeyMismatch("the FROST group key is not ak"));
    }
    shares
        .into_iter()
        .map(|(id, share)| Ok((SignerId::from_identifier(id)?, KeyPackage::try_from(share)?)))
        .collect()
}

/// Writes a new file, refusing to replace one. Key files are owner-only.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path).map_err(|e| Error::io(path, e))?;
    file.write_all(bytes).map_err(|e| Error::io(path, e))?;
    file.sync_all().map_err(|e| Error::io(path, e))
}
