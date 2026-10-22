//! The payer's wallet (`docs/decisions/stack.md`, Funding).
//!
//! Two seeds, each in a `*.key` file that stays outside the repository:
//!
//! - `payer_wallet.key` owns the note that funds the escrow.
//! - `refund.key` owns the fresh addresses a refund pays. Its full viewing
//!   key goes to the deadline signer, which needs to recognise a refund
//!   output but never to spend it (`docs/decisions/shares.md`).
//!
//! Both accounts live in one `zcash_client_sqlite` database,
//! `payer_wallet.sqlite`, which holds the notes the wallet has scanned and
//! the refund addresses it has handed out.

use std::fs;
use std::num::NonZeroU32;
use std::path::Path;

use orchard::keys::{FullViewingKey, OutgoingViewingKey, Scope, SpendAuthorizingKey};
use pczt::roles::signer::Signer;
use pczt::Pczt;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretVec};
use shardtree::error::ShardTreeError;
use zcash_client_backend::data_api::locking::LockedInputPolicy;
use zcash_client_backend::data_api::wallet::input_selection::LockFilter;
use zcash_client_backend::data_api::wallet::{ConfirmationsPolicy, TargetHeight};
use zcash_client_backend::data_api::{
    Account, AccountBalance, AccountBirthday, Balance, InputSource, WalletCommitmentTrees,
    WalletRead, WalletWrite,
};
use zcash_client_backend::wallet::ReceivedNote;
use zcash_client_sqlite::util::SystemClock;
use zcash_client_sqlite::wallet::commitment_tree;
use zcash_client_sqlite::wallet::init::init_wallet_db;
use zcash_client_sqlite::{AccountUuid, ReceivedNoteId, WalletDb};
use zcash_keys::address::UnifiedAddress;
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedSpendingKey};
use zcash_protocol::consensus::{BlockHeight, Network};
use zcash_protocol::value::Zatoshis;
use zcash_protocol::ShieldedPool;
use zeroize::Zeroize;

use crate::address::require_ironwood_only;
use crate::block_cache::MemBlockCache;
use crate::error::Error;
use crate::files::write_new;
use crate::light::LightClient;
use crate::note::NoteInputs;

/// The seed that owns the funding note.
pub const PAYER_KEY_FILE: &str = "payer_wallet.key";
/// The seed that owns refund addresses.
pub const REFUND_KEY_FILE: &str = "refund.key";
/// The wallet database.
pub const WALLET_DB_FILE: &str = "payer_wallet.sqlite";

const SEED_LEN: usize = 32;

type Db = WalletDb<rusqlite::Connection, Network, SystemClock, UnwrapErr<SysRng>>;

/// An Ironwood note the payer can spend, as the wallet database tracks it.
pub type SpendableNote = ReceivedNote<ReceivedNoteId, orchard::note::Note>;

/// Where a scan stands, and the funding account's balance in each pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalletReport {
    /// The chain tip the last scan saw.
    pub chain_tip: BlockHeight,
    /// The height below which every block has been scanned.
    pub fully_scanned: BlockHeight,
    /// Ironwood, the pool the escrow spends from.
    pub ironwood: Zatoshis,
    /// Orchard, where an older faucet may pay.
    pub orchard: Zatoshis,
    /// Sapling.
    pub sapling: Zatoshis,
}

const SCAN_BATCH: u32 = 1_000;

/// Confirmations before the funding note is spent: the anchor sits this far
/// below the scanned tip, matching the default policy `spendable_note` uses.
const FUNDING_CONFIRMATIONS: u32 = 10;

/// The payer's funding account and refund account.
///
/// `Debug` prints the network and nothing else.
pub struct PayerWallet {
    network: Network,
    db: Db,
    funding: AccountUuid,
    refund: AccountUuid,
    payer_seed: SecretVec<u8>,
}

impl PayerWallet {
    /// Creates a wallet in `dir`: two fresh seeds and a database with both
    /// accounts, scanning from `birthday`. Refuses to replace any file.
    pub fn create(dir: &Path, network: Network, birthday: &AccountBirthday) -> Result<Self, Error> {
        let db_path = dir.join(WALLET_DB_FILE);
        if db_path.exists() {
            return Err(Error::io(
                &db_path,
                std::io::ErrorKind::AlreadyExists.into(),
            ));
        }
        let payer_seed = new_seed(&dir.join(PAYER_KEY_FILE))?;
        let refund_seed = new_seed(&dir.join(REFUND_KEY_FILE))?;
        let mut db = open_db(dir, network)?;
        let funding = db
            .import_account_hd(
                "funding",
                &payer_seed,
                zip32::AccountId::ZERO,
                birthday,
                None,
            )
            .map_err(wallet_err)?
            .0
            .id();
        let refund = db
            .import_account_hd(
                "refund",
                &refund_seed,
                zip32::AccountId::ZERO,
                birthday,
                None,
            )
            .map_err(wallet_err)?
            .0
            .id();
        Ok(PayerWallet {
            network,
            db,
            funding,
            refund,
            payer_seed,
        })
    }

    /// Opens the wallet [`PayerWallet::create`] wrote in `dir`.
    pub fn open(dir: &Path, network: Network) -> Result<Self, Error> {
        let payer_seed = read_seed(&dir.join(PAYER_KEY_FILE))?;
        let refund_seed = read_seed(&dir.join(REFUND_KEY_FILE))?;
        let db = open_db(dir, network)?;
        let funding = account_for_seed(&db, network, &payer_seed, PAYER_KEY_FILE)?;
        let refund = account_for_seed(&db, network, &refund_seed, REFUND_KEY_FILE)?;
        Ok(PayerWallet {
            network,
            db,
            funding,
            refund,
            payer_seed,
        })
    }

    /// The address a faucet pays: the funding account's Orchard receiver at
    /// diversifier index 0, alone. Ironwood shares the Orchard receiver. The
    /// same seed always gives this address.
    pub fn payer_address(&self) -> Result<UnifiedAddress, Error> {
        let (address, _) = self
            .ufvk(self.funding)?
            .default_address(UnifiedAddressRequest::ORCHARD)
            .map_err(|e| Error::Wallet(format!("{e:?}")))?;
        require_ironwood_only(&address)?;
        Ok(address)
    }

    /// An Ironwood note of at least `min` zatoshis that the funding account
    /// can spend, or `no_spendable_note`. Reads what the last scan stored;
    /// before any scan, the tip is the account's birthday.
    pub fn spendable_note(&self, min: Zatoshis) -> Result<SpendableNote, Error> {
        let tip = match self.db.chain_height().map_err(wallet_err)? {
            Some(height) => height,
            None => self
                .db
                .get_account(self.funding)
                .map_err(wallet_err)?
                .ok_or_else(|| Error::Wallet("the funding account is missing".into()))?
                .birthday_height(),
        };
        let notes = self
            .db
            .select_single_spendable_note(
                self.funding,
                min,
                &[ShieldedPool::Ironwood],
                TargetHeight::from(tip + 1),
                ConfirmationsPolicy::default(),
                &[],
                LockFilter::Policy(&LockedInputPolicy::Exclude),
            )
            .map_err(wallet_err)?;
        notes
            .take_ironwood()
            .into_iter()
            .next()
            .ok_or(Error::NoSpendableNote)
    }

    /// The note the funding transaction spends, with its Merkle path to the
    /// Ironwood anchor `FUNDING_CONFIRMATIONS` blocks below the scanned tip.
    pub fn funding_input(&mut self, min: Zatoshis) -> Result<NoteInputs, Error> {
        let confirmations = NonZeroU32::new(FUNDING_CONFIRMATIONS).expect("nonzero");
        let (target, anchor_height) = self
            .db
            .get_target_and_anchor_heights(confirmations)
            .map_err(wallet_err)?
            .ok_or(Error::NoSpendableNote)?;
        let received = self.spendable_note(min)?;
        if received.mined_height().is_none_or(|h| h > anchor_height) {
            return Err(Error::NoSpendableNote);
        }
        let position = received.note_commitment_tree_position();
        let (root, path) = self
            .db
            .with_ironwood_tree_mut::<_, _, ShardTreeError<commitment_tree::Error>>(|tree| {
                let root = tree.root_at_checkpoint_id(&anchor_height)?;
                let path = tree.witness_at_checkpoint_id_caching(position, &anchor_height)?;
                Ok((root, path))
            })
            .map_err(wallet_err)?
            .ok_or_else(|| Error::Wallet("the wallet has no Ironwood tree".into()))?;
        let (Some(root), Some(path)) = (root, path) else {
            return Err(Error::Wallet(format!(
                "no Ironwood anchor or witness at height {anchor_height}"
            )));
        };
        Ok(NoteInputs {
            fvk: orchard_fvk(&self.ufvk(self.funding)?)?,
            note: *received.note(),
            merkle_path: path.into(),
            anchor: root.into(),
            target_height: target.into(),
        })
    }

    /// Signs the funding account's Ironwood spend at `index` in an
    /// IO-finalized, proved PCZT. The spend authorizing key is derived for
    /// this call and dropped with it.
    pub fn sign_funding_spend(&self, pczt: Pczt, index: usize) -> Result<Pczt, Error> {
        let usk = UnifiedSpendingKey::from_seed(
            &self.network,
            self.payer_seed.expose_secret(),
            zip32::AccountId::ZERO,
        )
        .map_err(|e| Error::Wallet(format!("{e:?}")))?;
        let ask = SpendAuthorizingKey::from(usk.orchard());
        let mut signer = Signer::new(pczt).map_err(|e| Error::Pczt(format!("signer: {e:?}")))?;
        signer
            .sign_ironwood(UnwrapErr(SysRng), index, &ask)
            .map_err(|e| Error::Pczt(format!("signer: {e:?}")))?;
        Ok(signer.finish())
    }

    /// The next unused Ironwood-only refund address. The database records
    /// its diversifier index, so the next call returns a different address.
    pub fn fresh_refund_address(&mut self) -> Result<UnifiedAddress, Error> {
        let (address, _) = self
            .db
            .get_next_available_address(self.refund, UnifiedAddressRequest::ORCHARD)
            .map_err(wallet_err)?
            .ok_or_else(|| Error::Wallet("the refund account has no address left".into()))?;
        require_ironwood_only(&address)?;
        Ok(address)
    }

    /// The refund full viewing key the deadline signer holds.
    pub fn refund_fvk(&self) -> Result<FullViewingKey, Error> {
        orchard_fvk(&self.ufvk(self.refund)?)
    }

    /// The payer's outgoing viewing key for an external payment, which the
    /// funding output is. Never the all-zero key.
    pub fn outgoing_viewing_key(&self) -> Result<OutgoingViewingKey, Error> {
        Ok(orchard_fvk(&self.ufvk(self.funding)?)?.to_ovk(Scope::External))
    }

    /// Scans compact blocks from the light server, from where the last scan
    /// stopped (or the birthday) to the server's tip, and stores what the two
    /// accounts received. A light-client scan: no node, no full chain.
    pub async fn sync(&mut self, client: &mut LightClient) -> Result<(), Error> {
        let cache = MemBlockCache::default();
        zcash_client_backend::sync::run(client, &self.network, &cache, &mut self.db, SCAN_BATCH)
            .await
            .map_err(|e| Error::LightServer(format!("scan: {e}")))
    }

    /// Scanned heights and the funding account's balances by pool.
    pub fn summary(&self) -> Result<Option<WalletReport>, Error> {
        let Some(summary) = self
            .db
            .get_wallet_summary(ConfirmationsPolicy::default())
            .map_err(wallet_err)?
        else {
            return Ok(None);
        };
        let funding = summary.account_balances().get(&self.funding);
        let pool = |f: fn(&AccountBalance) -> &Balance| {
            funding.map(|b| f(b).total()).unwrap_or(Zatoshis::ZERO)
        };
        Ok(Some(WalletReport {
            chain_tip: summary.chain_tip_height(),
            fully_scanned: summary.fully_scanned_height(),
            ironwood: pool(AccountBalance::ironwood_balance),
            orchard: pool(AccountBalance::orchard_balance),
            sapling: pool(AccountBalance::sapling_balance),
        }))
    }

    /// The network this wallet is on.
    pub fn network(&self) -> Network {
        self.network
    }

    fn ufvk(&self, account: AccountUuid) -> Result<zcash_keys::keys::UnifiedFullViewingKey, Error> {
        self.db
            .get_account(account)
            .map_err(wallet_err)?
            .and_then(|a| a.ufvk().cloned())
            .ok_or_else(|| Error::Wallet("an account has no full viewing key".into()))
    }
}

impl std::fmt::Debug for PayerWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PayerWallet")
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

/// Opens, or creates, the wallet database. It holds both accounts' full
/// viewing keys, so it is owner-only like the seeds.
fn open_db(dir: &Path, network: Network) -> Result<Db, Error> {
    let path = dir.join(WALLET_DB_FILE);
    let mut db = WalletDb::for_path(&path, network, SystemClock, UnwrapErr(SysRng))
        .map_err(|e| Error::Wallet(format!("{}: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::io(&path, e))?;
    }
    init_wallet_db(&mut db, None).map_err(|e| Error::Wallet(format!("{}: {e}", path.display())))?;
    Ok(db)
}

fn new_seed(path: &Path) -> Result<SecretVec<u8>, Error> {
    let mut seed = vec![0u8; SEED_LEN];
    OsRng.fill_bytes(&mut seed);
    let written = write_new(path, &seed);
    let secret = SecretVec::new(seed);
    written.map(|()| secret)
}

fn read_seed(path: &Path) -> Result<SecretVec<u8>, Error> {
    let mut bytes = fs::read(path).map_err(|e| Error::io(path, e))?;
    if bytes.len() != SEED_LEN {
        bytes.zeroize();
        return Err(Error::key_file(path, "a wallet seed is 32 bytes"));
    }
    Ok(SecretVec::new(bytes))
}

fn account_for_seed(
    db: &Db,
    network: Network,
    seed: &SecretVec<u8>,
    file: &str,
) -> Result<AccountUuid, Error> {
    let usk = UnifiedSpendingKey::from_seed(&network, seed.expose_secret(), zip32::AccountId::ZERO)
        .map_err(|e| Error::Wallet(format!("{file}: {e:?}")))?;
    db.get_account_for_ufvk(&usk.to_unified_full_viewing_key())
        .map_err(wallet_err)?
        .map(|account| account.id())
        .ok_or_else(|| Error::Wallet(format!("{file} has no account in {WALLET_DB_FILE}")))
}

fn orchard_fvk(ufvk: &zcash_keys::keys::UnifiedFullViewingKey) -> Result<FullViewingKey, Error> {
    ufvk.orchard()
        .cloned()
        .ok_or_else(|| Error::Wallet("an account has no Orchard key".into()))
}

fn wallet_err(e: impl std::fmt::Display) -> Error {
    Error::Wallet(e.to_string())
}
