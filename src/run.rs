//! What the `fill` and `refund` binaries share: where things live, the
//! escrow keys split by holder, the solver's NEAR payment, waiting on the
//! chain, and broadcasting.
//!
//! Everything secret lives under `~/.ironwood-intent-escrow/testnet`, outside
//! every repository: the wallet seeds, the three shares (each in its own
//! holder's directory), the NEAR keys, and each run's resumable state. Only
//! the run records go into the repository's `runs/`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use orchard::keys::FullViewingKey;
use pczt::roles::signer::Signer;
use pczt::Pczt;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zcash_client_backend::data_api::AccountBirthday;
use zcash_keys::address::UnifiedAddress;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BranchId, Network};
use zcash_protocol::value::Zatoshis;

use crate::attest::{attest, Attestation, Banned, NearRpc, NearTxPointer};
use crate::checker::check_zec;
use crate::cosign::SignerId;
use crate::error::Error;
use crate::frost::{keygen, read_fvk, ShareFile, FVK_FILE};
use crate::light::{
    broadcast, mined_height, require_ironwood_tree, tip_tree_state, LightClient, SCAN_SERVER,
};
use crate::note::{extract, fund_escrow, prove, tx_bytes};
use crate::quote::Quote;
use crate::wallet::{PayerWallet, PAYER_KEY_FILE};

/// The value each escrow note holds.
pub const ESCROW_ZATOSHIS: u64 = 4_000_000;
/// What the solver pays on NEAR: 0.01 wNEAR, in yoctowNEAR.
pub const QUOTE_YOCTO: u128 = 10_000_000_000_000_000_000_000;
/// The NEP-141 asset, wNEAR.
pub const WNEAR: &str = "wrap.testnet";
/// The network both runs use.
pub const NETWORK: Network = Network::TestNetwork;

const POLL: Duration = Duration::from_secs(30);
const MAX_POLLS: u32 = 80;

/// Where a run's files live.
pub struct RunPaths {
    /// `~/.ironwood-intent-escrow/testnet`, outside every repository.
    pub base: PathBuf,
    /// The repository's `runs/`, for records only.
    pub runs: PathBuf,
}

impl RunPaths {
    /// The default locations; `runs/` is relative to the working directory.
    pub fn default_locations() -> Result<Self, Error> {
        let home =
            std::env::var_os("HOME").ok_or_else(|| Error::Wallet("HOME is not set".into()))?;
        Ok(RunPaths {
            base: PathBuf::from(home).join(".ironwood-intent-escrow/testnet"),
            runs: PathBuf::from("runs"),
        })
    }

    /// The payer's wallet directory.
    pub fn payer_wallet(&self) -> PathBuf {
        self.base.join("payer")
    }

    /// The solver's test wallet, which only receives the release.
    pub fn solver_wallet(&self) -> PathBuf {
        self.base.join("solver")
    }

    /// One holder's directory: its share and a copy of `escrow.fvk`.
    pub fn holder(&self, role: SignerId) -> PathBuf {
        let name = match role {
            SignerId::Payer => "payer",
            SignerId::Solver => "solver",
            SignerId::Deadline => "deadline",
        };
        self.base.join("escrow").join(name)
    }

    /// A run's resumable state file.
    pub fn state(&self, run: &str) -> PathBuf {
        self.base.join("runs").join(format!("{run}.state.json"))
    }
}

/// `run.json`: the NEAR accounts and the CLI the solver process uses.
#[derive(Clone, Debug, Deserialize)]
pub struct RunConfig {
    /// The account that pays wNEAR.
    pub solver_account: String,
    /// Its access key file, outside every repository.
    pub solver_key_file: PathBuf,
    /// The payer's account, the quote's destination.
    pub payer_account: String,
    /// The `near` executable.
    pub near_cli: PathBuf,
}

impl RunConfig {
    /// Reads `run.json` from the base directory.
    pub fn load(paths: &RunPaths) -> Result<Self, Error> {
        let path = paths.base.join("run.json");
        let bytes = fs::read(&path).map_err(|e| Error::io(&path, e))?;
        serde_json::from_slice(&bytes).map_err(|e| Error::key_file(&path, e.to_string()))
    }
}

/// The escrow key: generated once by the trusted dealer, then each share is
/// moved into its holder's directory beside a copy of `escrow.fvk`, and the
/// staging directory is removed, so the four files never stay together.
pub fn ensure_escrow_keys(paths: &RunPaths) -> Result<FullViewingKey, Error> {
    let payer_fvk = paths.holder(SignerId::Payer).join(FVK_FILE);
    if payer_fvk.exists() {
        return read_fvk(&payer_fvk);
    }
    let staging = paths.base.join("escrow").join("staging");
    private_dir(&staging)?;
    let fvk = keygen(&staging)?;
    for role in SignerId::ALL {
        let dir = paths.holder(role);
        private_dir(&dir)?;
        let share = role.key_file_name();
        fs::rename(staging.join(share), dir.join(share)).map_err(|e| Error::io(&dir, e))?;
        fs::copy(staging.join(FVK_FILE), dir.join(FVK_FILE)).map_err(|e| Error::io(&dir, e))?;
    }
    fs::remove_file(staging.join(FVK_FILE)).map_err(|e| Error::io(&staging, e))?;
    fs::remove_dir(&staging).map_err(|e| Error::io(&staging, e))?;
    Ok(fvk)
}

/// One holder's share, read from its own directory only.
pub fn share(paths: &RunPaths, role: SignerId) -> Result<ShareFile, Error> {
    ShareFile::read(&paths.holder(role).join(role.key_file_name()))
}

/// A wallet birthday at the light server's current tip.
pub async fn tip_birthday(client: &mut LightClient) -> Result<AccountBirthday, Error> {
    let state = tip_tree_state(client, SCAN_SERVER).await?;
    require_ironwood_tree(&state)?;
    AccountBirthday::from_treestate(state, None)
        .map_err(|e| Error::LightServer(format!("birthday: {e:?}")))
}

/// The solver's test wallet, created at the current tip if absent, and the
/// Ironwood-only address the release pays.
pub async fn solver_address(
    paths: &RunPaths,
    client: &mut LightClient,
) -> Result<UnifiedAddress, Error> {
    let dir = paths.solver_wallet();
    let wallet = if dir.join(PAYER_KEY_FILE).exists() {
        PayerWallet::open(&dir, NETWORK)?
    } else {
        private_dir(&dir)?;
        PayerWallet::create(&dir, NETWORK, &tip_birthday(client).await?)?
    };
    wallet.payer_address()
}

/// The solver process pays the quote on NEAR with the CLI and hands back
/// only the transaction hash and its own account.
pub fn near_pay(config: &RunConfig, quote: &Quote) -> Result<NearTxPointer, Error> {
    let args = serde_json::json!({
        "receiver_id": quote.destination_account,
        "amount": quote.amount.to_string(),
        "memo": quote.id.to_hex(),
    });
    let output = Command::new(&config.near_cli)
        .args([
            "contract",
            "call-function",
            "as-transaction",
            &quote.asset,
            "ft_transfer",
            "json-args",
        ])
        .arg(args.to_string())
        .args([
            "prepaid-gas",
            "30.0 Tgas",
            "attached-deposit",
            "1 yoctoNEAR",
            "sign-as",
        ])
        .arg(&config.solver_account)
        .args(["network-config", "testnet", "sign-with-access-key-file"])
        .arg(&config.solver_key_file)
        .arg("send")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| Error::Attestation(format!("near cli: {e}")))?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned()
        + &String::from_utf8_lossy(&output.stderr);
    let hash = text
        .lines()
        .find_map(|l| l.split("Transaction ID:").nth(1))
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty() && h.chars().all(|c| c.is_ascii_alphanumeric()));
    match (output.status.success() && text.contains("succeeded"), hash) {
        (true, Some(hash)) => Ok(NearTxPointer {
            hash,
            sender: config.solver_account.clone(),
        }),
        _ => Err(Error::Attestation(format!(
            "the NEAR payment failed: {}",
            tail(&text)
        ))),
    }
}

/// `attest`, retried while the archival node has not yet seen the
/// transaction the solver just sent.
pub async fn attest_when_final(
    quote: &Quote,
    pointer: &NearTxPointer,
    banned: &Banned,
    rpc: &dyn NearRpc,
) -> Result<Attestation, Error> {
    let mut last = None;
    for _ in 0..12 {
        match attest(quote, pointer, banned, rpc) {
            Ok(attestation) => return Ok(attestation),
            Err(Error::Attestation(e)) => last = Some(e),
            Err(other) => return Err(other),
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    Err(Error::Attestation(last.unwrap_or_default()))
}

/// Scans until `ready` returns `Ok`, polling every 30 s; `no_spendable_note`
/// means not yet.
pub async fn wait_for<T>(
    wallet: &mut PayerWallet,
    client: &mut LightClient,
    what: &str,
    mut ready: impl FnMut(&mut PayerWallet) -> Result<T, Error>,
) -> Result<T, Error> {
    for _ in 0..MAX_POLLS {
        wallet.sync(client).await?;
        match ready(wallet) {
            Ok(value) => return Ok(value),
            Err(Error::NoSpendableNote) => println!("waiting for {what}"),
            Err(other) => return Err(other),
        }
        tokio::time::sleep(POLL).await;
    }
    Err(Error::LightServer(format!("timed out waiting for {what}")))
}

/// Broadcasts and waits until the transaction is mined; returns the height.
pub async fn broadcast_and_wait(
    client: &mut LightClient,
    bytes: &[u8],
    txid: &TxId,
) -> Result<u64, Error> {
    if mined_height(client, SCAN_SERVER, txid)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        broadcast(client, SCAN_SERVER, bytes).await?;
    }
    for _ in 0..MAX_POLLS {
        if let Ok(Some(height)) = mined_height(client, SCAN_SERVER, txid).await {
            return Ok(height);
        }
        println!("waiting for {txid} to be mined");
        tokio::time::sleep(POLL).await;
    }
    Err(Error::LightServer(format!("{txid} was not mined in time")))
}

/// Proves the escrow spend, applies the aggregated FROST signature to its
/// spend action, and extracts the transaction.
pub fn finish_spend(
    pczt: Pczt,
    spend_index: usize,
    signature: orchard::primitives::redpallas::Signature<orchard::primitives::redpallas::SpendAuth>,
) -> Result<Transaction, Error> {
    let mut signer =
        Signer::new(prove(pczt)?).map_err(|e| Error::Pczt(format!("signer: {e:?}")))?;
    signer
        .apply_ironwood_signature(spend_index, signature)
        .map_err(|e| Error::Pczt(format!("signature: {e:?}")))?;
    extract(signer.finish())
}

/// A run's funding transaction: its bytes once built, its height once mined.
/// The field names are the state file's.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Funding {
    /// The raw funding transaction, hex.
    pub fund_tx: Option<String>,
    /// Where it was mined.
    pub fund_height: Option<u64>,
}

/// Funds the escrow once: builds and checks the transaction, persists it,
/// and only then broadcasts, so a resumed run rebroadcasts the same bytes
/// instead of spending the payer's note twice.
pub async fn fund_once(
    funding: &mut Funding,
    wallet: &mut PayerWallet,
    client: &mut LightClient,
    escrow: &UnifiedAddress,
    mut persist: impl FnMut(&Funding) -> Result<(), Error>,
) -> Result<Transaction, Error> {
    let tx = match &funding.fund_tx {
        Some(hex) => parse_tx(hex)?,
        None => {
            wallet.sync(client).await?;
            let amount = Zatoshis::const_from_u64(ESCROW_ZATOSHIS);
            let tx = fund_escrow(escrow, amount, wallet)?;
            check_zec(&tx_bytes(&tx)?)?;
            funding.fund_tx = Some(hex::encode(tx_bytes(&tx)?));
            persist(funding)?;
            tx
        }
    };
    if funding.fund_height.is_none() {
        let height = broadcast_and_wait(client, &tx_bytes(&tx)?, &tx.txid()).await?;
        println!("fund {} mined at {height}", tx.txid());
        funding.fund_height = Some(height);
        persist(funding)?;
    }
    Ok(tx)
}

/// Parses a transaction stored as hex.
pub fn parse_tx(hex_bytes: &str) -> Result<Transaction, Error> {
    let bytes = hex::decode(hex_bytes).map_err(|e| Error::Wallet(e.to_string()))?;
    Transaction::read(&bytes[..], BranchId::Nu7).map_err(|e| Error::Checker(e.to_string()))
}

/// SHA-256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

/// Reads a state file, if the run has one.
pub fn load_state<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, Error> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| Error::key_file(path, e.to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::io(path, e)),
    }
}

/// Writes a state file, owner-only, replacing the previous one.
pub fn save_state<T: Serialize>(path: &Path, state: &T) -> Result<(), Error> {
    if let Some(dir) = path.parent() {
        private_dir(dir)?;
    }
    let json = serde_json::to_vec_pretty(state).map_err(|e| Error::Wallet(e.to_string()))?;
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    crate::files::write_new(&tmp, &json)?;
    fs::rename(&tmp, path).map_err(|e| Error::io(path, e))
}

/// Writes a run record into the repository's `runs/`.
pub fn write_record(paths: &RunPaths, name: &str, bytes: &[u8]) -> Result<(), Error> {
    fs::create_dir_all(&paths.runs).map_err(|e| Error::io(&paths.runs, e))?;
    let path = paths.runs.join(name);
    fs::write(&path, bytes).map_err(|e| Error::io(&path, e))
}

/// Seconds since the Unix epoch.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A transaction id as the 64-hex display string, byte-reversed as block
/// explorers and `zcashd` show it.
pub fn txid_hex(txid: &TxId) -> String {
    txid.to_string()
}

fn private_dir(dir: &Path) -> Result<(), Error> {
    fs::create_dir_all(dir).map_err(|e| Error::io(dir, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::io(dir, e))?;
    }
    Ok(())
}

fn tail(text: &str) -> String {
    text.lines()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join(" | ")
}
