//! The testnet light servers in `docs/decisions/stack.md`, Broadcast path.
//!
//! gRPC over TLS on port 443. This module reads the chain tip and the tree
//! state there, which is what a wallet birthday needs. It does not download
//! or scan blocks.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_client_backend::proto::service::{
    BlockId, ChainSpec, RawTransaction, TreeState, TxFilter,
};
use zcash_primitives::transaction::TxId;

use crate::error::Error;

/// The two testnet light servers that accepted TCP on 2026-10-22.
pub const TESTNET_SERVERS: [&str; 2] = [
    "https://zaino.testnet.unsafe.zec.rocks:443",
    "https://testnet.zec.rocks:443",
];

/// The server the wallet scans and broadcasts through. Lance accepted it on
/// 2026-10-22, when it was the only one in `stack.md` returning an Ironwood
/// tree.
pub const SCAN_SERVER: &str = "https://testnet.zec.rocks:443";

/// The wallet birthday file, beside the wallet seeds.
pub const BIRTHDAY_FILE: &str = "birthday.json";

/// A gRPC client for one light server.
pub type LightClient = CompactTxStreamerClient<Channel>;

/// Connects to `url` over TLS with the webpki root store.
pub async fn connect(url: &str) -> Result<LightClient, Error> {
    let endpoint = Endpoint::from_shared(url.to_string())
        .and_then(|e| e.tls_config(ClientTlsConfig::new().with_webpki_roots()))
        .map_err(|e| light_err(url, e))?
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(60));
    let channel = endpoint.connect().await.map_err(|e| light_err(url, e))?;
    Ok(CompactTxStreamerClient::new(channel))
}

/// The tree state at the server's current tip.
pub async fn tip_tree_state(client: &mut LightClient, url: &str) -> Result<TreeState, Error> {
    let tip = client
        .get_latest_block(ChainSpec {})
        .await
        .map_err(|e| light_err(url, e))?
        .into_inner();
    let state = client
        .get_tree_state(BlockId {
            height: tip.height,
            hash: vec![],
        })
        .await
        .map_err(|e| light_err(url, e))?
        .into_inner();
    Ok(state)
}

/// Submits raw transaction bytes. A nonzero `error_code` from the server is
/// an error carrying its message, which a blocked run records verbatim.
pub async fn broadcast(client: &mut LightClient, url: &str, tx_bytes: &[u8]) -> Result<(), Error> {
    let response = client
        .send_transaction(RawTransaction {
            data: tx_bytes.to_vec(),
            height: 0,
        })
        .await
        .map_err(|e| light_err(url, e))?
        .into_inner();
    if response.error_code != 0 {
        return Err(Error::LightServer(format!(
            "{url}: send_transaction error {}: {}",
            response.error_code, response.error_message
        )));
    }
    Ok(())
}

/// Where a transaction stands: `Ok(Some(height))` once mined in the main
/// chain, `Ok(None)` while in the mempool or on a side fork.
pub async fn mined_height(
    client: &mut LightClient,
    url: &str,
    txid: &TxId,
) -> Result<Option<u64>, Error> {
    let raw = client
        .get_transaction(TxFilter {
            block: None,
            index: 0,
            hash: txid.as_ref().to_vec(),
        })
        .await
        .map_err(|e| light_err(url, e))?
        .into_inner();
    Ok(match raw.height {
        0 | u64::MAX => None,
        height => Some(height),
    })
}

/// Refuses a tree state without a non-empty Ironwood tree. A server that
/// does not serve Ironwood returns an empty string, which the backend would
/// otherwise read as an empty tree and so give the wallet a wrong birthday.
pub fn require_ironwood_tree(state: &TreeState) -> Result<(), Error> {
    if state.ironwood_tree.is_empty() {
        return Err(Error::LightServer(
            "the tree state has no Ironwood tree".into(),
        ));
    }
    let tree = state
        .ironwood_tree()
        .map_err(|e| Error::LightServer(format!("the Ironwood tree does not parse: {e}")))?;
    if tree.size() == 0 {
        return Err(Error::LightServer("the Ironwood tree is empty".into()));
    }
    state
        .to_chain_state()
        .map_err(|e| Error::LightServer(format!("the tree state does not parse: {e}")))?;
    Ok(())
}

/// A wallet birthday as written to `birthday.json`: the server it came from
/// and the tree state fields, which are public chain data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BirthdayRecord {
    /// The light server that returned the tree state.
    pub server: String,
    /// The network name the server reported.
    pub network: String,
    /// The block height of the tree state.
    pub height: u64,
    /// The block hash, as the server's hex.
    pub hash: String,
    /// The block time.
    pub time: u32,
    /// The Sapling note commitment tree, hex.
    pub sapling_tree: String,
    /// The Orchard note commitment tree, hex.
    pub orchard_tree: String,
    /// The Ironwood note commitment tree, hex.
    pub ironwood_tree: String,
}

impl BirthdayRecord {
    /// Records `state` as fetched from `server`.
    pub fn new(server: &str, state: &TreeState) -> Self {
        BirthdayRecord {
            server: server.to_string(),
            network: state.network.clone(),
            height: state.height,
            hash: state.hash.clone(),
            time: state.time,
            sapling_tree: state.sapling_tree.clone(),
            orchard_tree: state.orchard_tree.clone(),
            ironwood_tree: state.ironwood_tree.clone(),
        }
    }

    /// Writes the record to `dir/birthday.json`, refusing to replace one.
    pub fn write_new(&self, dir: &std::path::Path) -> Result<(), Error> {
        let json = serde_json::to_vec_pretty(self).map_err(|e| Error::Wallet(e.to_string()))?;
        crate::files::write_new(&dir.join(BIRTHDAY_FILE), &json)
    }

    /// The tree state this record holds.
    pub fn tree_state(&self) -> TreeState {
        TreeState {
            network: self.network.clone(),
            height: self.height,
            hash: self.hash.clone(),
            time: self.time,
            sapling_tree: self.sapling_tree.clone(),
            orchard_tree: self.orchard_tree.clone(),
            ironwood_tree: self.ironwood_tree.clone(),
        }
    }
}

fn light_err(url: &str, e: impl std::fmt::Display) -> Error {
    Error::LightServer(format!("{url}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(ironwood_tree: &str) -> TreeState {
        TreeState {
            network: "test".into(),
            height: 4_600_000,
            hash: "00".repeat(32),
            time: 1,
            ironwood_tree: ironwood_tree.into(),
            ..TreeState::default()
        }
    }

    #[test]
    fn light_refuses_a_tree_state_without_an_ironwood_tree() {
        let err = require_ironwood_tree(&state("")).unwrap_err();
        assert!(matches!(err, Error::LightServer(_)), "{err}");
    }

    #[test]
    fn light_refuses_an_ironwood_tree_that_is_not_hex() {
        let err = require_ironwood_tree(&state("not hex")).unwrap_err();
        assert!(err.to_string().contains("does not parse"), "{err}");
    }

    #[test]
    fn light_refuses_an_empty_ironwood_tree() {
        // An empty CommitmentTree encodes as three zero bytes: no left, no
        // right, no parents.
        let err = require_ironwood_tree(&state("000000")).unwrap_err();
        assert!(err.to_string().contains("is empty"), "{err}");
    }

    #[test]
    fn light_birthday_record_round_trips() {
        let original = state("000000");
        let record = BirthdayRecord::new("https://example.invalid:443", &original);
        let json = serde_json::to_string(&record).unwrap();
        let back: BirthdayRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
        assert_eq!(back.tree_state(), original);
    }
}
