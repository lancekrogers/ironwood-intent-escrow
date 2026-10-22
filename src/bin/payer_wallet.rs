//! Creates the payer's testnet wallet and prints the address a faucet pays.
//!
//! ```text
//! cargo run --bin payer_wallet -- <wallet-dir> [--scan]
//! ```
//!
//! `<wallet-dir>` must be outside any git repository: it holds the two
//! wallet seeds. The program asks each light server in
//! `docs/decisions/stack.md` for its tip and tree state, and reports which
//! ones carry an Ironwood tree. It takes the birthday from the first that
//! does and writes `birthday.json` beside the seeds. Run it again on an
//! existing wallet and it prints the address; add `--scan` to scan compact
//! blocks from the birthday over the light server and print the balance.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ironwood_intent_escrow::light::{
    connect, require_ironwood_tree, tip_tree_state, BirthdayRecord, SCAN_SERVER, TESTNET_SERVERS,
};
use ironwood_intent_escrow::wallet::{PayerWallet, PAYER_KEY_FILE};
use ironwood_intent_escrow::Error;
use zcash_client_backend::data_api::AccountBirthday;
use zcash_client_backend::proto::service::TreeState;
use zcash_protocol::consensus::Network;
use zcash_protocol::value::Zatoshis;

#[tokio::main]
async fn main() -> ExitCode {
    let Some(dir) = std::env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("usage: payer_wallet <wallet-dir outside any git repository>");
        return ExitCode::from(2);
    };
    match run(&dir).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(dir: &Path) -> Result<(), Error> {
    let network = Network::TestNetwork;
    if dir.join(PAYER_KEY_FILE).exists() {
        let mut wallet = PayerWallet::open(dir, network)?;
        println!(
            "payer address: {}",
            wallet.payer_address()?.encode(&network)
        );
        if std::env::args().any(|a| a == "--scan") {
            scan(&mut wallet).await?;
        }
        return Ok(());
    }
    refuse_inside_git(dir)?;
    create_private_dir(dir)?;

    let (server, state) = first_ironwood_server().await?;
    let birthday = AccountBirthday::from_treestate(state.clone(), None)
        .map_err(|e| Error::LightServer(format!("{server}: {e:?}")))?;
    BirthdayRecord::new(server, &state).write_new(dir)?;

    let wallet = PayerWallet::create(dir, network, &birthday)?;
    println!("birthday: height {} from {server}", birthday.height());
    println!(
        "payer address: {}",
        wallet.payer_address()?.encode(&network)
    );
    Ok(())
}

/// Scans the wallet over the server Lance accepted and prints where the
/// scan stands and the funding account's balance by pool.
async fn scan(wallet: &mut PayerWallet) -> Result<(), Error> {
    let mut client = connect(SCAN_SERVER).await?;
    wallet.sync(&mut client).await?;
    match wallet.summary()? {
        Some(r) => println!(
            "scanned to {} (tip {}): ironwood {} orchard {} sapling {} zatoshis",
            u32::from(r.fully_scanned),
            u32::from(r.chain_tip),
            r.ironwood.into_u64(),
            r.orchard.into_u64(),
            r.sapling.into_u64()
        ),
        None => println!("no wallet summary yet"),
    }
    match wallet.spendable_note(Zatoshis::const_from_u64(1)) {
        Ok(note) => println!(
            "spendable Ironwood note: {} zatoshis, mined at {}",
            note.note().value().inner(),
            note.mined_height().map(u32::from).unwrap_or(0)
        ),
        Err(e) => println!("{e}"),
    }
    Ok(())
}

/// Asks every server, reports each, and returns the first whose tree state
/// carries an Ironwood tree.
async fn first_ironwood_server() -> Result<(&'static str, TreeState), Error> {
    let mut chosen = None;
    for url in TESTNET_SERVERS {
        let probed = async {
            let mut client = connect(url).await?;
            let state = tip_tree_state(&mut client, url).await?;
            require_ironwood_tree(&state)?;
            Ok::<_, Error>(state)
        }
        .await;
        match probed {
            Ok(state) => {
                println!("{url}: tip {} carries an Ironwood tree", state.height);
                chosen.get_or_insert((url, state));
            }
            Err(e) => println!("{url}: refused: {e}"),
        }
    }
    chosen
        .ok_or_else(|| Error::LightServer("no server in stack.md returned an Ironwood tree".into()))
}

fn create_private_dir(dir: &Path) -> Result<(), Error> {
    std::fs::create_dir_all(dir).map_err(|e| Error::io(dir, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::io(dir, e))?;
    }
    Ok(())
}

/// Checked before anything is created, on the absolute path, so a refused
/// directory is never made.
fn refuse_inside_git(dir: &Path) -> Result<(), Error> {
    let dir = std::path::absolute(dir).map_err(|e| Error::io(dir, e))?;
    match dir.ancestors().find(|a| a.join(".git").exists()) {
        Some(repo) => Err(Error::key_file(
            &dir,
            format!(
                "the wallet directory is inside the git repository at {}",
                repo.display()
            ),
        )),
        None => Ok(()),
    }
}
