//! The judge's check: re-fetch the two recorded runs from live testnet
//! nodes and check them, with no keys and no funds.
//!
//! ```text
//! cargo run --release --bin verify                  # live: light server + archival NEAR RPC
//! cargo run --release --bin verify -- --offline     # the same checks on the stored bytes
//! cargo run --release --bin verify -- --runs <dir>  # another records directory, default runs
//! ```
//!
//! It reads only the records directory. It fetches the four Zcash
//! transactions from the light server named in `fill.json` and the NEAR
//! payment from the archival RPC named there, prints one `PASS` or `FAIL`
//! line per check, and exits 0 only when every check passed.

use std::path::PathBuf;
use std::process::ExitCode;

use ironwood_intent_escrow::attest::NearRpc;
use ironwood_intent_escrow::light::{connect, fetch_transaction, LightClient};
use ironwood_intent_escrow::near::ArchivalRpc;
use ironwood_intent_escrow::verify::*;

struct Args {
    offline: bool,
    runs: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(usage) => {
            eprintln!("{usage}");
            return ExitCode::from(2);
        }
    };
    let mut checks = Vec::new();
    match Records::load(&args.runs) {
        Ok(records) => {
            zec_checks(&records, args.offline, &mut checks).await;
            near_checks(&records, args.offline, &mut checks);
            report(&mut checks, refund_address_check(&records));
            report(&mut checks, policy_check(&records));
            report(&mut checks, broadcast_check(&records));
        }
        Err(e) => report(
            &mut checks,
            Check::new("records loaded", Err(e.to_string())),
        ),
    }
    println!("{}", summary(&checks));
    if all_passed(&checks) || (args.offline && no_failures(&checks)) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
    let usage = "usage: verify [--offline] [--runs <dir>]".to_string();
    let mut parsed = Args {
        offline: false,
        runs: PathBuf::from("runs"),
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--offline" => parsed.offline = true,
            "--runs" => parsed.runs = args.next().ok_or_else(|| usage.clone())?.into(),
            _ => return Err(usage),
        }
    }
    Ok(parsed)
}

fn report(checks: &mut Vec<Check>, check: Check) {
    println!("{}", check.line());
    checks.push(check);
}

fn no_failures(checks: &[Check]) -> bool {
    !checks.iter().any(|c| matches!(c.outcome, Outcome::Fail(_)))
}

/// Per transaction: the stored bytes against the record's txid, the light
/// server's copy against the stored bytes and the record's height, and
/// `check_zec` on the fetched bytes (the stored bytes offline).
async fn zec_checks(records: &Records, offline: bool, checks: &mut Vec<Check>) {
    let mut client = match (offline, records.light_server()) {
        (true, _) => None,
        (false, Ok(server)) => {
            println!("connecting to {server}");
            Some(connect(server).await.map_err(|e| e.to_string()))
        }
        (false, Err(e)) => Some(Err(e.to_string())),
    };
    for tx in &ZEC_TXS {
        report(checks, txid_check(records, tx));
        let bytes = match client.as_mut() {
            None => {
                report(checks, Check::skipped(format!("{} fetched", tx.file)));
                records.bytes(tx.file).ok()
            }
            Some(connection) => {
                let fetched = fetch(records, tx, connection).await;
                report(checks, fetched_check(records, tx, &fetched));
                fetched.ok().map(|(bytes, _)| bytes)
            }
        };
        report(checks, zec_check(tx, bytes.as_deref()));
    }
}

async fn fetch(
    records: &Records,
    tx: &ZecTx,
    connection: &mut Result<LightClient, String>,
) -> Result<(Vec<u8>, u64), String> {
    let client = connection.as_mut().map_err(|e| e.clone())?;
    let server = records.light_server().map_err(|e| e.to_string())?;
    let txid = records.txid(tx).map_err(|e| e.to_string())?;
    println!("fetching {} from {server}", tx.file);
    fetch_transaction(client, server, &txid)
        .await
        .map_err(|e| e.to_string())
}

/// The stored payload against the record, the archival RPC's copy against
/// the record, and `check_payload` on the fetched payload (the stored one
/// offline).
fn near_checks(records: &Records, offline: bool, checks: &mut Vec<Check>) {
    report(checks, near_recorded_check(records));
    if offline {
        report(checks, Check::skipped("near payment fetched"));
        report(
            checks,
            near_attests_check(records, Some(&records.near_payload)),
        );
        return;
    }
    let fetched = fetch_near(records);
    report(checks, near_fetched_check(records, &fetched));
    report(checks, near_attests_check(records, fetched.as_deref().ok()));
}

fn fetch_near(records: &Records) -> Result<Vec<u8>, String> {
    let url = records.near_rpc_url().map_err(|e| e.to_string())?;
    let pointer = records.pointer().map_err(|e| e.to_string())?;
    println!("fetching the NEAR payment from {url}");
    ArchivalRpc::new(url)
        .and_then(|rpc| rpc.tx(&pointer.hash, &pointer.sender))
        .map_err(|e| e.to_string())
}
