//! Fetches one NEAR testnet transaction from the archival RPC and prints
//! the SHA-256 of the raw response and whether it reports success. The
//! review uses it to re-fetch the fill's NEAR payment.
//!
//! ```text
//! cargo run --bin near_tx -- <tx-hash> <sender-account>
//! ```

use std::process::ExitCode;

use ironwood_intent_escrow::attest::{NearRpc, ARCHIVAL_RPC};
use ironwood_intent_escrow::near::ArchivalRpc;
use sha2::{Digest, Sha256};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [hash, sender] = args.as_slice() else {
        eprintln!("usage: near_tx <tx-hash> <sender-account>");
        return ExitCode::from(2);
    };
    let payload = match ArchivalRpc::new(ARCHIVAL_RPC).and_then(|rpc| rpc.tx(hash, sender)) {
        Ok(payload) => payload,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let body: serde_json::Value = serde_json::from_slice(&payload).unwrap_or_default();
    println!("rpc: {ARCHIVAL_RPC}");
    println!("payload_sha256: {}", hex::encode(Sha256::digest(&payload)));
    println!("bytes: {}", payload.len());
    match (body.pointer("/result/status"), body.get("error")) {
        (Some(status), _) => println!("status: {status}"),
        (None, Some(error)) => println!("error: {error}"),
        _ => println!("unrecognized response"),
    }
    ExitCode::SUCCESS
}
