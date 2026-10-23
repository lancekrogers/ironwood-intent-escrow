//! The fill run on testnet: fund the escrow, have the solver pay the quote
//! on NEAR, re-fetch that payment from the archival RPC, sign the release
//! with the payer's and the solver's shares, and broadcast it.
//!
//! ```text
//! cargo run --release --bin fill
//! ```
//!
//! Resumable: state is saved under `~/.ironwood-intent-escrow/testnet/runs/`
//! before every broadcast or payment, so a rerun continues and never funds
//! or pays twice. The records go to `runs/` in the repository.

use std::process::ExitCode;

use ironwood_intent_escrow::address::escrow_address;
use ironwood_intent_escrow::attest::{Attestation, Banned, NearTxPointer, ARCHIVAL_RPC};
use ironwood_intent_escrow::checker::check_zec;
use ironwood_intent_escrow::cosign::SignerId;
use ironwood_intent_escrow::frost::{aggregate, round1};
use ironwood_intent_escrow::light::{connect, LightClient, SCAN_SERVER};
use ironwood_intent_escrow::near::ArchivalRpc;
use ironwood_intent_escrow::note::{
    escrow_spend_fee, spend_pczt, tx_bytes, NoteInputs, SpendOutput,
};
use ironwood_intent_escrow::policy::{
    deadline_sign, payer_release, release_ovk, signing_package, solver_release, DeadlineSigner,
    PayerSigner, SolverSigner,
};
use ironwood_intent_escrow::quote::Quote;
use ironwood_intent_escrow::run::*;
use ironwood_intent_escrow::view::{verify_package, PackageFacts};
use ironwood_intent_escrow::wallet::PayerWallet;
use ironwood_intent_escrow::Error;
use orchard::keys::FullViewingKey;
use pczt::Pczt;
use serde::{Deserialize, Serialize};
use zcash_keys::address::UnifiedAddress;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::value::Zatoshis;

#[derive(Default, Serialize, Deserialize)]
struct FillState {
    quote: Option<Quote>,
    #[serde(flatten)]
    funding: Funding,
    near: Option<(String, String)>,
    near_payload: Option<String>,
    deadline_refused_release: Option<bool>,
    fill_pczt: Option<String>,
    spend_tx: Option<String>,
    spend_height: Option<u64>,
}

struct Ctx {
    paths: RunPaths,
    config: RunConfig,
    client: LightClient,
    wallet: PayerWallet,
    escrow_fvk: FullViewingKey,
    escrow: UnifiedAddress,
    solver: UnifiedAddress,
    state: FillState,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Error> {
    let mut ctx = setup().await?;
    let fund = fund_step(&mut ctx).await?;
    let fund_txid = fund.txid();
    // Once the spend exists the escrow note is spent, so there is nothing to
    // wait for; a rerun only rewrites the records.
    let inputs = match ctx.state.spend_tx {
        Some(_) => None,
        None => Some(escrow_note(&mut ctx, &fund_txid).await?),
    };
    let quote = quote_step(&mut ctx)?;
    let pointer = near_step(&mut ctx, &quote)?;
    let spend = spend_step(&mut ctx, &quote, &pointer, inputs.as_ref(), &fund_txid).await?;
    records(&ctx, &quote, &pointer, &fund, &spend)
}

async fn escrow_note(ctx: &mut Ctx, fund_txid: &TxId) -> Result<NoteInputs, Error> {
    let fvk = ctx.escrow_fvk.clone();
    wait_for(&mut ctx.wallet, &mut ctx.client, "the escrow note", |w| {
        w.escrow_input(&fvk, fund_txid)
    })
    .await
}

async fn setup() -> Result<Ctx, Error> {
    let paths = RunPaths::default_locations()?;
    let config = RunConfig::load(&paths)?;
    let mut client = connect(SCAN_SERVER).await?;
    let escrow_fvk = ensure_escrow_keys(&paths)?;
    let solver = solver_address(&paths, &mut client).await?;
    write_record(
        &paths,
        "solver_address.txt",
        format!("{}\n", solver.encode(&NETWORK)).as_bytes(),
    )?;
    let mut wallet = PayerWallet::open(&paths.payer_wallet(), NETWORK)?;
    if wallet.escrow_account(&escrow_fvk)?.is_none() {
        let birthday = tip_birthday(&mut client).await?;
        wallet.ensure_escrow_account(&escrow_fvk, &birthday)?;
    }
    let state = load_state(&paths.state("fill"))?.unwrap_or_default();
    Ok(Ctx {
        escrow: escrow_address(&escrow_fvk),
        paths,
        config,
        client,
        wallet,
        escrow_fvk,
        solver,
        state,
    })
}

async fn fund_step(ctx: &mut Ctx) -> Result<Transaction, Error> {
    let state_path = ctx.paths.state("fill");
    let mut funding = ctx.state.funding.clone();
    let tx = fund_once(
        &mut funding,
        &mut ctx.wallet,
        &mut ctx.client,
        &ctx.escrow,
        |f| {
            ctx.state.funding = f.clone();
            save_state(&state_path, &ctx.state)
        },
    )
    .await;
    ctx.state.funding = funding;
    tx
}

fn quote_step(ctx: &mut Ctx) -> Result<Quote, Error> {
    if let Some(quote) = &ctx.state.quote {
        return Ok(quote.clone());
    }
    let quote = Quote::new(
        &ctx.config.payer_account,
        WNEAR,
        QUOTE_YOCTO,
        now_unix() + 86_400,
    )?;
    if quote.amount.to_string() == ESCROW_ZATOSHIS.to_string() {
        return Err(Error::InvalidQuote(
            "the quote amount equals the zatoshi amount".into(),
        ));
    }
    write_record(&ctx.paths, "fill.quote.json", quote.to_json()?.as_bytes())?;
    ctx.state.quote = Some(quote.clone());
    save(ctx)?;
    Ok(quote)
}

/// The solver process pays on NEAR once and hands back only the pointer.
fn near_step(ctx: &mut Ctx, quote: &Quote) -> Result<NearTxPointer, Error> {
    if let Some((hash, sender)) = &ctx.state.near {
        return Ok(NearTxPointer {
            hash: hash.clone(),
            sender: sender.clone(),
        });
    }
    let pointer = near_pay(&ctx.config, quote)?;
    println!("near payment {} from {}", pointer.hash, pointer.sender);
    ctx.state.near = Some((pointer.hash.clone(), pointer.sender.clone()));
    save(ctx)?;
    Ok(pointer)
}

async fn spend_step(
    ctx: &mut Ctx,
    quote: &Quote,
    pointer: &NearTxPointer,
    inputs: Option<&NoteInputs>,
    fund_txid: &TxId,
) -> Result<(Transaction, Attestation), Error> {
    let rpc = ArchivalRpc::new(ARCHIVAL_RPC)?;
    let banned = Banned::new()
        .address(ctx.escrow.encode(&NETWORK))
        .txid(fund_txid)
        .zatoshis(ESCROW_ZATOSHIS);
    let attestation = attest_when_final(quote, pointer, &banned, &rpc).await?;
    if let Some(hex) = &ctx.state.spend_tx {
        return Ok((parse_tx(hex)?, attestation));
    }
    let inputs = inputs.ok_or_else(|| Error::Wallet("no escrow note to spend".into()))?;
    let (tx, attestation) = sign_release(ctx, quote, pointer, inputs, &banned, &rpc)?;
    check_zec(&tx_bytes(&tx)?)?;
    ctx.state.spend_tx = Some(hex::encode(tx_bytes(&tx)?));
    ctx.state.near_payload = Some(hex::encode(&attestation.payload));
    save(ctx)?;
    let height = broadcast_and_wait(&mut ctx.client, &tx_bytes(&tx)?, &tx.txid()).await?;
    println!("spend {} mined at {height}", tx.txid());
    ctx.state.spend_height = Some(height);
    save(ctx)?;
    Ok((tx, attestation))
}

/// The release package, the deadline device's refusal of it, then the
/// payer's and the solver's round 2 and the aggregate, all in this one
/// call; nonces never persist.
fn sign_release(
    ctx: &mut Ctx,
    quote: &Quote,
    pointer: &NearTxPointer,
    inputs: &NoteInputs,
    banned: &Banned,
    rpc: &ArchivalRpc,
) -> Result<(Transaction, Attestation), Error> {
    let outputs = release_outputs(ctx, inputs)?;
    let release_key = release_ovk(&ctx.escrow_fvk);
    let spend = spend_pczt(NETWORK, inputs, &outputs, &quote.id, &release_key)?;
    let facts = verify_package(&spend.pczt, &ctx.escrow_fvk)?;
    let refused = deadline_refuses(ctx, quote, &spend.pczt, &facts)?;
    ctx.state.deadline_refused_release = Some(refused);
    let pczt_bytes = spend.pczt.clone().serialize();
    let pczt_bytes = pczt_bytes.map_err(|e| Error::Pczt(format!("{e:?}")))?;
    ctx.state.fill_pczt = Some(hex::encode(pczt_bytes));

    let payer = PayerSigner::new(
        share(&ctx.paths, SignerId::Payer)?,
        ctx.escrow_fvk.clone(),
        ctx.wallet.refund_fvk()?,
        &ctx.solver,
    )?;
    let solver = SolverSigner::new(
        share(&ctx.paths, SignerId::Solver)?,
        ctx.escrow_fvk.clone(),
        &ctx.solver,
    )?;
    let (payer_nonces, payer_commitments) = round1(&share(&ctx.paths, SignerId::Payer)?);
    let (solver_nonces, solver_commitments) = round1(&share(&ctx.paths, SignerId::Solver)?);
    let package = signing_package(&facts, vec![payer_commitments, solver_commitments]);
    let (payer_share, attestation) = payer_release(
        &payer,
        quote,
        &spend.pczt,
        pointer,
        banned,
        rpc,
        payer_nonces,
        &package,
    )?;
    let solver_share = solver_release(&solver, quote, &spend.pczt, solver_nonces, &package)?;
    let signature = aggregate(&package, &[payer_share, solver_share], &ctx.escrow_fvk)?;
    let tx = finish_spend(spend.pczt, facts.spend_index, signature)?;
    Ok((tx, attestation))
}

/// The whole escrow note, less the fee, to the solver.
fn release_outputs(ctx: &Ctx, inputs: &NoteInputs) -> Result<[SpendOutput; 1], Error> {
    let fee = escrow_spend_fee(NETWORK, inputs, 1)?.into_u64();
    Ok([SpendOutput {
        address: ctx.solver.clone(),
        value: Zatoshis::const_from_u64(ESCROW_ZATOSHIS - fee),
    }])
}

/// Whether the deadline device returns `refused_release` for the release.
fn deadline_refuses(
    ctx: &Ctx,
    quote: &Quote,
    pczt: &Pczt,
    facts: &PackageFacts,
) -> Result<bool, Error> {
    let deadline = DeadlineSigner::new(
        share(&ctx.paths, SignerId::Deadline)?,
        ctx.escrow_fvk.clone(),
        ctx.wallet.refund_fvk()?,
        &ctx.solver,
    )?;
    let (nonces, deadline_commitments) = round1(&share(&ctx.paths, SignerId::Deadline)?);
    let (_, payer_commitments) = round1(&share(&ctx.paths, SignerId::Payer)?);
    let package = signing_package(facts, vec![payer_commitments, deadline_commitments]);
    let result = deadline_sign(&deadline, quote, pczt, nonces, &package, now_unix());
    Ok(matches!(result, Err(Error::RefusedRelease)))
}

fn records(
    ctx: &Ctx,
    quote: &Quote,
    pointer: &NearTxPointer,
    fund: &Transaction,
    spend: &(Transaction, Attestation),
) -> Result<(), Error> {
    let (spend_tx, attestation) = spend;
    let payload = ctx
        .state
        .near_payload
        .as_deref()
        .map(hex::decode)
        .transpose()
        .map_err(|e| Error::Wallet(e.to_string()))?
        .unwrap_or_else(|| attestation.payload.clone());
    let record = serde_json::json!({
        "quote_id": quote.id.to_hex(),
        "escrow_address": ctx.escrow.encode(&NETWORK),
        "escrow_zatoshis": ESCROW_ZATOSHIS,
        "fund_txid": txid_hex(&fund.txid()),
        "fund_mined_height": ctx.state.funding.fund_height,
        "spend_txid": txid_hex(&spend_tx.txid()),
        "spend_mined_height": ctx.state.spend_height,
        "near_rpc_url": ARCHIVAL_RPC,
        "near_tx_hash": pointer.hash,
        "near_sender": pointer.sender,
        "near_payload_sha256": hex::encode(sha256(&payload)),
        "deadline_refused_release": ctx.state.deadline_refused_release == Some(true),
        "light_server": SCAN_SERVER,
        "broadcast": "sent",
    });
    write_record(
        &ctx.paths,
        "fill.json",
        serde_json::to_string_pretty(&record)
            .map_err(|e| Error::Wallet(e.to_string()))?
            .as_bytes(),
    )?;
    write_record(&ctx.paths, "fill.fund.tx", &tx_bytes(fund)?)?;
    write_record(&ctx.paths, "fill.spend.tx", &tx_bytes(spend_tx)?)?;
    write_record(&ctx.paths, "fill.near.json", &payload)?;
    println!("records written to {}", ctx.paths.runs.display());
    Ok(())
}

fn save(ctx: &Ctx) -> Result<(), Error> {
    save_state(&ctx.paths.state("fill"), &ctx.state)
}
