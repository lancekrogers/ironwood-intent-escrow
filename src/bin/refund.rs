//! The expiry refund on testnet: fund a second escrow note, take a quote
//! whose expiry has passed, build the refund to a fresh address from the
//! payer wallet's refund key, sign it with the payer's and the deadline
//! device's shares, and broadcast it. The solver's share is not used.
//!
//! ```text
//! cargo run --bin refund
//! ```
//!
//! Run after `fill`: it also shows the deadline device still refuses the
//! fill's package. Resumable the same way as `fill`.

use std::process::ExitCode;

use ironwood_intent_escrow::address::escrow_address;
use ironwood_intent_escrow::checker::check_zec;
use ironwood_intent_escrow::cosign::SignerId;
use ironwood_intent_escrow::frost::{aggregate, read_fvk, round1, FVK_FILE};
use ironwood_intent_escrow::light::{connect, LightClient, SCAN_SERVER};
use ironwood_intent_escrow::note::{tx_bytes, NoteInputs};
use ironwood_intent_escrow::policy::{
    build_refund, deadline_sign, payer_refund, refund_ovk, signing_package, DeadlineSigner,
    PayerSigner,
};
use ironwood_intent_escrow::quote::Quote;
use ironwood_intent_escrow::run::*;
use ironwood_intent_escrow::view::{verify_package, CheckerView};
use ironwood_intent_escrow::wallet::PayerWallet;
use ironwood_intent_escrow::Error;
use orchard::keys::FullViewingKey;
use serde::{Deserialize, Serialize};
use zcash_keys::address::UnifiedAddress;
use zcash_primitives::transaction::Transaction;

#[derive(Default, Serialize, Deserialize)]
struct RefundState {
    #[serde(flatten)]
    funding: Funding,
    quote: Option<Quote>,
    refund_address: Option<String>,
    deadline_signed_after_expiry: Option<bool>,
    spend_tx: Option<String>,
    spend_height: Option<u64>,
}

/// The two fields the refund run reads from the fill run's state.
#[derive(Deserialize)]
struct FillFacts {
    quote: Quote,
    fill_pczt: String,
}

struct Ctx {
    paths: RunPaths,
    config: RunConfig,
    client: LightClient,
    wallet: PayerWallet,
    escrow_fvk: FullViewingKey,
    escrow: UnifiedAddress,
    solver: UnifiedAddress,
    state: RefundState,
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
    let fvk = ctx.escrow_fvk.clone();
    let inputs = wait_for(&mut ctx.wallet, &mut ctx.client, "the escrow note", |w| {
        w.escrow_input(&fvk, &fund_txid)
    })
    .await?;
    let quote = quote_step(&mut ctx)?;
    let spend = spend_step(&mut ctx, &quote, &inputs).await?;
    let fill_refused = fill_package_still_refused(&ctx)?;
    let address = ctx.state.refund_address.clone().unwrap_or_default();
    refund_address_absent(&ctx.paths, &address)?;
    records(&ctx, &quote, &fund, &spend, fill_refused)
}

async fn setup() -> Result<Ctx, Error> {
    let paths = RunPaths::default_locations()?;
    let config = RunConfig::load(&paths)?;
    let mut client = connect(SCAN_SERVER).await?;
    let escrow_fvk = read_fvk(&paths.holder(SignerId::Payer).join(FVK_FILE))?;
    let solver = solver_address(&paths, &mut client).await?;
    let wallet = PayerWallet::open(&paths.payer_wallet(), NETWORK)?;
    if wallet.escrow_account(&escrow_fvk)?.is_none() {
        return Err(Error::Wallet(
            "run fill first: the escrow account is not imported".into(),
        ));
    }
    let state = load_state(&paths.state("refund"))?.unwrap_or_default();
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
    let state_path = ctx.paths.state("refund");
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

/// A quote whose expiry is already past.
fn quote_step(ctx: &mut Ctx) -> Result<Quote, Error> {
    if let Some(quote) = &ctx.state.quote {
        return Ok(quote.clone());
    }
    let quote = Quote::new(
        &ctx.config.payer_account,
        WNEAR,
        QUOTE_YOCTO,
        now_unix() - 60,
    )?;
    write_record(&ctx.paths, "refund.quote.json", quote.to_json()?.as_bytes())?;
    ctx.state.quote = Some(quote.clone());
    save(ctx)?;
    Ok(quote)
}

async fn spend_step(
    ctx: &mut Ctx,
    quote: &Quote,
    inputs: &NoteInputs,
) -> Result<Transaction, Error> {
    let tx = match &ctx.state.spend_tx {
        Some(hex) => parse_tx(hex)?,
        None => {
            let tx = sign_refund(ctx, quote, inputs)?;
            check_zec(&tx_bytes(&tx)?)?;
            ctx.state.spend_tx = Some(hex::encode(tx_bytes(&tx)?));
            save(ctx)?;
            tx
        }
    };
    if ctx.state.spend_height.is_none() {
        let height = broadcast_and_wait(&mut ctx.client, &tx_bytes(&tx)?, &tx.txid()).await?;
        println!("refund {} mined at {height}", tx.txid());
        ctx.state.spend_height = Some(height);
        save(ctx)?;
    }
    Ok(tx)
}

/// `build_refund`, round 1 for the payer and the deadline device, both
/// round 2 policies, and the aggregate, in this one call.
fn sign_refund(ctx: &mut Ctx, quote: &Quote, inputs: &NoteInputs) -> Result<Transaction, Error> {
    let now = now_unix();
    let refund = build_refund(quote, inputs, &mut ctx.wallet, now)?;
    let refund_fvk = ctx.wallet.refund_fvk()?;
    let view = CheckerView::new(&refund.pczt, &ctx.escrow_fvk, &refund_ovk(&refund_fvk))?;
    let address = view
        .outputs
        .first()
        .ok_or_else(|| Error::NotARefund("no output".into()))?
        .address;
    let encoded = UnifiedAddress::from_receivers(Some(address), None, None, None, None)
        .ok_or_else(|| Error::NotARefund("no receiver".into()))?
        .encode(&NETWORK);
    ctx.state.refund_address = Some(encoded);

    let facts = verify_package(&refund.pczt, &ctx.escrow_fvk)?;
    let payer = PayerSigner::new(
        share(&ctx.paths, SignerId::Payer)?,
        ctx.escrow_fvk.clone(),
        refund_fvk.clone(),
        &ctx.solver,
    )?;
    let deadline = DeadlineSigner::new(
        share(&ctx.paths, SignerId::Deadline)?,
        ctx.escrow_fvk.clone(),
        refund_fvk,
        &ctx.solver,
    )?;
    let (payer_nonces, payer_commitments) = round1(&share(&ctx.paths, SignerId::Payer)?);
    let (deadline_nonces, deadline_commitments) = round1(&share(&ctx.paths, SignerId::Deadline)?);
    let package = signing_package(&facts, vec![payer_commitments, deadline_commitments]);
    let deadline_share = deadline_sign(
        &deadline,
        quote,
        &refund.pczt,
        deadline_nonces,
        &package,
        now,
    )?;
    ctx.state.deadline_signed_after_expiry = Some(now >= quote.expiry_unix);
    let payer_share = payer_refund(&payer, quote, &refund.pczt, payer_nonces, &package, now)?;
    let signature = aggregate(&package, &[payer_share, deadline_share], &ctx.escrow_fvk)?;
    finish_spend(refund.pczt, facts.spend_index, signature)
}

/// The deadline device still refuses the fill's package, now and after
/// the fill quote's expiry alike.
fn fill_package_still_refused(ctx: &Ctx) -> Result<bool, Error> {
    let fill: FillFacts = load_state(&ctx.paths.state("fill"))?
        .ok_or_else(|| Error::Wallet("run fill first: no fill state".into()))?;
    let bytes = hex::decode(&fill.fill_pczt).map_err(|e| Error::Wallet(e.to_string()))?;
    let pczt = pczt::Pczt::parse(&bytes).map_err(|e| Error::Pczt(format!("{e:?}")))?;
    let facts = verify_package(&pczt, &ctx.escrow_fvk)?;
    let deadline = DeadlineSigner::new(
        share(&ctx.paths, SignerId::Deadline)?,
        ctx.escrow_fvk.clone(),
        ctx.wallet.refund_fvk()?,
        &ctx.solver,
    )?;
    let (nonces, deadline_commitments) = round1(&share(&ctx.paths, SignerId::Deadline)?);
    let (_, payer_commitments) = round1(&share(&ctx.paths, SignerId::Payer)?);
    let package = signing_package(&facts, vec![payer_commitments, deadline_commitments]);
    let result = deadline_sign(&deadline, &fill.quote, &pczt, nonces, &package, u64::MAX);
    Ok(matches!(result, Err(Error::RefusedRelease)))
}

/// The refund address must not appear in the fill record, the NEAR payload,
/// or either quote. The run fails if it does.
fn refund_address_absent(paths: &RunPaths, address: &str) -> Result<(), Error> {
    if address.is_empty() {
        return Err(Error::NotARefund("no refund address recorded".into()));
    }
    for name in [
        "fill.json",
        "fill.near.json",
        "fill.quote.json",
        "refund.quote.json",
    ] {
        let path = paths.runs.join(name);
        let bytes = std::fs::read(&path).map_err(|e| Error::io(&path, e))?;
        if bytes
            .windows(address.len())
            .any(|w| w == address.as_bytes())
        {
            return Err(Error::BannedField(format!(
                "the refund address appears in {name}"
            )));
        }
    }
    Ok(())
}

fn records(
    ctx: &Ctx,
    quote: &Quote,
    fund: &Transaction,
    spend: &Transaction,
    fill_refused: bool,
) -> Result<(), Error> {
    let quote_bytes = std::fs::read(ctx.paths.runs.join("refund.quote.json"))
        .map_err(|e| Error::io(ctx.paths.runs.join("refund.quote.json"), e))?;
    let address = ctx.state.refund_address.clone().unwrap_or_default();
    let in_quote = quote_bytes
        .windows(address.len().max(1))
        .any(|w| w == address.as_bytes());
    let record = serde_json::json!({
        "quote_id": quote.id.to_hex(),
        "escrow_address": ctx.escrow.encode(&NETWORK),
        "escrow_zatoshis": ESCROW_ZATOSHIS,
        "fund_txid": txid_hex(&fund.txid()),
        "fund_mined_height": ctx.state.funding.fund_height,
        "spend_txid": txid_hex(&spend.txid()),
        "spend_mined_height": ctx.state.spend_height,
        "refund_address": address,
        "refund_address_in_quote": in_quote,
        "fill_package_still_refused": fill_refused,
        "deadline_signed_after_expiry": ctx.state.deadline_signed_after_expiry == Some(true),
        "light_server": SCAN_SERVER,
        "broadcast": "sent",
    });
    let json = serde_json::to_string_pretty(&record).map_err(|e| Error::Wallet(e.to_string()))?;
    write_record(&ctx.paths, "refund.json", json.as_bytes())?;
    write_record(&ctx.paths, "refund.fund.tx", &tx_bytes(fund)?)?;
    write_record(&ctx.paths, "refund.spend.tx", &tx_bytes(spend)?)?;
    println!("records written to {}", ctx.paths.runs.display());
    Ok(())
}

fn save(ctx: &Ctx) -> Result<(), Error> {
    save_state(&ctx.paths.state("refund"), &ctx.state)
}
