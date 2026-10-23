//! The expiry refund on testnet: fund a second escrow note, take a quote
//! whose expiry has passed, build the refund to a fresh address from the
//! payer wallet's refund key, sign it with the payer's and the deadline
//! device's shares, and broadcast it. The solver's share is not used.
//!
//! ```text
//! cargo run --release --bin refund
//! ```
//!
//! Run after `fill`. Before it funds anything it checks that the refund
//! guard refuses the fill's quote as `quote_paid`, by re-fetching the fill
//! claim's NEAR payment (`docs/decisions/fill-claims.md`). It also shows the
//! deadline device still refuses the fill's package. Resumable the same way
//! as `fill`.

use std::process::ExitCode;

use ironwood_intent_escrow::address::escrow_address;
use ironwood_intent_escrow::attest::{Banned, ARCHIVAL_RPC};
use ironwood_intent_escrow::checker::check_zec;
use ironwood_intent_escrow::claims::{ClaimStore, DirClaimStore};
use ironwood_intent_escrow::cosign::SignerId;
use ironwood_intent_escrow::frost::{aggregate, read_fvk, round1, FVK_FILE};
use ironwood_intent_escrow::light::{connect, LightClient, SCAN_SERVER};
use ironwood_intent_escrow::near::ArchivalRpc;
use ironwood_intent_escrow::note::{tx_bytes, EscrowSpend, NoteInputs};
use ironwood_intent_escrow::policy::{
    build_refund, check_not_paid, deadline_sign, payer_refund, refund_ovk, signing_package,
    DeadlineSigner, PayerSigner, RefundGuard,
};
use ironwood_intent_escrow::quote::Quote;
use ironwood_intent_escrow::run::*;
use ironwood_intent_escrow::view::{verify_package, CheckerView};
use ironwood_intent_escrow::wallet::PayerWallet;
use ironwood_intent_escrow::Error;
use orchard::keys::FullViewingKey;
use pczt::Pczt;
use serde::{Deserialize, Serialize};
use zcash_keys::address::UnifiedAddress;
use zcash_primitives::transaction::{Transaction, TxId};

#[derive(Default, Serialize, Deserialize)]
struct RefundState {
    #[serde(flatten)]
    funding: Funding,
    quote: Option<Quote>,
    refund_address: Option<String>,
    deadline_signed_after_expiry: Option<bool>,
    fill_claim_checked: Option<bool>,
    spend_tx: Option<String>,
    spend_height: Option<u64>,
}

/// What the refund run reads from the fill run's state: the quote, the
/// release package, and the funding transaction, whose id is a banned value
/// when the fill quote's claim is checked.
#[derive(Deserialize)]
struct FillFacts {
    quote: Quote,
    fill_pczt: String,
    fund_tx: String,
}

impl FillFacts {
    fn load(ctx: &Ctx) -> Result<Self, Error> {
        load_state(&ctx.paths.state("fill"))?
            .ok_or_else(|| Error::Wallet("run fill first: no fill state".into()))
    }

    fn fund_txid(&self) -> Result<TxId, Error> {
        Ok(parse_tx(&self.fund_tx)?.txid())
    }
}

struct Ctx {
    paths: RunPaths,
    config: RunConfig,
    client: LightClient,
    wallet: PayerWallet,
    escrow_fvk: FullViewingKey,
    escrow: UnifiedAddress,
    solver: UnifiedAddress,
    claims: DirClaimStore,
    rpc: ArchivalRpc,
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
    // Checked before funding: a refund guard that would sign the filled
    // quote fails the run before any TAZ moves.
    let fill_quote = fill_quote_refused(&ctx)?;
    if fill_quote != "quote_paid" {
        return Err(Error::Claim(format!(
            "the fill quote's refund was refused with {fill_quote}, not quote_paid"
        )));
    }
    let fund = fund_step(&mut ctx).await?;
    let fund_txid = fund.txid();
    // Once the refund exists the escrow note is spent; a rerun only checks
    // and rewrites the records.
    let inputs = match ctx.state.spend_tx {
        Some(_) => None,
        None => Some(escrow_note(&mut ctx, &fund_txid).await?),
    };
    let quote = quote_step(&mut ctx)?;
    let spend = spend_step(&mut ctx, &quote, inputs.as_ref(), &fund_txid).await?;
    let fill_refused = fill_package_still_refused(&ctx)?;
    let address = ctx.state.refund_address.clone().unwrap_or_default();
    refund_address_absent(&ctx.paths, &address)?;
    records(&ctx, &quote, &fund, &spend, fill_refused, &fill_quote)
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
        claims: DirClaimStore::new(paths.claims()),
        rpc: ArchivalRpc::new(ARCHIVAL_RPC)?,
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
    inputs: Option<&NoteInputs>,
    fund_txid: &TxId,
) -> Result<Transaction, Error> {
    let tx = match &ctx.state.spend_tx {
        Some(hex) => parse_tx(hex)?,
        None => {
            let inputs = inputs.ok_or_else(|| Error::Wallet("no escrow note to spend".into()))?;
            let tx = sign_refund(ctx, quote, inputs, fund_txid)?;
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
/// round 2 policies under the refund guard, and the aggregate, in this one
/// call.
fn sign_refund(
    ctx: &mut Ctx,
    quote: &Quote,
    inputs: &NoteInputs,
    fund_txid: &TxId,
) -> Result<Transaction, Error> {
    let now = now_unix();
    let (refund, refund_fvk) = build_and_record(ctx, quote, inputs, now)?;
    let facts = verify_package(&refund.pczt, &ctx.escrow_fvk)?;
    let (payer, deadline) = refund_signers(ctx, &refund_fvk)?;
    let (payer_nonces, payer_commitments) = round1(&share(&ctx.paths, SignerId::Payer)?);
    let (deadline_nonces, deadline_commitments) = round1(&share(&ctx.paths, SignerId::Deadline)?);
    let package = signing_package(&facts, vec![payer_commitments, deadline_commitments]);
    let guard = refund_guard(ctx, fund_txid);
    let claim = ctx.claims.claim(&quote.id)?.map_or("none", |_| "present");
    println!("fill claim for this quote: {claim}");
    let deadline_share = deadline_sign(
        &deadline,
        quote,
        &refund.pczt,
        deadline_nonces,
        &package,
        now,
        &guard,
    )?;
    println!("deadline device signed: past expiry, pays the refund key, no paid fill claim");
    let payer_share = payer_refund(
        &payer,
        quote,
        &refund.pczt,
        payer_nonces,
        &package,
        now,
        &guard,
    )?;
    println!("payer signed the refund");
    ctx.state.deadline_signed_after_expiry = Some(now >= quote.expiry_unix);
    ctx.state.fill_claim_checked = Some(true);
    let signature = aggregate(&package, &[payer_share, deadline_share], &ctx.escrow_fvk)?;
    finish_spend(refund.pczt, facts.spend_index, signature)
}

/// Builds the refund at `now` to a fresh address from the payer wallet's
/// refund key, and records that address in the state.
fn build_and_record(
    ctx: &mut Ctx,
    quote: &Quote,
    inputs: &NoteInputs,
    now: u64,
) -> Result<(EscrowSpend, FullViewingKey), Error> {
    println!(
        "quote {} expired at {}, now {now}",
        quote.id, quote.expiry_unix
    );
    let refund = build_refund(quote, inputs, &mut ctx.wallet, now)?;
    let refund_fvk = ctx.wallet.refund_fvk()?;
    ctx.state.refund_address = Some(refund_address(ctx, &refund.pczt, &refund_fvk)?);
    println!("refund built to a fresh address from the payer wallet's refund key");
    Ok((refund, refund_fvk))
}

/// The two refund signers, each with its own share.
fn refund_signers(
    ctx: &Ctx,
    refund_fvk: &FullViewingKey,
) -> Result<(PayerSigner, DeadlineSigner), Error> {
    let payer = PayerSigner::new(
        share(&ctx.paths, SignerId::Payer)?,
        ctx.escrow_fvk.clone(),
        refund_fvk.clone(),
        &ctx.solver,
    )?;
    let deadline = DeadlineSigner::new(
        share(&ctx.paths, SignerId::Deadline)?,
        ctx.escrow_fvk.clone(),
        refund_fvk.clone(),
        &ctx.solver,
    )?;
    Ok((payer, deadline))
}

/// The refund guard for the escrow note `fund_txid` funded: the claim store,
/// the archival RPC, and that note's banned values (`fill-claims.md`).
fn refund_guard<'a>(ctx: &'a Ctx, fund_txid: &TxId) -> RefundGuard<'a> {
    RefundGuard {
        claims: &ctx.claims,
        rpc: &ctx.rpc,
        banned: Banned::new()
            .address(ctx.escrow.encode(&NETWORK))
            .txid(fund_txid)
            .zatoshis(ESCROW_ZATOSHIS),
    }
}

/// The encoded address of the refund's one output, which only the refund
/// key opens. It is recorded and searched for, and never sent anywhere.
fn refund_address(ctx: &Ctx, pczt: &Pczt, refund_fvk: &FullViewingKey) -> Result<String, Error> {
    let view = CheckerView::new(pczt, &ctx.escrow_fvk, &refund_ovk(refund_fvk))?;
    let address = view
        .outputs
        .first()
        .ok_or_else(|| Error::NotARefund("no output".into()))?
        .address;
    Ok(
        UnifiedAddress::from_receivers(Some(address), None, None, None, None)
            .ok_or_else(|| Error::NotARefund("no receiver".into()))?
            .encode(&NETWORK),
    )
}

/// The refund guard on the fill's quote, which the solver paid: the claim
/// the fill run left is re-fetched from the archival RPC and must attest.
/// Returns the refusal's code, `quote_paid` when the guard works, and fails
/// if the guard would have signed.
fn fill_quote_refused(ctx: &Ctx) -> Result<String, Error> {
    let fill = FillFacts::load(ctx)?;
    let guard = refund_guard(ctx, &fill.fund_txid()?);
    println!("fill quote {}: checking its fill claim", fill.quote.id);
    match check_not_paid(&guard, &fill.quote) {
        Ok(()) => Err(Error::Claim(
            "the refund guard would sign a refund of the filled quote".into(),
        )),
        Err(e) => {
            let code = e
                .to_string()
                .split(':')
                .next()
                .unwrap_or_default()
                .to_string();
            println!("fill quote {}: refund refused, {code}", fill.quote.id);
            Ok(code)
        }
    }
}

/// The deadline device still refuses the fill's package, now and after
/// the fill quote's expiry alike.
fn fill_package_still_refused(ctx: &Ctx) -> Result<bool, Error> {
    let fill = FillFacts::load(ctx)?;
    let bytes = hex::decode(&fill.fill_pczt).map_err(|e| Error::Wallet(e.to_string()))?;
    let pczt = Pczt::parse(&bytes).map_err(|e| Error::Pczt(format!("{e:?}")))?;
    let facts = verify_package(&pczt, &ctx.escrow_fvk)?;
    let deadline = DeadlineSigner::new(
        share(&ctx.paths, SignerId::Deadline)?,
        ctx.escrow_fvk.clone(),
        ctx.wallet.refund_fvk()?,
        &ctx.solver,
    )?;
    let guard = refund_guard(ctx, &fill.fund_txid()?);
    let (nonces, deadline_commitments) = round1(&share(&ctx.paths, SignerId::Deadline)?);
    let (_, payer_commitments) = round1(&share(&ctx.paths, SignerId::Payer)?);
    let package = signing_package(&facts, vec![payer_commitments, deadline_commitments]);
    let result = deadline_sign(
        &deadline,
        &fill.quote,
        &pczt,
        nonces,
        &package,
        u64::MAX,
        &guard,
    );
    let refused = matches!(result, Err(Error::RefusedRelease));
    println!("fill release package: deadline device refused, refused_release = {refused}");
    Ok(refused)
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
    fill_quote: &str,
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
        "fill_claim_checked": ctx.state.fill_claim_checked == Some(true),
        "fill_quote_refund_refused": fill_quote,
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
