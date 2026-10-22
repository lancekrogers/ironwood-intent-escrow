//! The escrow as a third account in the payer wallet.
//!
//! The payer process holds `escrow.fvk`, so its wallet can watch the escrow
//! address: a scan then finds each funded escrow note and keeps its Merkle
//! witness, which the escrow spend needs. The account holds no spending key;
//! the escrow is spent only through the FROST rounds.

use orchard::keys::FullViewingKey;
use zcash_address::unified::{self, Encoding};
use zcash_client_backend::data_api::locking::LockedInputPolicy;
use zcash_client_backend::data_api::wallet::input_selection::LockFilter;
use zcash_client_backend::data_api::wallet::{ConfirmationsPolicy, TargetHeight};
use zcash_client_backend::data_api::{
    Account, AccountBirthday, AccountPurpose, InputSource, TargetValue, WalletRead, WalletWrite,
};
use zcash_client_sqlite::AccountUuid;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::Parameters;
use zcash_protocol::value::Zatoshis;
use zcash_protocol::ShieldedPool;

use crate::error::Error;
use crate::note::NoteInputs;
use crate::wallet::{wallet_err, PayerWallet};

/// The unified full viewing key with `escrow.fvk` as its only component.
/// zcash_keys 0.17.0 builds one directly only behind test or unstable
/// features, so this goes through the ZIP 316 encoding.
pub fn escrow_ufvk<P: Parameters>(
    params: &P,
    fvk: &FullViewingKey,
) -> Result<UnifiedFullViewingKey, Error> {
    let items = vec![unified::Uitem::Data(unified::Fvk::Orchard(fvk.to_bytes()))];
    let encoded = unified::Ufvk::try_from_items(unified::Revision::R0, items)
        .map_err(|e| Error::Wallet(format!("escrow ufvk: {e}")))?
        .encode(&params.network_type());
    UnifiedFullViewingKey::decode(params, &encoded)
        .map_err(|e| Error::Wallet(format!("escrow ufvk: {e}")))
}

impl PayerWallet {
    /// The escrow account, imported with `birthday` the first time and found
    /// by its key afterwards. Import before the first funding transaction:
    /// a scan finds only notes mined at or after the birthday.
    pub fn ensure_escrow_account(
        &mut self,
        fvk: &FullViewingKey,
        birthday: &AccountBirthday,
    ) -> Result<AccountUuid, Error> {
        if let Some(id) = self.escrow_account(fvk)? {
            return Ok(id);
        }
        let ufvk = escrow_ufvk(&self.network(), fvk)?;
        let account = self
            .db
            .import_account_ufvk(
                "escrow",
                &ufvk,
                birthday,
                AccountPurpose::Spending { derivation: None },
                None,
            )
            .map_err(wallet_err)?;
        Ok(account.id())
    }

    /// The escrow account, if it has been imported.
    pub fn escrow_account(&self, fvk: &FullViewingKey) -> Result<Option<AccountUuid>, Error> {
        let ufvk = escrow_ufvk(&self.network(), fvk)?;
        Ok(self
            .db
            .get_account_for_ufvk(&ufvk)
            .map_err(wallet_err)?
            .map(|account| account.id()))
    }

    /// The escrow note that `fund_txid` created, with its Merkle path, once
    /// it is spendable; `no_spendable_note` until then.
    pub fn escrow_input(
        &mut self,
        fvk: &FullViewingKey,
        fund_txid: &TxId,
    ) -> Result<NoteInputs, Error> {
        let account = self
            .escrow_account(fvk)?
            .ok_or_else(|| Error::Wallet("the escrow account is not imported".into()))?;
        let Some(tip) = self.db.chain_height().map_err(wallet_err)? else {
            return Err(Error::NoSpendableNote);
        };
        let notes = self
            .db
            .select_spendable_notes(
                account,
                TargetValue::AtLeast(Zatoshis::const_from_u64(1)),
                &[ShieldedPool::Ironwood],
                TargetHeight::from(tip + 1),
                ConfirmationsPolicy::default(),
                &[],
                LockFilter::Policy(&LockedInputPolicy::Exclude),
            )
            .map_err(wallet_err)?;
        let received = notes
            .take_ironwood()
            .into_iter()
            .find(|note| note.txid() == fund_txid)
            .ok_or(Error::NoSpendableNote)?;
        self.note_input(&received, fvk.clone())
    }
}
