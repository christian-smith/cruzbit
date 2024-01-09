use ed25519_compact::{PublicKey, Signature};
use thiserror::Error;

use crate::balance_cache::BalanceCacheError;
use crate::transaction::{AsBase64, Transaction, TransactionID};

/// An interface to a queue of transactions to be confirmed.
pub trait TransactionQueue {
    /// Adds the transaction to the queue. Returns true if the transaction was added to the queue on this call.
    fn add(&self, id: &TransactionID, tx: &Transaction) -> Result<bool, TransactionQueueError>;

    /// Adds a batch of transactions to the queue (a block has been disconnected.)
    /// "height" is the block chain height after this disconnection.
    fn add_batch(&self, ids: &[TransactionID], txs: &[Transaction]);

    /// Removes a batch of transactions from the queue (a block has been connected.)
    /// "height" is the block chain height after this connection.
    /// "more" indicates if more connections are coming.
    fn remove_batch(
        &self,
        ids: &[TransactionID],
        height: u64,
        more: bool,
    ) -> Result<(), TransactionQueueError>;

    /// Returns transactions in the queue for the miner.
    fn get(&self, limit: usize) -> Vec<Transaction>;

    /// Returns true if the given transaction is in the queue.
    fn exists(&self, id: &TransactionID) -> bool;

    /// Returns true if the given transaction is in the queue and contains the given signature.
    fn exists_signed(&self, id: &TransactionID, signature: Signature) -> bool;

    /// Returns the queue length.
    fn len(&self) -> usize;

    /// Returns true if the queue has a length of 0.
    fn is_empty(&self) -> bool;
}

#[derive(Error, Debug)]
pub enum TransactionQueueError {
    #[error("transaction {0} sender {} has insufficient balance", .1.as_base64())]
    SenderBalanceInsufficient(TransactionID, PublicKey),

    #[error("balance cache")]
    BalanceCache(#[from] BalanceCacheError),
}
