use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};

use ed25519_compact::Signature;

use crate::balance_cache::BalanceCache;
use crate::constants::{MIN_AMOUNT_CRUZBITS, MIN_FEE_CRUZBITS};
use crate::ledger_disk::LedgerDisk;
use crate::processor::Processor;
use crate::transaction::{Transaction, TransactionID};
use crate::transaction_queue::{TransactionQueue, TransactionQueueError};

/// An in-memory FIFO implementation of the TransactionQueue interface.
pub struct TransactionQueueMemory {
    tx_map: RwLock<HashMap<TransactionID, Transaction>>,
    tx_queue: RwLock<VecDeque<TransactionID>>,
    balance_cache: RwLock<BalanceCache>,
}

impl TransactionQueueMemory {
    /// Returns a new TransactionQueueMemory instance.
    pub fn new(ledger: Arc<LedgerDisk>) -> Arc<Self> {
        // don't accept transactions that would leave an unspendable balance with this node
        let min_balance = MIN_AMOUNT_CRUZBITS + MIN_FEE_CRUZBITS;

        Arc::new(Self {
            tx_map: RwLock::new(HashMap::new()),
            tx_queue: RwLock::new(VecDeque::new()),
            balance_cache: RwLock::new(BalanceCache::new(ledger, min_balance)),
        })
    }

    /// Rebuild the balance cache and remove transactions now in violation
    fn reprocess_queue(&self, height: u64) -> Result<(), TransactionQueueError> {
        // invalidate the cache
        let mut balance_cache = self.balance_cache.write().unwrap();
        balance_cache.reset();

        // remove invalidated transactions from the queue
        let mut tx_ids_to_remove = Vec::new();
        let mut tx_queue = self.tx_queue.write().unwrap();
        let mut tx_map = self.tx_map.write().unwrap();

        for tx_id in tx_queue.iter() {
            let tx = tx_map.get(tx_id).expect("tx queue to contain id");

            // check that the series would still be valid
            if !Processor::check_transaction_series(tx, height + 1) ||
                // check maturity and expiration if included in the next block
                !tx.is_mature(height + 1) || tx.is_expired(height + 1) ||
                // don't re-mine any now unconfirmed spam
                tx.fee < Some(MIN_FEE_CRUZBITS) || tx.amount < MIN_AMOUNT_CRUZBITS
            {
                // transaction has been invalidated. add it for removal and continue
                tx_ids_to_remove.push(*tx_id);
                continue;
            }

            // check balance
            let ok = balance_cache.apply(tx)?;
            if !ok {
                // transaction has been invalidated. add it for removal and continue
                tx_ids_to_remove.push(*tx_id);
                continue;
            }
        }

        // only retain elements that haven't been selected for removal
        tx_map.retain(|tx_id, _tx| !tx_ids_to_remove.contains(tx_id));
        tx_queue.retain(|tx_id| !tx_ids_to_remove.contains(tx_id));

        Ok(())
    }
}

impl TransactionQueue for TransactionQueueMemory {
    /// Adds the transaction to the queue. Returns true if the transaction was added to the queue on this call.
    fn add(&self, id: &TransactionID, tx: &Transaction) -> Result<bool, TransactionQueueError> {
        let mut tx_map = self.tx_map.write().unwrap();

        if tx_map.contains_key(id) {
            return Ok(false);
        }

        // check sender balance and update sender and receiver balances
        let mut balance_cache = self.balance_cache.write().unwrap();
        if !balance_cache.apply(tx)? {
            // insufficient sender balance
            return Err(TransactionQueueError::SenderBalanceInsufficient(
                *id,
                tx.from.expect("transaction should have a sender"),
            ));
        }

        // add to the back of the queue
        let mut tx_queue = self.tx_queue.write().unwrap();
        tx_queue.push_back(*id);
        tx_map.insert(*id, tx.clone());

        Ok(true)
    }

    /// Returns the queue length.
    fn len(&self) -> usize {
        self.tx_queue.read().unwrap().len()
    }

    /// Returns true if the queue has a length of 0.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns transactions in the queue for the miner.
    fn get(&self, limit: usize) -> Vec<Transaction> {
        let tx_queue = self.tx_queue.read().unwrap();
        let tx_map = self.tx_map.read().unwrap();
        tx_queue
            .iter()
            .take(limit)
            .filter_map(|tx_id| tx_map.get(tx_id).cloned())
            .collect()
    }

    /// Adds a batch of transactions to the queue (a block has been disconnected.)
    fn add_batch(&self, ids: &[TransactionID], txs: &[Transaction]) {
        let mut tx_queue = self.tx_queue.write().unwrap();
        let mut tx_map = self.tx_map.write().unwrap();

        // add to front in reverse order.
        // we want formerly confirmed transactions to have the highest
        // priority for getting into the next block.
        for (i, tx) in txs.iter().rev().enumerate() {
            let tx_id = ids[i];

            if tx_map.contains_key(&tx_id) {
                if let Some(index) = tx_queue
                    .iter()
                    .position(|queue_tx_id| *queue_tx_id == tx_id)
                {
                    // remove it from its current position
                    tx_queue.remove(index);
                }
            }

            tx_queue.push_front(tx_id);
            tx_map.insert(tx_id, tx.clone());
        }

        // we don't want to invalidate anything based on maturity/expiration/balance yet.
        // if we're disconnecting a block we're going to be connecting some shortly.
    }

    /// Removes a batch of transactions from the queue (a block has been connected.)
    /// "height" is the block chain height after this connection.
    /// "more" indicates if more connections are coming.
    fn remove_batch(
        &self,
        ids: &[TransactionID],
        height: u64,
        more: bool,
    ) -> Result<(), TransactionQueueError> {
        // create a scope for the guards
        {
            let mut tx_map = self.tx_map.write().unwrap();

            // remove the transactions from the queue
            let mut tx_queue = self.tx_queue.write().unwrap();
            tx_queue.retain(|tx_id| !ids.contains(tx_id));
            tx_map.retain(|tx_id, _tx| !ids.contains(tx_id));
        }

        if more {
            // we don't want to invalidate anything based on series/maturity/expiration/balance
            // until we're done connecting all of the blocks we intend to
            Ok(())
        } else {
            self.reprocess_queue(height)
        }
    }

    /// Returns true if the given transaction is in the queue.
    fn exists(&self, id: &TransactionID) -> bool {
        self.tx_map.read().unwrap().contains_key(id)
    }

    /// Return true if the given transaction is in the queue and contains the given signature.
    fn exists_signed(&self, id: &TransactionID, signature: Signature) -> bool {
        if let Some(tx) = self.tx_map.read().unwrap().get(id) {
            tx.signature.expect("transaction should have a signature") == signature
        } else {
            false
        }
    }
}
