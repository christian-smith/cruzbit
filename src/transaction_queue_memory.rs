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
    inner: RwLock<Inner>,
}

struct Inner {
    tx_map: HashMap<TransactionID, Transaction>,
    tx_queue: VecDeque<TransactionID>,
    balance_cache: BalanceCache,
}

impl TransactionQueueMemory {
    /// Returns a new TransactionQueueMemory instance.
    pub fn new(ledger: Arc<LedgerDisk>) -> Arc<Self> {
        // don't accept transactions that would leave an unspendable balance with this node
        let min_balance = MIN_AMOUNT_CRUZBITS + MIN_FEE_CRUZBITS;

        Arc::new(Self {
            inner: RwLock::new(Inner {
                tx_map: HashMap::new(),
                tx_queue: VecDeque::new(),
                balance_cache: BalanceCache::new(ledger, min_balance),
            }),
        })
    }

    /// Rebuild the balance cache and remove transactions now in violation
    fn reprocess_queue(inner: &mut Inner, height: u64) -> Result<(), TransactionQueueError> {
        // invalidate the cache
        inner.balance_cache.reset();

        // remove invalidated transactions from the queue
        let mut tx_ids_to_remove = Vec::new();

        for tx_id in inner.tx_queue.iter() {
            let tx = inner.tx_map.get(tx_id).expect("tx queue to contain id");

            // check that the series would still be valid
            if !Processor::check_transaction_series(tx, height + 1) ||
                // check maturity and expiration if included in the next block
                !tx.is_mature(height + 1) || tx.is_expired(height + 1) ||
                // don't re-mine any now unconfirmed spam
                tx.fee.unwrap_or(0) < MIN_FEE_CRUZBITS || tx.amount < MIN_AMOUNT_CRUZBITS
            {
                // transaction has been invalidated. add it for removal and continue
                tx_ids_to_remove.push(*tx_id);
                continue;
            }

            // check balance
            let ok = inner.balance_cache.apply(tx)?;
            if !ok {
                // transaction has been invalidated. add it for removal and continue
                tx_ids_to_remove.push(*tx_id);
                continue;
            }
        }

        // only retain elements that haven't been selected for removal
        inner
            .tx_map
            .retain(|tx_id, _tx| !tx_ids_to_remove.contains(tx_id));
        inner
            .tx_queue
            .retain(|tx_id| !tx_ids_to_remove.contains(tx_id));

        Ok(())
    }
}

impl TransactionQueue for TransactionQueueMemory {
    /// Adds the transaction to the queue. Returns true if the transaction was added to the queue on this call.
    fn add(&self, id: &TransactionID, tx: &Transaction) -> Result<bool, TransactionQueueError> {
        let mut inner = self.inner.write().unwrap();

        if inner.tx_map.contains_key(id) {
            return Ok(false);
        }

        // check sender balance and update sender and receiver balances
        if !inner.balance_cache.apply(tx)? {
            // insufficient sender balance
            return Err(TransactionQueueError::SenderBalanceInsufficient(
                *id,
                tx.from.expect("transaction should have a sender"),
            ));
        }

        // add to the back of the queue
        inner.tx_queue.push_back(*id);
        inner.tx_map.insert(*id, tx.clone());

        Ok(true)
    }

    /// Returns the queue length.
    fn len(&self) -> usize {
        self.inner.read().unwrap().tx_queue.len()
    }

    /// Returns true if the queue has a length of 0.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns transactions in the queue for the miner.
    fn get(&self, limit: usize) -> Vec<Transaction> {
        let inner = self.inner.read().unwrap();
        let limit = if limit == 0 || inner.tx_queue.len() < limit {
            inner.tx_queue.len()
        } else {
            limit
        };
        inner
            .tx_queue
            .iter()
            .take(limit)
            .filter_map(|tx_id| inner.tx_map.get(tx_id).cloned())
            .collect()
    }

    /// Adds a batch of transactions to the queue (a block has been disconnected.)
    fn add_batch(&self, ids: &[TransactionID], txs: &[Transaction]) {
        let mut inner = self.inner.write().unwrap();

        // add to front in reverse order.
        // we want formerly confirmed transactions to have the highest
        // priority for getting into the next block.
        for i in (0..txs.len()).rev() {
            let tx = &txs[i];
            let tx_id = ids[i];

            if inner.tx_map.contains_key(&tx_id) {
                if let Some(index) = inner
                    .tx_queue
                    .iter()
                    .position(|queue_tx_id| *queue_tx_id == tx_id)
                {
                    // remove it from its current position
                    inner.tx_queue.remove(index);
                }
            }

            inner.tx_queue.push_front(tx_id);
            inner.tx_map.insert(tx_id, tx.clone());
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
        let mut inner = self.inner.write().unwrap();
        inner.tx_queue.retain(|tx_id| !ids.contains(tx_id));
        inner.tx_map.retain(|tx_id, _tx| !ids.contains(tx_id));

        if more {
            // we don't want to invalidate anything based on series/maturity/expiration/balance
            // until we're done connecting all of the blocks we intend to
            Ok(())
        } else {
            Self::reprocess_queue(&mut inner, height)
        }
    }

    /// Returns true if the given transaction is in the queue.
    fn exists(&self, id: &TransactionID) -> bool {
        self.inner.read().unwrap().tx_map.contains_key(id)
    }

    /// Return true if the given transaction is in the queue and contains the given signature.
    fn exists_signed(&self, id: &TransactionID, signature: Signature) -> bool {
        if let Some(tx) = self.inner.read().unwrap().tx_map.get(id) {
            tx.signature.expect("transaction should have a signature") == signature
        } else {
            false
        }
    }
}

#[cfg(test)]
mod test {
    use ed25519_compact::KeyPair;
    use tempfile::tempdir;

    use super::*;
    use crate::block_storage_disk::BlockStorageDisk;

    fn make_test_tx(amount: u64) -> Transaction {
        let from = KeyPair::generate().pk;
        let to = KeyPair::generate().pk;
        Transaction::new(Some(from), to, amount, None, None, None, 1, None)
    }

    #[test]
    fn test_get_limit_matches_go() {
        let temp_dir = tempdir().unwrap();
        let data_dir = temp_dir.path();
        let block_store = BlockStorageDisk::new(
            data_dir.join("blocks"),
            data_dir.join("headers.db"),
            false,
            false,
        )
        .unwrap();
        let ledger = LedgerDisk::new(data_dir.join("ledger.db"), block_store, false).unwrap();
        let queue = TransactionQueueMemory::new(ledger);

        let txs = [make_test_tx(1), make_test_tx(2), make_test_tx(3)];
        let ids: Vec<TransactionID> = txs.iter().map(|t| t.id().unwrap()).collect();
        queue.add_batch(&ids, &txs);

        // limit zero returns the full queue
        assert_eq!(queue.get(0).len(), txs.len());
        assert_eq!(queue.get(txs.len() + 1).len(), txs.len());
        assert_eq!(queue.get(2).len(), 2);
    }
}
