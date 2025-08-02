use std::collections::HashMap;
use std::sync::Arc;

use ed25519_compact::PublicKey;
use thiserror::Error;

use crate::ledger::LedgerError;
use crate::ledger_disk::LedgerDisk;
use crate::transaction::Transaction;

/// Maintains a partial unconfirmed view of the ledger.
/// It's used by Ledger when (dis-)connecting blocks and by TransactionQueueMemory
/// when deciding whether or not to add a transaction to the queue.
pub struct BalanceCache {
    ledger: Arc<LedgerDisk>,
    min_balance: u64,
    cache: HashMap<PublicKey, u64>,
}

impl BalanceCache {
    /// Returns a new instance of a BalanceCache.
    pub fn new(ledger: Arc<LedgerDisk>, min_balance: u64) -> Self {
        BalanceCache {
            ledger,
            min_balance,
            cache: HashMap::new(),
        }
    }

    /// Resets the balance cache.
    pub fn reset(&mut self) {
        self.cache = HashMap::new();
    }

    /// Applies the effect of the transaction to the involved parties' cached balances.
    /// It returns false if the sender balance would go negative as a result of applying this transaction.
    /// It also returns false if a remaining non-zero sender balance would be less than min_balance.
    pub fn apply(&mut self, tx: &Transaction) -> Result<bool, BalanceCacheError> {
        if !tx.is_coinbase() {
            // check and debit sender balance
            let fpk = tx.from.expect("transaction should have a sender");
            let mut sender_balance = match self.cache.get(&fpk).copied() {
                Some(v) => v,
                None => self.ledger.get_public_key_balance(&fpk)?,
            };
            let total_spent = tx.amount + tx.fee.expect("transaction should have a fee");
            if total_spent > sender_balance {
                return Ok(false);
            }
            sender_balance -= total_spent;
            if sender_balance > 0 && sender_balance < self.min_balance {
                return Ok(false);
            }
            self.cache.insert(fpk, sender_balance);
        }

        // credit recipient balance
        let tpk = tx.to;
        let mut recipient_balance = match self.cache.get(&tpk).copied() {
            Some(v) => v,
            None => self.ledger.get_public_key_balance(&tx.to)?,
        };
        recipient_balance += tx.amount;
        self.cache.insert(tpk, recipient_balance);

        Ok(true)
    }

    /// Undoes the effects of a transaction on the involved parties' cached balances.
    pub fn undo(&mut self, tx: &Transaction) -> Result<(), BalanceCacheError> {
        if !tx.is_coinbase() {
            // credit balance for sender
            let fpk = tx.from.expect("transaction should have a sender");
            let mut sender_balance = match self.cache.get(&fpk).copied() {
                Some(v) => v,
                None => {
                    let from = tx.from.expect("transaction should have a sender");
                    self.ledger.get_public_key_balance(&from)?
                }
            };
            let total_spent = tx.amount + tx.fee.expect("transaction should have a fee");
            sender_balance += total_spent;
            self.cache.insert(fpk, sender_balance);
        }

        // debit recipient balance
        let tpk = tx.to;
        let recipient_balance = match self.cache.get(&tpk).copied() {
            Some(v) => v,
            None => self.ledger.get_public_key_balance(&tpk)?,
        };
        if recipient_balance < tx.amount {
            panic!("Recipient balance went negative")
        }
        self.cache.insert(tpk, recipient_balance - tx.amount);

        Ok(())
    }

    /// returns the underlying cache of balances.
    pub fn balances(&self) -> &HashMap<PublicKey, u64> {
        &self.cache
    }
}

#[derive(Error, Debug)]
pub enum BalanceCacheError {
    #[error("ledger")]
    Ledger(#[from] LedgerError),
}
