use std::collections::HashMap;
use std::mem;
use std::path::PathBuf;
use std::sync::Arc;

use ed25519_compact::PublicKey;
use leveldb::database::batch::{Batch, WriteBatch};
use leveldb::database::{Database, DatabaseReader};
use leveldb::iterator::{Iterable, LevelDBIterator};
use leveldb::options::{Options, ReadOptions, WriteOptions};
use leveldb::snapshots::Snapshots;

use crate::balance_cache::BalanceCache;
use crate::block::{Block, BlockID, BLOCK_ID_LENGTH};
use crate::block_storage::BlockStorage;
use crate::block_storage_disk::BlockStorageDisk;
use crate::constants::{BLOCKS_UNTIL_NEW_SERIES, COINBASE_MATURITY};
use crate::error::{DataError, DbError};
use crate::ledger::{BranchType, Ledger, LedgerError, LedgerNotFoundError};
use crate::transaction::{TransactionID, TRANSACTION_ID_LENGTH};

/// An on-disk implementation of the Ledger interface using LevelDB.
pub struct LedgerDisk {
    db: Database,
    block_store: Arc<BlockStorageDisk>,
    /// prune historic transaction and public key transaction indices
    prune: bool,
}

impl LedgerDisk {
    /// Returns a new instance of LedgerDisk.
    pub fn new(
        db_path: PathBuf,
        block_store: Arc<BlockStorageDisk>,
        prune: bool,
    ) -> Result<Arc<Self>, LedgerError> {
        let mut options = Options::new();
        options.create_if_missing = true;
        let db = Database::open(&db_path, &options).map_err(|err| DbError::Open(db_path, err))?;

        Ok(Arc::new(Self {
            db,
            block_store,
            prune,
        }))
    }

    /// Sometimes we call this with leveldb Database or Snapshot
    fn get_chain_tip(db: &impl DatabaseReader) -> Result<Option<(BlockID, u64)>, LedgerError> {
        // compute db key
        let key = compute_chain_tip_key();

        // fetch the id
        let Some(ct_bytes) = db
            .get_u8(&ReadOptions::new(), &key)
            .map_err(DbError::Read)?
        else {
            return Ok(None);
        };

        // decode the tip
        let (id, height) = decode_chain_tip(&ct_bytes)?;
        Ok(Some((id, height)))
    }

    /// Sometimes we call this with leveldb Database or Snapshot
    fn get_block_id_for_height<T: DatabaseReader>(
        height: u64,
        db: &T,
    ) -> Result<Option<BlockID>, LedgerError> {
        // compute db key
        let key = compute_block_height_index_key(height);

        // fetch the id
        let Some(id_bytes) = db
            .get_u8(&ReadOptions::new(), &key)
            .map_err(DbError::Read)?
        else {
            return Ok(None);
        };

        // return it
        Ok(Some(BlockID::from(id_bytes)))
    }
    /// Prune transaction and public key transaction indices created by the block at the given height
    fn prune_indices(&self, height: u64, batch: &WriteBatch) -> Result<(), LedgerError> {
        // get the ID
        let Some(id) = self.get_block_id_for_height(height)? else {
            return Err(LedgerNotFoundError::BlockIDForHeight(height).into());
        };

        // fetch the block
        let Some(block) = self.block_store.get_block(&id)? else {
            return Err(LedgerNotFoundError::BlockForID(id).into());
        };

        for (i, tx) in block.transactions.iter().enumerate() {
            let tx_id = tx.id()?;

            // prune transaction index
            let key = compute_transaction_index_key(&tx_id);
            batch.delete_u8(&key);

            // prune public key transaction indices
            if !tx.is_coinbase() {
                let key = compute_pub_key_transaction_index_key(
                    tx.from.expect("transaction should have a sender"),
                    Some(block.header.height),
                    Some(i as u32),
                );
                batch.delete(&key);
            }
        }

        Ok(())
    }

    /// Restore transaction and public key transaction indices created by the block at the given height
    fn restore_indices(&self, height: u64, batch: &WriteBatch) -> Result<(), LedgerError> {
        // get the ID
        let Some(id) = self.get_block_id_for_height(height)? else {
            return Err(LedgerNotFoundError::BlockIDForHeight(height).into());
        };

        // fetch the block
        let Some(block) = self.block_store.get_block(&id)? else {
            return Err(LedgerNotFoundError::BlockForID(id).into());
        };

        for (i, tx) in block.transactions.iter().enumerate() {
            let tx_id = tx.id()?;

            // restore transaction index
            let key = compute_transaction_index_key(&tx_id);
            let index_bytes = encode_transaction_index(block.header.height, i as u32);
            batch.put_u8(&key, &index_bytes);

            // restore public key transaction indices
            if !tx.is_coinbase() {
                let key = compute_pub_key_transaction_index_key(
                    tx.from.expect("transaction should have a sender"),
                    Some(block.header.height),
                    Some(i as u32),
                );
                batch.put_u8(&key, &[0x1]);
            }

            let key = compute_pub_key_transaction_index_key(
                tx.to,
                Some(block.header.height),
                Some(i as u32),
            );
            batch.put_u8(&key, &[0x1]);
        }

        Ok(())
    }

    /// Returns the index of a processed transaction.
    pub fn get_transaction_index(
        &self,
        id: &TransactionID,
    ) -> Result<Option<(BlockID, u32)>, LedgerError> {
        // compute the db key
        let key_result = compute_transaction_index_key(id);

        // we want a consistent view during our two queries as height can change
        let snapshot = self.db.snapshot();

        // fetch and decode the index
        let Some(index_bytes) = snapshot
            .get_u8(&ReadOptions::new(), &key_result)
            .map_err(DbError::Read)?
        else {
            return Ok(None);
        };
        let (height, index) = decode_transaction_index(&index_bytes)?;

        // map height to block id
        let Some(block_id) = Self::get_block_id_for_height(height, &snapshot)? else {
            return Ok(None);
        };

        Ok(Some((block_id, index)))
    }

    /// Iterate through transaction history going forward
    fn get_public_key_transaction_indices_range_forward(
        &self,
        pub_key: PublicKey,
        start_height: u64,
        mut end_height: u64,
        start_index: u32,
        limit: usize,
    ) -> Result<(Vec<BlockID>, Vec<u32>, u64, u32), LedgerError> {
        let start_key =
            compute_pub_key_transaction_index_key(pub_key, Some(start_height), Some(start_index));

        // make it inclusive
        end_height += 1;
        let end_key = compute_pub_key_transaction_index_key(pub_key, Some(end_height), None);

        let mut height_map = HashMap::new();
        let mut ids = Vec::new();
        let mut indices = Vec::new();
        let mut last_height = 0;
        let mut last_index = 0;

        // we want a consistent view of this. heights can change out from under us otherwise
        let snapshot = self.db.snapshot();
        let iter = snapshot
            .keys_iter(&ReadOptions::new())
            .from(&start_key)
            .to(&end_key);

        for key in iter {
            (_, last_height, last_index) = decode_pub_key_transaction_index_key(key)?;

            // lookup the block id
            let id = match height_map.get(&last_height).cloned() {
                Some(v) => v,
                None => {
                    let Some(id) = Self::get_block_id_for_height(last_height, &snapshot)? else {
                        return Err(LedgerNotFoundError::BlockIDForHeight(last_height).into());
                    };
                    height_map.insert(last_height, id);
                    id
                }
            };

            ids.push(id);
            indices.push(last_index);

            if limit != 0 && indices.len() == limit {
                break;
            }
        }

        Ok((ids, indices, last_height, last_index))
    }

    /// Iterate through transaction history in reverse
    fn get_public_key_transaction_indices_range_reverse(
        &self,
        pub_key: PublicKey,
        start_height: u64,
        end_height: u64,
        mut start_index: u32,
        limit: usize,
    ) -> Result<(Vec<BlockID>, Vec<u32>, u64, u32), LedgerError> {
        let end_key = compute_pub_key_transaction_index_key(pub_key, Some(end_height), None);

        // make it inclusive
        start_index += 1;
        let start_key =
            compute_pub_key_transaction_index_key(pub_key, Some(start_height), Some(start_index));

        let mut height_map = HashMap::new();
        let mut ids = Vec::new();
        let mut indices = Vec::new();
        let mut last_height = 0;
        let mut last_index = 0;

        // we want a consistent view of this. heights can change out from under us otherwise
        let snapshot = self.db.snapshot();
        let iter = snapshot
            .keys_iter(&ReadOptions::new())
            .from(&start_key)
            .to(&end_key)
            .reverse();

        for key in iter {
            (_, last_height, last_index) = decode_pub_key_transaction_index_key(key)?;

            // lookup the block id
            let id = match height_map.get(&last_height).cloned() {
                Some(v) => v,
                None => {
                    let Some(id) = Self::get_block_id_for_height(last_height, &snapshot)? else {
                        return Err(LedgerNotFoundError::BlockIDForHeight(last_height).into());
                    };
                    height_map.insert(last_height, id);
                    id
                }
            };

            ids.push(id);
            indices.push(last_index);
            if limit != 0 && indices.len() == limit {
                break;
            }
        }

        Ok((ids, indices, last_height, last_index))
    }

    /// Returns the current balance of a given public key.
    pub fn get_public_key_balance(&self, pub_key: &PublicKey) -> Result<u64, LedgerError> {
        // compute db key
        let key = compute_pub_key_balance_key(pub_key);

        // fetch balance
        let Some(balance_bytes) = self
            .db
            .get_u8(&ReadOptions::new(), &key)
            .map_err(DbError::Read)?
        else {
            return Ok(0);
        };

        // decode and return it
        let balance = u64::from_be_bytes(balance_bytes[..].try_into().map_err(DataError::U64)?);

        Ok(balance)
    }
}

impl Ledger for LedgerDisk {
    /// Returns the ID and the height of the block at the current tip of the main chain.
    fn get_chain_tip(&self) -> Result<Option<(BlockID, u64)>, LedgerError> {
        Self::get_chain_tip(&self.db)
    }

    /// Returns the ID of the block at the given block chain height.
    fn get_block_id_for_height(&self, height: u64) -> Result<Option<BlockID>, LedgerError> {
        Self::get_block_id_for_height(height, &self.db)
    }

    /// Sets the branch type for the given block.
    fn set_branch_type(&self, id: &BlockID, branch_type: BranchType) -> Result<(), LedgerError> {
        // compute db key
        let key = compute_branch_type_key(id);
        self.db
            .put_u8(&WriteOptions { sync: true }, &key, &[branch_type as u8])
            .map_err(DbError::Write)?;

        Ok(())
    }

    /// Returns the branch type for the given block.
    fn get_branch_type(&self, id: &BlockID) -> Result<BranchType, LedgerError> {
        let key = compute_branch_type_key(id);
        let options = ReadOptions::new();
        match self.db.get_u8(&options, &key).map_err(DbError::Read)? {
            Some(bt) => Ok(BranchType::try_from(bt[0])?),
            None => Ok(BranchType::Unknown),
        }
    }

    /// Connects a block to the tip of the block chain and applies the transactions to the ledger.
    fn connect_block(
        self: &Arc<Self>,
        id: &BlockID,
        block: &Block,
    ) -> Result<Vec<TransactionID>, LedgerError> {
        // sanity check
        if let Some((tip_id, _height)) = self.get_chain_tip()? {
            if tip_id != block.header.previous {
                return Err(LedgerError::ConnectBlockTipAndPreviousMismatch(
                    *id,
                    block.header.previous,
                    tip_id,
                ));
            }
        }

        // apply all resulting writes atomically
        let batch = WriteBatch::new();

        let mut balance_cache = BalanceCache::new(Arc::clone(self), 0);
        let mut tx_ids = Vec::with_capacity(block.transactions.len());

        for (i, tx) in block.transactions.iter().enumerate() {
            let tx_id = tx.id()?;
            tx_ids.push(tx_id);

            // verify the transaction hasn't been processed already.
            // note that we can safely prune indices for transactions older than the previous series
            let key = compute_transaction_index_key(&tx_id);
            if self
                .db
                .get_u8(&ReadOptions::new(), &key)
                .map_err(DbError::Read)?
                .is_some()
            {
                return Err(LedgerError::TransactionAlreadyProcessed(tx_id));
            }

            // set the transaction index now
            let index_bytes = encode_transaction_index(block.header.height, i as u32);
            batch.put_u8(&key, &index_bytes);

            let mut tx_to_apply = Some(tx.clone());

            if tx.is_coinbase() {
                // don't apply a coinbase to a balance until it's 100 blocks deep.
                // during honest reorgs normal transactions usually get into the new most-work branch
                // but coinbases vanish. this mitigates the impact on UX when reorgs occur and transactions
                // depend on coinbases.
                tx_to_apply = None;

                if block.header.height >= COINBASE_MATURITY {
                    // mature the coinbase from 100 blocks ago now
                    let Some(old_id) =
                        self.get_block_id_for_height(block.header.height - COINBASE_MATURITY)?
                    else {
                        return Err(LedgerNotFoundError::BlockIDForHeight(
                            block.header.height - COINBASE_MATURITY,
                        )
                        .into());
                    };

                    // we could store the last 100 coinbases on our own in memory if we end up needing to
                    let (Some(old_tx), _block_header) =
                        self.block_store.get_transaction(&old_id, 0)?
                    else {
                        return Err(LedgerNotFoundError::CoinbaseForBlock(old_id).into());
                    };

                    // apply it to the recipient's balance
                    tx_to_apply = Some(old_tx);
                }
            }

            if let Some(tx_to_apply) = tx_to_apply {
                // check sender balance and update sender and receiver balances
                if !balance_cache.apply(&tx_to_apply)? {
                    return Err(LedgerError::BalanceCacheApplyFailed(tx_id));
                }
            }

            // associate this transaction with both parties
            if !tx.is_coinbase() {
                let from = tx.from.expect("transaction should have a sender");
                let key = compute_pub_key_transaction_index_key(
                    from,
                    Some(block.header.height),
                    Some(i as u32),
                );
                batch.put_u8(&key, &[0x1]);
            }

            let key = compute_pub_key_transaction_index_key(
                tx.to,
                Some(block.header.height),
                Some(i as u32),
            );
            batch.put_u8(&key, &[0x1]);
        }

        // update recorded balances
        let balances = balance_cache.balances();
        for (pub_key, balance) in balances.iter() {
            let key = compute_pub_key_balance_key(pub_key);

            if *balance == 0 {
                batch.delete_u8(&key);
            } else {
                batch.put_u8(&key, &balance.to_be_bytes());
            }
        }

        // index the block by height
        let key = compute_block_height_index_key(block.header.height);
        batch.put_u8(&key, id);

        // set this block on the main chain
        let key = compute_branch_type_key(id);
        batch.put_u8(&key, &[BranchType::Main as u8]);

        // set this block as the new tip
        let key = compute_chain_tip_key();
        let ct_bytes = encode_chain_tip(id, block.header.height);
        batch.put_u8(&key, &ct_bytes);

        // prune historic transaction and public key transaction indices now
        if self.prune && block.header.height >= 2 * BLOCKS_UNTIL_NEW_SERIES {
            self.prune_indices(block.header.height - 2 * BLOCKS_UNTIL_NEW_SERIES, &batch)?;
        };

        // perform the writes
        let wo = WriteOptions { sync: true };
        self.db.write(&wo, &batch).map_err(DbError::Write)?;

        Ok(tx_ids)
    }

    /// Disconnects a block from the tip of the block chain and undoes the effects of the transactions on the ledger.
    fn disconnect_block(
        self: &Arc<Self>,
        id: &BlockID,
        block: &Block,
    ) -> Result<Vec<TransactionID>, LedgerError> {
        // sanity check
        let Some((tip_id, _height)) = self.get_chain_tip()? else {
            return Err(LedgerError::DisconnectTipNotFound(*id));
        };

        if tip_id != *id {
            return Err(LedgerError::DisconnectTipMismatch(*id, tip_id));
        }

        // apply all resulting writes atomically
        let batch = WriteBatch::new();

        let mut balance_cache = BalanceCache::new(Arc::clone(self), 0);
        let mut tx_ids = Vec::with_capacity(block.transactions.len());

        // disconnect transactions in reverse order
        for (i, tx) in block.transactions.iter().rev().enumerate() {
            let tx_id = tx.id()?;
            // save the id
            tx_ids.push(tx_id);

            // mark the transaction unprocessed now (delete its index)
            let key = compute_transaction_index_key(&tx_id);
            batch.delete_u8(&key);

            let mut tx_to_undo = Some(tx.clone());
            if tx.is_coinbase() {
                // coinbase doesn't affect recipient balance for 100 more blocks
                tx_to_undo = None;

                if block.header.height >= COINBASE_MATURITY {
                    // undo the effect of the coinbase from 100 blocks ago now
                    let Some(old_id) =
                        self.get_block_id_for_height(block.header.height - COINBASE_MATURITY)?
                    else {
                        return Err(LedgerNotFoundError::BlockIDForHeight(
                            block.header.height - COINBASE_MATURITY,
                        )
                        .into());
                    };

                    let (Some(old_tx), _block_header) =
                        self.block_store.get_transaction(&old_id, 0)?
                    else {
                        return Err(LedgerNotFoundError::CoinbaseForBlock(old_id).into());
                    };

                    // undo its effect on the recipient's balance
                    tx_to_undo = Some(old_tx);
                }
            }

            if let Some(tx_to_undo) = tx_to_undo {
                // credit sender and debit recipient
                balance_cache.undo(&tx_to_undo)?;
            }

            // unassociate this transaction with both parties
            if !tx.is_coinbase() {
                let key = compute_pub_key_transaction_index_key(
                    tx.from.expect("transaction should have a sender"),
                    Some(block.header.height),
                    Some(i as u32),
                );
                batch.delete_u8(&key);
            }

            let key = compute_pub_key_transaction_index_key(
                tx.to,
                Some(block.header.height),
                Some(i as u32),
            );
            batch.delete_u8(&key);
        }

        // update recorded balances
        let balances = balance_cache.balances();
        for (pub_key, balance) in balances.iter() {
            let key = compute_pub_key_balance_key(pub_key);
            if *balance == 0 {
                batch.delete_u8(&key);
            } else {
                batch.put_u8(&key, &balance.to_be_bytes());
            }
        }

        // remove this block's index by height
        let key = compute_block_height_index_key(block.header.height);
        batch.delete_u8(&key);

        // set this block on a side chain
        let key = compute_branch_type_key(id);
        batch.put_u8(&key, &[BranchType::Side as u8]);

        // set the previous block as the chain tip
        let key = compute_chain_tip_key();
        let ct_bytes = encode_chain_tip(&block.header.previous, block.header.height - 1);
        batch.put_u8(&key, &ct_bytes);

        // restore historic indices now
        if self.prune && block.header.height >= 2 * BLOCKS_UNTIL_NEW_SERIES {
            self.restore_indices(block.header.height - 2 * BLOCKS_UNTIL_NEW_SERIES, &batch)?;
        }

        // perform the writes
        let wo = WriteOptions { sync: true };
        self.db.write(&wo, &batch).map_err(DbError::Write)?;

        Ok(tx_ids)
    }

    /// Returns the current balance of the given public keys
    /// along with block ID and height of the corresponding main chain tip.
    fn get_public_key_balances(
        &self,
        pub_keys: Vec<PublicKey>,
    ) -> Result<(HashMap<PublicKey, u64>, BlockID, u64), LedgerError> {
        // get a consistent view across all queries
        let snapshot = self.db.snapshot();

        // get the chain tip
        let Some((tip_id, tip_height)) = Self::get_chain_tip(&snapshot)? else {
            return Err(LedgerNotFoundError::ChainTip.into());
        };

        let mut balances = HashMap::new();

        for pub_key in pub_keys.iter() {
            // compute balance db key
            let key = compute_pub_key_balance_key(pub_key);

            // fetch balance
            let Some(balance_bytes) = snapshot
                .get_u8(&ReadOptions::new(), &key)
                .map_err(DbError::Read)?
            else {
                balances.insert(*pub_key, 0);
                continue;
            };

            // decode it
            let balance = u64::from_be_bytes(balance_bytes[..].try_into().map_err(DataError::U64)?);

            // save it
            balances.insert(*pub_key, balance);
        }

        Ok((balances, tip_id, tip_height))
    }

    /// Returns the current balance of a given public key.
    fn get_public_key_balance(&self, pub_key: &PublicKey) -> Result<u64, LedgerError> {
        // compute db key
        let key = compute_pub_key_balance_key(pub_key);

        // fetch balance
        let Some(balance_bytes) = self
            .db
            .get_u8(&ReadOptions::new(), &key)
            .map_err(DbError::Read)?
        else {
            return Err(DataError::NotFound.into());
        };

        // decode and return it
        let balance = u64::from_be_bytes(balance_bytes[..].try_into().map_err(DataError::U64)?);

        Ok(balance)
    }

    /// Returns the index of a processed transaction.
    fn get_transaction_index(&self, id: &TransactionID) -> Result<(BlockID, u32), LedgerError> {
        let key = compute_transaction_index_key(id);

        // we want a consistent view during our two queries as height can change
        let snapshot = self.db.snapshot();

        // fetch and decode the index
        let Some(index_bytes) = snapshot
            .get_u8(&ReadOptions::new(), &key)
            .map_err(DbError::Read)?
        else {
            return Err(LedgerNotFoundError::TransactionAtIndex(*id).into());
        };

        let (height, index) = decode_transaction_index(&index_bytes)?;
        // map height to block id
        let Some(block_id) = Self::get_block_id_for_height(height, &snapshot)? else {
            return Err(LedgerNotFoundError::BlockIDForHeight(height).into());
        };

        Ok((block_id, index))
    }

    /// Returns transaction indices involving a given public key over
    /// a range of heights. If startHeight > endHeight this iterates
    /// in reverse.
    fn get_public_key_transaction_indices_range(
        &self,
        pub_key: PublicKey,
        start_height: u64,
        end_height: u64,
        start_index: u32,
        limit: usize,
    ) -> Result<(Vec<BlockID>, Vec<u32>, u64, u32), LedgerError> {
        if end_height >= start_height {
            // forward
            self.get_public_key_transaction_indices_range_forward(
                pub_key,
                start_height,
                end_height,
                start_index,
                limit,
            )
        } else {
            // reverse
            self.get_public_key_transaction_indices_range_reverse(
                pub_key,
                start_height,
                end_height,
                start_index,
                limit,
            )
        }
    }

    /// Returns the total current ledger balance by summing the balance of all public keys.
    /// It's only used offline for verification purposes.
    fn balance(&self) -> Result<u64, LedgerError> {
        let mut total = 0;

        // compute the sum of all public key balances
        let key = compute_pub_key_balance_key_all();
        let iter = self.db.value_iter(&ReadOptions::new()).prefix(&key);

        for balance_bytes in iter {
            let balance = u64::from_be_bytes(balance_bytes[..].try_into().map_err(DataError::U64)?);
            total += balance
        }

        Ok(total)
    }

    /// Returns the public key balance at the given height.
    /// It's only used offline for historical and verification purposes.
    /// This is only accurate when the full block chain is indexed (pruning disabled.)
    fn get_public_key_balance_at(
        &self,
        pub_key: &PublicKey,
        mut height: u64,
    ) -> Result<u64, LedgerError> {
        let current_height = match self.get_chain_tip()? {
            Some((_tip_id, height)) => height,
            None => 0,
        };

        let start_key = compute_pub_key_transaction_index_key(*pub_key, None, None);

        // make it inclusive
        height += 1;
        let end_key = compute_pub_key_transaction_index_key(*pub_key, Some(height), None);

        let mut balance = 0;

        let snapshot = self.db.snapshot();
        let iter = snapshot
            .keys_iter(&ReadOptions::new())
            .from(&start_key)
            .to(&end_key);

        for key in iter {
            let (_, height, index) = decode_pub_key_transaction_index_key(key)?;

            if index == 0 && height > current_height.saturating_sub(COINBASE_MATURITY) {
                // coinbase isn't mature
                continue;
            }

            let Some(block_id) = self.get_block_id_for_height(height)? else {
                return Err(LedgerNotFoundError::BlockIDForHeight(height).into());
            };

            let (Some(tx), _block_header) = self.block_store.get_transaction(&block_id, index)?
            else {
                return Err(LedgerNotFoundError::TransactionInBlock(index, block_id).into());
            };

            if *pub_key == tx.to {
                balance += tx.amount;
            } else if pub_key == tx.from.as_ref().expect("transaction should have a sender") {
                let fee = tx.fee.expect("transaction should have a fee");
                balance = balance
                    .checked_sub(tx.amount)
                    .and_then(|new_balance| new_balance.checked_sub(fee))
                    .ok_or(LedgerError::TransactionBalanceNegative(tx.id()?))?;
            } else {
                return Err(LedgerError::TransactionPublicKeyMismatch(tx.id()?));
            }
        }

        Ok(balance)
    }
}

/// leveldb schema
/// h{height}            -> {bid}
/// B{bid}               -> main|side|orphan (1 byte)
/// T                    -> {bid}{height} (main chain tip)
/// b{pk}                -> {balance} (we always need all of this table)
/// k{pk}{height}{index} -> 1 (not strictly necessary. probably should make it optional by flag)
/// t{txid}              -> {height}{index} (prunable up to the previous series)
const BLOCK_HEIGHT_INDEX_PREFIX: u8 = b'h';
const BRANCH_TYPE_PREFIX: u8 = b'B';
const CHAIN_TIP_PREFIX: u8 = b'T';
const PUB_KEY_BALANCE_PREFIX: u8 = b'b';
const PUB_KEY_TRANSACTION_INDEX_PREFIX: u8 = b'k';
const TRANSACTION_INDEX_PREFIX: u8 = b't';

const U32_LENGTH: usize = mem::size_of::<u32>();
const U64_LENGTH: usize = mem::size_of::<u64>();
const PREFIX_LENGTH: usize = 1;

type BlockHeightIndexKey = [u8; PREFIX_LENGTH + U64_LENGTH];
type BranchTypeKey = [u8; PREFIX_LENGTH + BLOCK_ID_LENGTH];
type ChainTipKey = [u8; PREFIX_LENGTH];
type PubKeyBalanceKey = [u8; PREFIX_LENGTH + PublicKey::BYTES];
type PubKeyBalanceKeyAll = [u8; PREFIX_LENGTH];
type PubKeyTransactionIndexKey = Vec<u8>;
type TransactionIndexKey = [u8; PREFIX_LENGTH + TRANSACTION_ID_LENGTH];

type ChainTip = [u8; BLOCK_ID_LENGTH + U64_LENGTH];
type TransactionIndex = [u8; U64_LENGTH + U32_LENGTH];

fn compute_branch_type_key(id: &BlockID) -> BranchTypeKey {
    let mut key: BranchTypeKey = [0u8; mem::size_of::<BranchTypeKey>()];
    key[0] = BRANCH_TYPE_PREFIX;
    key[1..].copy_from_slice(id);
    key
}

fn compute_block_height_index_key(height: u64) -> BlockHeightIndexKey {
    let mut key: BlockHeightIndexKey = [0u8; mem::size_of::<BlockHeightIndexKey>()];
    key[0] = BLOCK_HEIGHT_INDEX_PREFIX;
    key[1..].copy_from_slice(&height.to_be_bytes());
    key
}

fn compute_chain_tip_key() -> ChainTipKey {
    [CHAIN_TIP_PREFIX]
}

fn compute_transaction_index_key(id: &TransactionID) -> TransactionIndexKey {
    let mut key: TransactionIndexKey = [0u8; mem::size_of::<TransactionIndexKey>()];
    key[0] = TRANSACTION_INDEX_PREFIX;
    key[1..].copy_from_slice(id);
    key
}

fn compute_pub_key_transaction_index_key(
    pub_key: PublicKey,
    height: Option<u64>,
    index: Option<u32>,
) -> PubKeyTransactionIndexKey {
    let mut key: PubKeyTransactionIndexKey = Vec::new();
    key.push(PUB_KEY_TRANSACTION_INDEX_PREFIX);
    key.extend_from_slice(&pub_key[..]);

    // omiting lets us search with just the public key
    if let Some(height) = height {
        key.extend_from_slice(&height.to_be_bytes());
    } else {
        return key;
    }

    // omiting lets us search with just the public key and height
    if let Some(index) = index {
        key.extend_from_slice(&index.to_be_bytes());
    };
    key
}

fn decode_pub_key_transaction_index_key(
    key: Vec<u8>,
) -> Result<(PublicKey, u64, u32), LedgerError> {
    let mut offset = PREFIX_LENGTH;
    let pub_key = PublicKey::new(
        key[offset..][..PublicKey::BYTES]
            .try_into()
            .map_err(DataError::PublicKey)?,
    );
    offset += PublicKey::BYTES;

    let height = u64::from_be_bytes(
        key[offset..][..U64_LENGTH]
            .try_into()
            .map_err(DataError::U64)?,
    );
    offset += U64_LENGTH;

    let index = u32::from_be_bytes(
        key[offset..][..U32_LENGTH]
            .try_into()
            .map_err(DataError::U64)?,
    );
    Ok((pub_key, height, index))
}

fn compute_pub_key_balance_key(pub_key: &PublicKey) -> PubKeyBalanceKey {
    let mut key: PubKeyBalanceKey = [0u8; mem::size_of::<PubKeyBalanceKey>()];
    key[0] = PUB_KEY_BALANCE_PREFIX;
    key[1..].copy_from_slice(&pub_key[..]);
    key
}

fn compute_pub_key_balance_key_all() -> PubKeyBalanceKeyAll {
    [PUB_KEY_BALANCE_PREFIX]
}

fn encode_chain_tip(id: &BlockID, height: u64) -> ChainTip {
    let mut buf = [0u8; std::mem::size_of::<ChainTip>()];
    buf[..BLOCK_ID_LENGTH].copy_from_slice(id);
    buf[BLOCK_ID_LENGTH..][..U64_LENGTH].copy_from_slice(&u64::to_be_bytes(height));
    buf
}

fn decode_chain_tip(ct_bytes: &[u8]) -> Result<(BlockID, u64), LedgerError> {
    let id = BlockID::from(&ct_bytes[..BLOCK_ID_LENGTH]);
    let height = u64::from_be_bytes(
        ct_bytes[BLOCK_ID_LENGTH..]
            .try_into()
            .map_err(DataError::U64)?,
    );
    Ok((id, height))
}

fn encode_transaction_index(height: u64, index: u32) -> TransactionIndex {
    let mut buf = [0u8; std::mem::size_of::<TransactionIndex>()];
    buf[..U64_LENGTH].copy_from_slice(&height.to_be_bytes());
    buf[U64_LENGTH..].copy_from_slice(&index.to_be_bytes());
    buf
}

fn decode_transaction_index(index_bytes: &[u8]) -> Result<(u64, u32), LedgerError> {
    let height = u64::from_be_bytes(
        index_bytes[..U64_LENGTH]
            .try_into()
            .map_err(DataError::U64)?,
    );
    let index = u32::from_be_bytes(
        index_bytes[U64_LENGTH..][..U32_LENGTH]
            .try_into()
            .map_err(DataError::U32)?,
    );
    Ok((height, index))
}

#[cfg(test)]
mod test {
    use ed25519_compact::KeyPair;
    use tempfile::tempdir;

    use crate::block::test_utils::make_test_block;
    use crate::utils::now_as_secs;

    use super::*;

    #[test]
    fn test_compute_block_height_index_key() {
        let height = 1;
        let block_height_key = compute_block_height_index_key(height);
        assert_eq!(block_height_key[0], BLOCK_HEIGHT_INDEX_PREFIX);
        assert_eq!(block_height_key[1..], height.to_be_bytes());
    }

    #[test]
    fn test_compute_branch_type_key() {
        let block_id = BlockID::new();
        let branch_type_key = compute_branch_type_key(&block_id);
        assert_eq!(branch_type_key[0], BRANCH_TYPE_PREFIX);
        assert_eq!(branch_type_key[1..], block_id[..]);
    }

    #[test]
    fn test_compute_pub_key_balance_key() {
        let public_key = KeyPair::generate().pk;
        let compute_key = compute_pub_key_balance_key(&public_key);
        assert_eq!(compute_key[0], PUB_KEY_BALANCE_PREFIX);
        assert_eq!(&compute_key[1..], &public_key[..]);
    }

    #[test]
    fn test_decode_transaction_index() {
        let height = 1;
        let index = 1;
        let transaction_index = encode_transaction_index(height, index);
        let (height_decode, index_decode) = decode_transaction_index(&transaction_index).unwrap();
        assert_eq!(height_decode, height);
        assert_eq!(index_decode, index);
    }

    #[test]
    fn test_decode_chain_tip() {
        let block_id = BlockID::new();
        let height = 1;
        let chain_tip = encode_chain_tip(&block_id, height);
        let (block_id_decode, height_decode) = decode_chain_tip(&chain_tip).unwrap();
        assert_eq!(block_id_decode, block_id);
        assert_eq!(height_decode, height);
    }

    #[test]
    fn test_compute_chain_tip_key() {
        let chain_tip_key = compute_chain_tip_key();
        assert_eq!(chain_tip_key[0], CHAIN_TIP_PREFIX);
    }

    #[test]
    fn test_compute_pub_key_transaction_index_key() {
        let public_key = KeyPair::generate().pk;
        let height = 1;
        let index = 1;

        let pub_key_transaction_index_key =
            compute_pub_key_transaction_index_key(public_key, Some(height), Some(index));
        assert_eq!(
            pub_key_transaction_index_key[0],
            PUB_KEY_TRANSACTION_INDEX_PREFIX
        );
        let mut offset = 1;
        assert_eq!(
            &pub_key_transaction_index_key[offset..][..PublicKey::BYTES],
            &public_key[..]
        );

        offset += PublicKey::BYTES;
        let height_encoded = &pub_key_transaction_index_key[offset..][..U64_LENGTH];
        assert_eq!(height_encoded, height.to_be_bytes());

        offset += U64_LENGTH;
        let index_encoded = &pub_key_transaction_index_key[offset..];
        assert_eq!(index_encoded, index.to_be_bytes());
    }

    #[test]
    fn test_get_public_key_transaction_indices_range_forward() {
        let temp_dir = tempdir().unwrap();
        let data_dir = temp_dir.path();

        let block_store = BlockStorageDisk::new(
            data_dir.join("blocks"),
            data_dir.join("headers.db"),
            false, // not read only
            false,
        )
        .unwrap();

        let mut genesis_block = make_test_block(0);
        genesis_block.header.height += 1;
        let genesis_block_id = genesis_block.id().unwrap();
        block_store
            .store(&genesis_block_id, &genesis_block, now_as_secs())
            .unwrap();

        let mut block = genesis_block.clone();
        block.header.height += 1;
        block.header.previous = genesis_block_id;
        block.transactions[0].time += 1;
        let block_id = block.id().unwrap();
        block_store.store(&block_id, &block, now_as_secs()).unwrap();

        let ledger = LedgerDisk::new(data_dir.join("ledger.db"), block_store, false).unwrap();
        ledger
            .connect_block(&genesis_block_id, &genesis_block)
            .unwrap();
        ledger.connect_block(&block_id, &block).unwrap();

        let tx = &genesis_block.transactions[0];
        let (ids, indices, last_height, last_index) = ledger
            .get_public_key_transaction_indices_range(tx.to, 1, block.header.height - 1, 0, 100)
            .unwrap();
        assert_eq!(ids, vec![genesis_block_id]);
        assert_eq!(indices, vec![0]);
        assert_eq!(last_height, 1);
        assert_eq!(last_index, 0);

        let (ids, indices, last_height, last_index) = ledger
            .get_public_key_transaction_indices_range(tx.to, 1, block.header.height, 0, 100)
            .unwrap();
        assert_eq!(ids, vec![genesis_block_id, block_id]);
        assert_eq!(indices, vec![0, 0]);
        assert_eq!(last_height, block.header.height);
        assert_eq!(last_index, 0);
    }
}
