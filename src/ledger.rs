use std::collections::HashMap;
use std::sync::Arc;

use ed25519_compact::PublicKey;
use thiserror::Error;

use crate::balance_cache::BalanceCacheError;
use crate::block::{Block, BlockID};
use crate::block_storage::BlockStorageError;
use crate::error::{DataError, DbError};
use crate::transaction::{TransactionError, TransactionID};

/// Indicates the type of branch a particular block resides on.
/// Only blocks currently on the main branch are considered confirmed and only
/// transactions in those blocks affect public key balances.
/// Values are: Main, Side, Orphan or Unknown.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BranchType {
    Main = 0,
    Side = 2,
    Orphan = 3,
    Unknown = 4,
}

impl TryFrom<u8> for BranchType {
    type Error = LedgerError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(BranchType::Main),
            2 => Ok(BranchType::Side),
            3 => Ok(BranchType::Orphan),
            4 => Ok(BranchType::Unknown),
            _ => Err(LedgerError::BranchTypeInvalid(value)),
        }
    }
}

/// Ledger is an interface to a ledger built from the most-work chain of blocks.
/// It manages and computes public key balances as well as transaction and public key transaction indices.
/// It also maintains an index of the block chain by height as well as branch information.
pub trait Ledger {
    /// Returns the ID and the height of the block at the current tip of the main chain.
    fn get_chain_tip(&self) -> Result<Option<(BlockID, u64)>, LedgerError>;

    /// Returns the ID of the block at the given block chain height.
    fn get_block_id_for_height(&self, height: u64) -> Result<Option<BlockID>, LedgerError>;

    /// Sets the branch type for the given block.
    fn set_branch_type(&self, id: &BlockID, branch_type: BranchType) -> Result<(), LedgerError>;

    /// Returns the branch type for the given block.
    fn get_branch_type(&self, id: &BlockID) -> Result<BranchType, LedgerError>;

    /// Connects a block to the tip of the block chain and applies the transactions
    /// to the ledger.
    fn connect_block(
        self: &Arc<Self>,
        id: &BlockID,
        block: &Block,
    ) -> Result<Vec<TransactionID>, LedgerError>;

    /// Disconnects a block from the tip of the block chain and undoes the effects
    /// of the transactions on the ledger.
    fn disconnect_block(
        self: &Arc<Self>,
        id: &BlockID,
        block: &Block,
    ) -> Result<Vec<TransactionID>, LedgerError>;

    /// Returns the current balance of a given public key.
    fn get_public_key_balance(&self, pub_key: &PublicKey) -> Result<u64, LedgerError>;

    /// Returns the current balance of the given public keys
    /// along with block ID and height of the corresponding main chain tip.
    fn get_public_key_balances(
        &self,
        pub_keys: Vec<PublicKey>,
    ) -> Result<(HashMap<PublicKey, u64>, BlockID, u64), LedgerError>;

    /// Returns the index of a processed transaction.
    fn get_transaction_index(&self, id: &TransactionID) -> Result<(BlockID, u32), LedgerError>;

    /// Returns transaction indices involving a given public key
    /// over a range of heights. If startHeight > endHeight this iterates in reverse.
    fn get_public_key_transaction_indices_range(
        &self,
        pub_key: PublicKey,
        start_height: u64,
        end_height: u64,
        start_index: u32,
        limit: usize,
    ) -> Result<(Vec<BlockID>, Vec<u32>, u64, u32), LedgerError>;

    /// Returns the total current ledger balance by summing the balance of all public keys.
    /// It's only used offline for verification purposes.
    fn balance(&self) -> Result<u64, LedgerError>;

    /// Returns the public key balance at the given height.
    /// It's only used offline for historical and verification purposes.
    /// This is only accurate when the full block chain is indexed (pruning disabled.)
    fn get_public_key_balance_at(
        &self,
        pub_key: &PublicKey,
        height: u64,
    ) -> Result<u64, LedgerError>;
}

#[derive(Error, Debug)]
pub enum LedgerError {
    #[error("failed to apply transaction {0} to balance cache, sender balance would go negative")]
    BalanceCacheApplyFailed(TransactionID),
    #[error("branch type is invalid for value {0}")]
    BranchTypeInvalid(u8),
    #[error("being asked to connect {0} but previous {1} does not match tip {2}")]
    ConnectBlockTipAndPreviousMismatch(BlockID, BlockID, BlockID),
    #[error("being asked to disconnect {0} but it does not match tip {1}")]
    DisconnectTipMismatch(BlockID, BlockID),
    #[error("being asked to disconnect {0} but no tip is currently set")]
    DisconnectTipNotFound(BlockID),
    #[error("sender has insufficent balance in transaction {0}")]
    SenderBalanceInsufficient(TransactionID),
    #[error("transaction {0} already processed")]
    TransactionAlreadyProcessed(TransactionID),
    #[error("balance went negative at transaction {0}")]
    TransactionBalanceNegative(TransactionID),
    #[error("transaction {0} doesn't involve the public key")]
    TransactionPublicKeyMismatch(TransactionID),

    #[error("balance cache")]
    BalanceCache(Box<BalanceCacheError>),
    #[error("block storage")]
    BlockStorage(#[from] BlockStorageError),
    #[error("data")]
    Data(#[from] DataError),
    #[error("db")]
    Db(#[from] DbError),
    #[error("ledger not found")]
    LedgerNotFound(#[from] LedgerNotFoundError),
    #[error("transaction")]
    Transaction(#[from] TransactionError),
}

// needs boxed because it's recursive
impl From<BalanceCacheError> for LedgerError {
    fn from(value: BalanceCacheError) -> Self {
        Self::BalanceCache(Box::new(value))
    }
}

#[derive(Error, Debug)]
pub enum LedgerNotFoundError {
    #[error("block for ID {0} not found")]
    BlockForID(BlockID),
    #[error("block ID for height {0} not found")]
    BlockIDForHeight(u64),
    #[error("chain tip not found")]
    ChainTip,
    #[error("chain tip header not found")]
    ChainTipHeader,
    #[error("coinbase for block {0} not found")]
    CoinbaseForBlock(BlockID),
    #[error("transaction at index for {0} not found")]
    TransactionAtIndex(TransactionID),
    #[error("transaction at index {0} in block {1} not found")]
    TransactionInBlock(u32, BlockID),
}
