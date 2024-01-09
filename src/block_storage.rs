use thiserror::Error;

use crate::block::{Block, BlockHeader, BlockID};
use crate::error::{DbError, EncodingError, FileError, JsonError};
use crate::transaction::Transaction;

pub trait BlockStorage {
    /// Called to store all of the block's information.
    fn store(&self, id: &BlockID, block: &Block, now: u64) -> Result<(), BlockStorageError>;

    /// Returns the referenced block.
    fn get_block(&self, id: &BlockID) -> Result<Option<Block>, BlockStorageError>;

    /// Returns the referenced block as a byte slice.
    fn get_block_bytes(&self, id: &BlockID) -> Result<Option<Vec<u8>>, BlockStorageError>;

    /// Returns the referenced block's header and the timestamp of when it was stored.
    fn get_block_header(
        &self,
        id: &BlockID,
    ) -> Result<Option<(BlockHeader, u64)>, BlockStorageError>;

    /// Returns a transaction within a block and the block's header.
    fn get_transaction(
        &self,
        id: &BlockID,
        index: u32,
    ) -> Result<(Option<Transaction>, BlockHeader), BlockStorageError>;
}

#[derive(Error, Debug)]
pub enum BlockStorageError {
    #[error("block storage is in read-only mode")]
    ReadOnly,

    #[error("block storage not found")]
    BlockStorageNotFound(#[from] BlockStorageNotFoundError),

    #[error("db")]
    Db(#[from] DbError),
    #[error("encoding")]
    Encoding(#[from] EncodingError),
    #[error("file")]
    File(#[from] FileError),
    #[error("json")]
    Json(#[from] JsonError),
}

#[derive(Error, Debug)]
pub enum BlockStorageNotFoundError {
    #[error("block {0} not found")]
    Block(BlockID),
    #[error("block {0} bytes not found")]
    BlockBytes(BlockID),
    #[error("block {0} header not found")]
    BlockHeader(BlockID),
    #[error("transaction at block {0}, index {1} not found")]
    TransactionAtBlockIndex(BlockID, u32),
}
