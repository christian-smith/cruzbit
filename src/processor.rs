use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::from_utf8;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ed25519_compact::{PublicKey, Signature};
use faster_hex::hex_decode;
use ibig::UBig;
use log::{error, info};
use sha3::{Digest, Sha3_256};
use thiserror::Error;
use tokio::sync::mpsc::{
    channel, unbounded_channel, Receiver, Sender, UnboundedReceiver, UnboundedSender,
};
use tokio::sync::oneshot;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

use crate::block::{
    compute_chain_work, compute_hash_list_root, Block, BlockError, BlockHeader, BlockID,
};
use crate::block_storage::{BlockStorage, BlockStorageError, BlockStorageNotFoundError};
use crate::block_storage_disk::BlockStorageDisk;
use crate::checkpoints::{checkpoint_check, CheckpointError};
use crate::constants::{
    BITCOIN_CASH_RETARGET_ALGORITHM_HEIGHT, BLOCKS_UNTIL_NEW_SERIES, BLOCKS_UNTIL_REWARD_HALVING,
    BLOCKS_UNTIL_TRANSACTIONS_PER_BLOCK_DOUBLING, CRUZBITS_PER_CRUZ, INITIAL_COINBASE_REWARD,
    INITIAL_MAX_TRANSACTIONS_PER_BLOCK, INITIAL_TARGET, MAX_FUTURE_SECONDS, MAX_MEMO_LENGTH,
    MAX_MONEY, MAX_NUMBER, MAX_TRANSACTIONS_PER_BLOCK,
    MAX_TRANSACTIONS_PER_BLOCK_EXCEEDED_AT_HEIGHT, MAX_TRANSACTION_QUEUE_LENGTH,
    MIN_AMOUNT_CRUZBITS, MIN_FEE_CRUZBITS, NUM_BLOCKS_FOR_MEDIAN_TIMESTAMP, RETARGET_INTERVAL,
    RETARGET_SMA_WINDOW, RETARGET_TIME, TARGET_SPACING,
};
use crate::error::{impl_debug_error_chain, ChannelError, EncodingError, ErrChain};
use crate::ledger::{BranchType, Ledger, LedgerError, LedgerNotFoundError};
use crate::ledger_disk::LedgerDisk;
use crate::shutdown::{ShutdownChanReceiver, SpawnedError};
use crate::transaction::{Transaction, TransactionError, TransactionID};
use crate::transaction_queue::{TransactionQueue, TransactionQueueError};
use crate::transaction_queue_memory::TransactionQueueMemory;
use crate::utils::now_as_secs;

pub type TipChangeSenderChan = UnboundedSender<TipChange>;
pub type TipChangeReceiverChan = UnboundedReceiver<TipChange>;
pub type TipChangeChan = (TipChangeSenderChan, TipChangeReceiverChan);
type TipChangeChanChan = (
    UnboundedSender<TipChangeSenderChan>,
    Mutex<Option<UnboundedReceiver<TipChangeSenderChan>>>,
);

type TxSenderChan = Sender<TxToProcess>;
type TxReceiverChan = Receiver<TxToProcess>;
type TxChan = (TxSenderChan, Mutex<Option<TxReceiverChan>>);

type BlockSenderChan = Sender<BlockToProcess>;
type BlockReceiverChan = Receiver<BlockToProcess>;
type BlockChan = (BlockSenderChan, Mutex<Option<BlockReceiverChan>>);

pub type NewTxSenderChan = Sender<NewTx>;
pub type NewTxReceiverChan = Receiver<NewTx>;
pub type NewTxChan = (NewTxSenderChan, NewTxReceiverChan);

type NewTxChanChan = (
    UnboundedSender<NewTxSenderChan>,
    Mutex<Option<UnboundedReceiver<NewTxSenderChan>>>,
);
pub type BlockResultChan = oneshot::Sender<Result<(), ProcessBlockError>>;
pub type TransactionResultChan = oneshot::Sender<Result<(), ProcessTransactionError>>;

/// Processes blocks and transactions in order to construct the ledger.
/// It also manages the storage of all block chain data as well as inclusion of new transactions into the transaction queue.
pub struct Processor {
    genesis_id: &'static BlockID,
    /// storage of raw block data
    block_store: Arc<BlockStorageDisk>,
    /// queue of transactions to confirm
    tx_queue: Arc<TransactionQueueMemory>,
    /// ledger built from processing blocks
    ledger: Arc<LedgerDisk>,
    /// receive new transactions to process on this channel
    tx_chan: TxChan,
    /// receive new blocks to process on this channel
    block_chan: BlockChan,
    /// receive registration requests for new transaction notifications
    register_new_tx_chan: NewTxChanChan,
    /// receive unregistration requests for new transactions
    unregister_new_tx_chan: NewTxChanChan,
    /// receive registration requests for tip change notifications
    register_tip_change_chan: TipChangeChanChan,
    /// receive unregistration requests for tip change notifications
    unregister_tip_change_chan: TipChangeChanChan,
    /// channels needing notification of newly processed transactions
    new_tx_channels: AsyncMutex<Vec<NewTxSenderChan>>,
    /// channels needing notification of changes to main chain tip blocks
    tip_change_channels: AsyncMutex<Vec<TipChangeSenderChan>>,
    shutdown_chan_rx: Mutex<Option<ShutdownChanReceiver>>,
}

/// Is a message sent to registered new transaction channels when a transaction is queued.
pub struct NewTx {
    /// transaction id
    pub transaction_id: TransactionID,
    /// new transaction
    pub transaction: Transaction,
    /// who sent it
    pub source: SocketAddr,
}

/// Message sent to registered new tip channels on main chain tip (dis-)connection..
pub struct TipChange {
    /// block ID of the main chain tip block
    pub block_id: BlockID,
    /// full block
    pub block: Block,
    /// who sent the block that caused this change
    pub source: SocketAddr,
    /// true if the tip has been connected. false for disconnected
    pub connect: bool,
    /// true if the tip has been connected and more connections are expected
    pub more: bool,
}

struct TxToProcess {
    /// transaction ID
    id: TransactionID,
    /// transaction to process
    tx: Transaction,
    /// who sent it
    source: SocketAddr,
    /// channel to receive the result
    result_chan: TransactionResultChan,
}

struct BlockToProcess {
    /// block ID
    id: BlockID,
    /// block to process
    block: Block,
    /// who sent it
    source: SocketAddr,
    /// channel to receive the result
    result_chan: BlockResultChan,
}

impl Processor {
    /// Returns a new Processor instance.
    pub fn new(
        genesis_id: &'static BlockID,
        block_store: Arc<BlockStorageDisk>,
        tx_queue: Arc<TransactionQueueMemory>,
        ledger: Arc<LedgerDisk>,
        shutdown_chan_rx: ShutdownChanReceiver,
    ) -> Arc<Self> {
        let tx_chan = channel(100);
        let block_chan = channel(10);
        let register_new_tx_chan = unbounded_channel();
        let unregister_new_tx_chan = unbounded_channel();
        let register_tip_change_chan = unbounded_channel();
        let unregister_tip_change_chan = unbounded_channel();

        Arc::new(Self {
            genesis_id,
            block_store,
            tx_queue,
            ledger,
            tx_chan: (tx_chan.0, Mutex::new(Some(tx_chan.1))),
            block_chan: (block_chan.0, Mutex::new(Some(block_chan.1))),
            register_new_tx_chan: (
                register_new_tx_chan.0,
                Mutex::new(Some(register_new_tx_chan.1)),
            ),
            unregister_new_tx_chan: (
                unregister_new_tx_chan.0,
                Mutex::new(Some(unregister_new_tx_chan.1)),
            ),
            register_tip_change_chan: (
                register_tip_change_chan.0,
                Mutex::new(Some(register_tip_change_chan.1)),
            ),
            unregister_tip_change_chan: (
                unregister_tip_change_chan.0,
                Mutex::new(Some(unregister_tip_change_chan.1)),
            ),
            new_tx_channels: AsyncMutex::new(Vec::new()),
            tip_change_channels: AsyncMutex::new(Vec::new()),
            shutdown_chan_rx: Mutex::new(Some(shutdown_chan_rx)),
        })
    }

    /// Spawns the Processor's main loop.
    pub fn spawn(self: &Arc<Self>) -> JoinHandle<Result<(), SpawnedError>> {
        let arc_self = Arc::clone(self);
        tokio::spawn(async move { arc_self.run().await.map_err(Into::into) })
    }

    /// Runs the Processor's main loop.
    /// It verifies and processes blocks and transactions.
    pub async fn run(&self) -> Result<(), ProcessorError> {
        let mut tx_chan_rx = self.tx_chan.1.lock().unwrap().take().unwrap();
        let mut block_chan_rx = self.block_chan.1.lock().unwrap().take().unwrap();
        let mut register_new_tx_chan_rx =
            self.register_new_tx_chan.1.lock().unwrap().take().unwrap();
        let mut unregister_new_tx_chan_rx = self
            .unregister_new_tx_chan
            .1
            .lock()
            .unwrap()
            .take()
            .unwrap();
        let mut register_tip_change_chan_rx = self
            .register_tip_change_chan
            .1
            .lock()
            .unwrap()
            .take()
            .unwrap();
        let mut unregister_tip_change_chan_rx = self
            .unregister_tip_change_chan
            .1
            .lock()
            .unwrap()
            .take()
            .unwrap();
        let mut shutdown_chan_rx = self.shutdown_chan_rx.lock().unwrap().take().unwrap();

        loop {
            tokio::select! {
                Some(tx_to_process) = tx_chan_rx.recv() => {
                    // process a transaction
                    let result = self.process_transaction(
                        tx_to_process.id,
                        tx_to_process.tx,
                        tx_to_process.source,
                    ).await;

                    if let Err(err) = tx_to_process.result_chan.send(result).map_err(ProcessTransactionError::from) {
                        error!("{err:?}");
                    }
                }

                Some(block_to_process) = block_chan_rx.recv() => {
                    // process a block
                    let txs_len = block_to_process.block.transactions.len();
                    let start = Instant::now();

                    let result = self.process_block(
                        block_to_process.id,
                        block_to_process.block,
                        block_to_process.source,
                    ).await;

                    let duration = start.elapsed();

                    info!(
                        "Processing took {:?}, {} transaction(s), transaction queue length: {}",
                        duration,
                        txs_len,
                        self.tx_queue.len()
                    );

                    // send back the result
                    if let Err(err) = block_to_process.result_chan.send(result).map_err(ProcessBlockError::from) {
                        error!("{err:?}");
                    }
                }

                Some(ch) = register_new_tx_chan_rx.recv() => {
                    let mut new_tx_channels = self.new_tx_channels.lock().await;
                    new_tx_channels.push(ch);
                }

                Some(ch) = unregister_new_tx_chan_rx.recv() => {
                    let mut new_tx_channels = self.new_tx_channels.lock().await;
                    if let Some(index) = new_tx_channels
                        .iter()
                        .position(|c| c.same_channel(&ch)) {
                            new_tx_channels.remove(index);
                        }
                }

                Some(ch) = register_tip_change_chan_rx.recv() => {
                    let mut tip_change_channels =
                        self.tip_change_channels.lock().await;
                    tip_change_channels.push(ch);
                }

                Some(ch) = unregister_tip_change_chan_rx.recv() => {
                    let mut tip_change_channels =
                        self.tip_change_channels.lock().await;
                    if let Some(index) = tip_change_channels
                        .iter()
                        .position(|c| c.same_channel(&ch)) {
                            tip_change_channels.remove(index);
                        }
                }

                _ = &mut shutdown_chan_rx => {
                    info!("Processor shutting down");
                    break Ok(())
                }
            }
        }
    }

    /// Is called to process a new candidate transaction from the transaction queue
    pub async fn process_candidate_transaction(
        &self,
        id: &TransactionID,
        tx: &Transaction,
        from: &SocketAddr,
    ) -> Result<(), ProcessTransactionError> {
        let (result_chan_tx, result_chan_rx) = oneshot::channel();
        self.tx_chan
            .0
            .send(TxToProcess {
                id: *id,
                tx: tx.clone(),
                source: *from,
                result_chan: result_chan_tx,
            })
            .await?;
        result_chan_rx.await?
    }

    /// Called to process a new candidate block chain tip.
    pub async fn process_candidate_block(
        &self,
        id: BlockID,
        block: Block,
        source: SocketAddr,
    ) -> Result<(), ProcessBlockError> {
        let (result_chan_tx, result_chan_rx) = oneshot::channel();
        let block_to_process = BlockToProcess {
            id,
            block,
            source,
            result_chan: result_chan_tx,
        };

        self.block_chan.0.send(block_to_process).await?;
        result_chan_rx.await?
    }

    /// Called to register to receive notifications of newly queued transactions.
    pub fn register_for_new_transactions(&self, new_tx_chan_tx: NewTxSenderChan) {
        self.register_new_tx_chan
            .0
            .send(new_tx_chan_tx)
            .expect("send on register new tx channel");
    }

    /// Called to unregister to receive notifications of newly queued transactions
    pub fn unregister_for_new_transactions(&self, new_tx_chan_tx: NewTxSenderChan) {
        self.unregister_new_tx_chan
            .0
            .send(new_tx_chan_tx)
            .expect("send on unregister new tx channel");
    }

    /// Called to register to receive notifications of tip block changes.
    pub fn register_for_tip_change(&self, tip_change_chan_tx: TipChangeSenderChan) {
        self.register_tip_change_chan
            .0
            .send(tip_change_chan_tx)
            .expect("send on register tip change channel")
    }

    /// Called to unregister to receive notifications of tip block changes.
    pub fn unregister_for_tip_change(&self, tip_change_chan_tx: TipChangeSenderChan) {
        self.unregister_tip_change_chan
            .0
            .send(tip_change_chan_tx)
            .expect("send on unregister tip change channel");
    }

    /// Process a transaction
    pub async fn process_transaction(
        &self,
        id: TransactionID,
        tx: Transaction,
        source: SocketAddr,
    ) -> Result<(), ProcessTransactionError> {
        info!("Processing transaction {id}");

        // min fee? if not waste no more time
        if tx.fee.expect("transaction should have a fee") < MIN_FEE_CRUZBITS {
            return Err(ProcessTransactionError::MinimumFee(
                id,
                (MIN_FEE_CRUZBITS / CRUZBITS_PER_CRUZ) as f64,
            ));
        }

        // min amount? if not waste no more time
        if tx.amount < MIN_AMOUNT_CRUZBITS {
            return Err(ProcessTransactionError::AmountTooSmall(
                id,
                (MIN_AMOUNT_CRUZBITS / CRUZBITS_PER_CRUZ) as f64,
            ));
        }

        // context-free checks
        Self::check_transaction(&id, &tx)?;

        // no loose coinbases
        if tx.is_coinbase() {
            return Err(ProcessTransactionError::CoinbaseInBlockOnly(id));
        }

        // is the queue full?
        if self.tx_queue.len() >= MAX_TRANSACTION_QUEUE_LENGTH as usize {
            return Err(ProcessTransactionError::QueueIsFull(id));
        }

        // is it confirmed already?
        if self.ledger.get_transaction_index(&id)?.is_some() {
            return Err(ProcessTransactionError::ConfirmedAlready(id));
        }

        // check series, maturity and expiration
        let Some((_block_id, tip_height)) = self.ledger.get_chain_tip()? else {
            return Err(LedgerNotFoundError::ChainTip.into());
        };

        // is the series current for inclusion in the next block?
        if !Self::check_transaction_series(&tx, tip_height + 1) {
            return Err(ProcessTransactionError::SeriesInvalid(id));
        }

        // would it be mature if included in the next block?
        if !tx.is_mature(tip_height + 1) {
            return Err(ProcessTransactionError::NotMature(id));
        }

        // is it expired if included in the next block?
        if tx.is_expired(tip_height + 1) {
            return Err(ProcessTransactionError::Expired(
                id,
                tip_height,
                tx.expires.expect("transaction should expire"),
            ));
        }

        // verify signature
        if !tx.verify()? {
            return Err(ProcessTransactionError::SignatureVerificationFailed(id));
        }

        // rejects a transaction if sender would have insufficient balance
        if !self.tx_queue.add(&id, &tx)? {
            // don't notify others if the transaction already exists in the queue
            return Ok(());
        }

        // notify channels
        let new_tx_channels = self.new_tx_channels.lock().await;
        for new_tx in new_tx_channels.iter() {
            if let Err(err) = new_tx
                .send(NewTx {
                    transaction_id: id,
                    transaction: tx.clone(),
                    source,
                })
                .await
                .map_err(ProcessTransactionError::from)
            {
                error!("{err:?}")
            }
        }
        Ok(())
    }

    /// Context-free transaction sanity checker
    fn check_transaction(
        id: &TransactionID,
        tx: &Transaction,
    ) -> Result<(), ProcessTransactionError> {
        // sane-ish time.
        // transaction timestamps are strictly for user and application usage.
        // we make no claims to their validity and rely on them for nothing.
        if tx.time > MAX_NUMBER {
            return Err(ProcessTransactionError::TimeTooLarge(*id));
        }

        // no nonces larger than i32
        if tx.nonce > i32::MAX as u32 {
            return Err(ProcessTransactionError::NonceTooLarge(*id));
        }

        if tx.is_coinbase() {
            // no sender in coinbase
            if tx.from.is_some() {
                return Err(ProcessTransactionError::CoinbaseSenderNotAllowed(*id));
            }

            // no fee in coinbase
            if tx.fee.is_some() {
                return Err(ProcessTransactionError::CoinbaseFeeNotAllowed(*id));
            }

            // no maturity for coinbase
            if tx.matures.is_some() {
                return Err(ProcessTransactionError::CoinbaseMaturityNotAllowed(*id));
            }

            // no expiration for coinbase
            if tx.expires.is_some() {
                return Err(ProcessTransactionError::CoinbaseExpired(*id));
            }

            // no signature on coinbase
            if tx.signature.is_some() {
                return Err(ProcessTransactionError::CoinbaseSignatureNotAllowed(*id));
            }
        } else {
            // sanity check sender
            if let Some(from) = tx.from {
                if from.len() != PublicKey::BYTES {
                    return Err(ProcessTransactionError::SenderInvalid(*id));
                }
            } else {
                return Err(ProcessTransactionError::SenderMissing(*id));
            }

            // sanity check fee
            if let Some(fee) = tx.fee {
                if fee > MAX_MONEY {
                    return Err(ProcessTransactionError::FeeTooLarge(*id));
                }
            } else {
                return Err(ProcessTransactionError::FeeMissing(*id));
            }

            // sanity check maturity
            if let Some(matures) = tx.matures {
                if matures > MAX_NUMBER {
                    return Err(ProcessTransactionError::MaturityTooLarge(*id));
                }
            }

            // sanity check expiration
            if let Some(expires) = tx.expires {
                if expires > MAX_NUMBER {
                    return Err(ProcessTransactionError::ExpirationTooLarge(*id));
                }
            }

            // sanity check signature
            if let Some(signature) = tx.signature {
                if signature.len() != Signature::BYTES {
                    return Err(ProcessTransactionError::SignatureInvalid(*id));
                }
            } else {
                return Err(ProcessTransactionError::SignatureMissing(*id));
            }
        }

        // sanity check recipient
        if tx.to.len() != PublicKey::BYTES {
            return Err(ProcessTransactionError::RecipientInvalid(*id));
        }

        // sanity check amount
        if tx.amount > MAX_MONEY {
            return Err(ProcessTransactionError::AmountTooLarge(*id));
        }

        if let Some(memo) = &tx.memo {
            // make sure memo is valid ascii/utf8
            if from_utf8(memo.as_bytes()).is_err() {
                return Err(ProcessTransactionError::MemoCharactersInvalid(*id));
            }
            // check memo length
            if memo.len() > MAX_MEMO_LENGTH {
                return Err(ProcessTransactionError::MemoLengthExceeded(*id));
            }
        }

        // sanity check series
        if tx.series > MAX_NUMBER {
            return Err(ProcessTransactionError::SeriesTooLarge(*id));
        }
        Ok(())
    }

    /// The series must be within the acceptable range given the current height
    pub fn check_transaction_series(tx: &Transaction, height: u64) -> bool {
        if tx.from.is_none() {
            // coinbases must start a new series right on time
            return tx.series == height / BLOCKS_UNTIL_NEW_SERIES + 1;
        }

        // user transactions have a grace period (1 full series) to mitigate effects
        // of any potential queueing delay and/or reorgs near series switchover time
        let high = height / BLOCKS_UNTIL_NEW_SERIES + 1;
        let mut low = high - 1;

        if low == 0 {
            low = 1;
        }

        tx.series >= low && tx.series <= high
    }

    /// Process a block
    pub async fn process_block(
        &self,
        id: BlockID,
        block: Block,
        source: SocketAddr,
    ) -> Result<(), ProcessBlockError> {
        info!("Processing block {id}");

        // did we process this block already?
        let branch_type = self.ledger.get_branch_type(&id)?;

        if branch_type != BranchType::Unknown {
            info!("Already processed block {id}");
            return Ok(());
        }

        // sanity check the block
        let now = now_as_secs();
        Self::check_block(&id, &block, now)?;

        // have we processed its parent?
        let branch_type = self.ledger.get_branch_type(&block.header.previous)?;

        if branch_type != BranchType::Main && branch_type != BranchType::Side {
            if id == *self.genesis_id {
                // store it
                self.block_store.store(&id, &block, now)?;
                // begin the ledger
                self.connect_block(&id, &block, &source, false).await?;
                info!("Connected block {id}");
                return Ok(());
            }

            // current block is an orphan
            return Err(ProcessBlockError::Orphan(id));
        }

        // attempt to extend the chain
        self.accept_block(&id, &block, now, source).await
    }

    /// Context-free block sanity checker
    fn check_block(id: &BlockID, block: &Block, now: u64) -> Result<(), ProcessBlockError> {
        // sanity check time
        if block.header.time > MAX_NUMBER {
            return Err(ProcessBlockError::TimeTooLarge(*id));
        }

        // check timestamp isn't too far in the future
        if block.header.time > now + MAX_FUTURE_SECONDS {
            return Err(ProcessBlockError::TimestampInvalid(
                block.header.time,
                now,
                *id,
            ));
        }

        // proof-of-work should satisfy declared target
        if !block.check_pow(id) {
            return Err(ProcessBlockError::ProofOfWorkInsufficient(*id));
        }

        // sanity check nonce
        if block.header.nonce > MAX_NUMBER {
            return Err(ProcessBlockError::NonceTooLarge(*id));
        }

        // sanity check height
        if block.header.height > MAX_NUMBER {
            return Err(ProcessBlockError::HeightTooLarge(*id));
        }

        // check against known checkpoints
        checkpoint_check(id, block.header.height)?;

        // sanity check transaction count
        if block.header.transaction_count > MAX_TRANSACTIONS_PER_BLOCK {
            return Err(ProcessBlockError::TransactionCountTooLarge(*id));
        }

        if block.header.transaction_count as usize != block.transactions.len() {
            return Err(ProcessBlockError::TransactionCountMismatch(*id));
        }

        // must have at least one transaction
        if block.transactions.is_empty() {
            return Err(ProcessBlockTransactionsError::Missing(*id).into());
        }

        // first tx must be a coinbase
        if !block.transactions[0].is_coinbase() {
            return Err(ProcessBlockTransactionsError::CoinbaseMissing(*id).into());
        }

        // check max number of transactions
        let max = Self::compute_max_transactions_per_block(block.header.height);

        if block.transactions.len() > max as usize {
            return Err(ProcessBlockTransactionsError::Exceeded(
                *id,
                block.transactions.len(),
                max,
            )
            .into());
        }

        // the rest must not be coinbases
        if block.transactions.len() > 1 {
            for transaction in block.transactions[1..].iter() {
                if transaction.is_coinbase() {
                    return Err(ProcessBlockTransactionsError::CoinbaseMultiple(*id).into());
                }
            }
        }

        // basic transaction checks that don't depend on context
        let mut tx_ids = HashMap::new();
        for tx in block.transactions.iter() {
            let id = tx.id()?;
            Self::check_transaction(&id, tx)?;
            tx_ids.insert(id, true);
        }

        // check for duplicate transactions
        if tx_ids.len() != block.transactions.len() {
            return Err(ProcessBlockTransactionsError::Duplicate(*id).into());
        }

        // verify hash list root
        let mut hasher = Sha3_256::new();
        let hash_list_root = compute_hash_list_root(&mut hasher, &block.transactions)?;

        if hash_list_root != block.header.hash_list_root {
            return Err(ProcessBlockError::HashListRootMismatch(*id));
        }
        Ok(())
    }

    /// Computes the maximum number of transactions allowed in a block at the given height. Inspired by BIP 101
    pub fn compute_max_transactions_per_block(height: u64) -> u32 {
        if height >= MAX_TRANSACTIONS_PER_BLOCK_EXCEEDED_AT_HEIGHT {
            // I guess we can revisit this sometime in the next 35 years if necessary
            return MAX_TRANSACTIONS_PER_BLOCK;
        }

        // piecewise-linear-between-doublings growth
        let doublings = height / BLOCKS_UNTIL_TRANSACTIONS_PER_BLOCK_DOUBLING;
        if doublings >= 64 {
            panic!("Overflow uint64")
        }
        let remainder = height % BLOCKS_UNTIL_TRANSACTIONS_PER_BLOCK_DOUBLING;
        let factor = 1 << doublings;

        let interpolate = INITIAL_MAX_TRANSACTIONS_PER_BLOCK as u64 * factor as u64 * remainder
            / BLOCKS_UNTIL_TRANSACTIONS_PER_BLOCK_DOUBLING;
        INITIAL_MAX_TRANSACTIONS_PER_BLOCK * factor + interpolate as u32
    }

    /// Attempt to extend the chain with the new block
    async fn accept_block(
        &self,
        id: &BlockID,
        block: &Block,
        now: u64,
        source: SocketAddr,
    ) -> Result<(), ProcessBlockError> {
        let Some((prev_header, _height)) =
            self.block_store.get_block_header(&block.header.previous)?
        else {
            return Err(BlockStorageNotFoundError::BlockHeader(block.header.previous).into());
        };

        // check height
        let new_height = prev_header.height + 1;
        if block.header.height != new_height {
            return Err(ProcessBlockError::HeightMismatch(
                new_height,
                block.header.height,
                *id,
            ));
        }

        // did we process it already?
        let branch_type = self.ledger.get_branch_type(id)?;

        if branch_type != BranchType::Unknown {
            info!("Already processed block {id}");
            return Ok(());
        }

        // check declared proof of work is correct
        let target = Self::compute_target(&prev_header, &self.block_store, &self.ledger)?;

        if block.header.target != target {
            return Err(ProcessBlockError::TargetInvalid(
                block.header.target,
                target,
                *id,
            ));
        }

        // check that cumulative work is correct
        let chain_work = compute_chain_work(&block.header.target, &prev_header.chain_work);
        if block.header.chain_work != chain_work {
            return Err(ProcessBlockError::ChainWorkInvalid(
                block.header.chain_work,
                chain_work,
                *id,
            ));
        }

        // check that the timestamp isn't too far in the past
        let median_timestamp = Self::compute_median_timestamp(&prev_header, &self.block_store)?;

        if block.header.time <= median_timestamp {
            return Err(ProcessBlockError::TimestampTooEarly(*id));
        }

        // check series, maturity, expiration then verify signatures and calculate total fees
        let mut fees = 0;

        for tx in &block.transactions {
            let tx_id = tx.id()?;

            if !Self::check_transaction_series(tx, block.header.height) {
                return Err(ProcessBlockTransactionsError::SeriesInvalid(tx_id).into());
            }

            if !tx.is_coinbase() {
                if !tx.is_mature(block.header.height) {
                    return Err(ProcessBlockTransactionsError::Immature(tx_id).into());
                }

                if tx.is_expired(block.header.height) {
                    return Err(ProcessBlockTransactionsError::Expired(
                        tx_id,
                        block.header.height,
                        tx.expires.expect("should not be none"),
                    )
                    .into());
                }

                // if it's in the queue with the same signature we've verified it already
                if !self
                    .tx_queue
                    .exists_signed(&tx_id, tx.signature.expect("signature"))
                {
                    match tx.verify() {
                        Ok(ok) => {
                            if !ok {
                                return Err(
                                    ProcessBlockTransactionsError::SignatureVerificationFailed(
                                        tx_id,
                                    )
                                    .into(),
                                );
                            }
                        }
                        Err(err) => {
                            return Err(err.into());
                        }
                    };
                }

                if let Some(fee) = tx.fee {
                    fees += fee;
                } else {
                    return Err(ProcessBlockTransactionsError::FeeMissing(tx_id).into());
                }
            }
        }

        // verify coinbase reward
        let reward = Self::block_creation_reward(block.header.height) + fees;
        if block.transactions[0].amount != reward {
            // in cruzbit every last issued bit must be accounted for in public key balances
            return Err(ProcessBlockTransactionsError::CoinbaseInvalidAmount(*id).into());
        }

        // store the block if we think we're going to accept it
        self.block_store.store(id, block, now)?;

        // get the current tip before we try adjusting the chain
        let Some((tip_id, _height)) = self.ledger.get_chain_tip()? else {
            return Err(LedgerNotFoundError::ChainTip.into());
        };

        // finish accepting the block if possible
        if let Err(err) = self
            .accept_block_continue(id, block, now, prev_header, &source)
            .await
        {
            // we may have disconnected the old best chain and partially
            // connected the new one before encountering a problem. re-activate it now
            if let Err(err2) = self.reconnect_tip(&tip_id, &source).await {
                info!("Error reconnecting tip: {err2}, block: {tip_id}");
            }

            // return the original error
            return Err(err);
        }
        Ok(())
    }

    /// Computes the expected block reward for the given height.
    pub fn block_creation_reward(height: u64) -> u64 {
        let halvings = height / BLOCKS_UNTIL_REWARD_HALVING;
        if halvings >= 64 {
            return 0;
        }
        INITIAL_COINBASE_REWARD >> halvings
    }

    /// Compute the median timestamp of the last NUM_BLOCKS_FOR_MEDIAN_TIMESTAMP blocks
    /// Convenience method to get the current main chain's tip ID, header, and storage time.
    /// Compute expected target of the current block
    pub fn compute_target<T: BlockStorage, U: Ledger>(
        prev_header: &BlockHeader,
        block_store: &Arc<T>,
        ledger: &Arc<U>,
    ) -> Result<BlockID, ProcessBlockError> {
        if prev_header.height >= BITCOIN_CASH_RETARGET_ALGORITHM_HEIGHT {
            return Self::compute_target_bitcoin_cash(prev_header, block_store, ledger);
        }

        Self::compute_target_bitcoin(prev_header, block_store)
    }

    /// Original target computation
    pub fn compute_target_bitcoin<U: BlockStorage>(
        prev_header: &BlockHeader,
        block_store: &Arc<U>,
    ) -> Result<BlockID, ProcessBlockError> {
        if (prev_header.height + 1) % RETARGET_INTERVAL != 0 {
            // not 2016th block, use previous block's value
            return Ok(prev_header.target);
        }

        // defend against time warp attack
        let mut blocks_to_go_back = RETARGET_INTERVAL - 1;
        if (prev_header.height + 1) != RETARGET_INTERVAL {
            blocks_to_go_back = RETARGET_INTERVAL;
        }

        // walk back to the first block of the interval
        let mut first_header = prev_header.clone();
        for _ in 0..blocks_to_go_back {
            let Some((block_header, _when)) =
                block_store.get_block_header(&first_header.previous)?
            else {
                return Err(BlockStorageNotFoundError::BlockHeader(first_header.previous).into());
            };
            first_header = block_header;
        }

        let mut actual_timespan = prev_header.time - first_header.time;

        let min_timespan = RETARGET_TIME / 4;
        let max_timespan = RETARGET_TIME * 4;

        if actual_timespan < min_timespan {
            actual_timespan = min_timespan;
        }
        if actual_timespan > max_timespan {
            actual_timespan = max_timespan;
        }

        let actual_timespan_int = UBig::from(actual_timespan);
        let retarget_time_int = UBig::from(RETARGET_TIME);

        let mut initial_target_bytes = BlockID::new();
        hex_decode(INITIAL_TARGET.as_bytes(), &mut initial_target_bytes)
            .map_err(EncodingError::HexDecode)?;

        let max_target_int = UBig::from_be_bytes(&initial_target_bytes[..]);
        let prev_target_int = UBig::from_be_bytes(&prev_header.target[..]);
        let new_target_int = prev_target_int * actual_timespan_int;
        let new_target_int = new_target_int / retarget_time_int;

        let target = if new_target_int > max_target_int {
            BlockID::from(max_target_int)
        } else {
            BlockID::from(new_target_int)
        };
        Ok(target)
    }

    /// Revised target computation
    fn compute_target_bitcoin_cash<T: Ledger, U: BlockStorage>(
        prev_header: &BlockHeader,
        block_store: &Arc<U>,
        ledger: &Arc<T>,
    ) -> Result<BlockID, ProcessBlockError> {
        let Some(first_id) =
            ledger.get_block_id_for_height(prev_header.height - RETARGET_SMA_WINDOW)?
        else {
            return Err(LedgerNotFoundError::BlockIDForHeight(prev_header.height).into());
        };

        let Some((first_header, _when)) = block_store.get_block_header(&first_id)? else {
            return Err(BlockStorageNotFoundError::BlockHeader(first_id).into());
        };

        let work_int = prev_header.chain_work.as_big_int() - first_header.chain_work.as_big_int();
        let work_int = work_int * UBig::from(TARGET_SPACING);

        // "In order to avoid difficulty cliffs, we bound the amplitude of the
        // adjustment we are going to do to a factor in [0.5, 2]." - Bitcoin-ABC
        let mut actual_timespan = prev_header.time - first_header.time;
        if actual_timespan > 2 * RETARGET_SMA_WINDOW * TARGET_SPACING {
            actual_timespan = 2 * RETARGET_SMA_WINDOW * TARGET_SPACING;
        } else if actual_timespan < (RETARGET_SMA_WINDOW / 2) * TARGET_SPACING {
            actual_timespan = (RETARGET_SMA_WINDOW / 2) * TARGET_SPACING;
        }

        let work_int = work_int / actual_timespan;

        // T = (2^256 / W) - 1
        let max_int = UBig::from(2u8).pow(256);
        let new_target_int = max_int / work_int;
        let new_target_int = new_target_int - UBig::from(1u8);

        // don't go above the initial target
        let mut initial_target_bytes = BlockID::new();
        hex_decode(INITIAL_TARGET.as_bytes(), &mut initial_target_bytes)
            .map_err(EncodingError::HexEncode)?;

        let max_target_int = UBig::from_be_bytes(&initial_target_bytes);

        let target_id = if new_target_int > max_target_int {
            BlockID::from(max_target_int)
        } else {
            BlockID::from(new_target_int)
        };
        Ok(target_id)
    }

    /// Compute the median timestamp of the last NUM_BLOCKS_FOR_MEDIAN_TIMESTAMP blocks
    pub fn compute_median_timestamp(
        prev_header: &BlockHeader,
        block_store: &Arc<BlockStorageDisk>,
    ) -> Result<u64, ProcessorError> {
        let mut prev_header = prev_header.clone();
        let mut timestamps = Vec::new();

        for _ in 0..NUM_BLOCKS_FOR_MEDIAN_TIMESTAMP {
            timestamps.push(prev_header.time);
            prev_header = match block_store.get_block_header(&prev_header.previous)? {
                Some((block_header, _when)) => block_header,
                None => break,
            };
        }
        timestamps.sort();
        Ok(timestamps.remove(timestamps.len() / 2))
    }

    /// Continue accepting the block
    async fn accept_block_continue(
        &self,
        id: &BlockID,
        block: &Block,
        block_when: u64,
        prev_header: BlockHeader,
        source: &SocketAddr,
    ) -> Result<(), ProcessBlockError> {
        // get the current tip
        let Some((tip_id, tip_header, tip_when)) =
            Self::get_chain_tip_header(&self.ledger, &self.block_store)?
        else {
            return Err(LedgerNotFoundError::ChainTipHeader.into());
        };

        if *id == tip_id {
            // can happen if we failed connecting a new block
            return Ok(());
        }

        // is this block better than the current tip?
        if !block.header.compare(&tip_header, block_when, tip_when) {
            // flag this as a side branch block
            info!("Block {id} does not represent the tip of the best chain");
            return self
                .ledger
                .set_branch_type(id, BranchType::Side)
                .map_err(ProcessBlockError::Ledger);
        }

        // the new block is the better chain
        let mut tip_ancestor = tip_header;
        let mut new_ancestor = prev_header;

        let mut min_height = tip_ancestor.height;
        if new_ancestor.height < min_height {
            min_height = new_ancestor.height;
        }

        let mut blocks_to_disconnect = Vec::new();
        let mut blocks_to_connect = Vec::new();

        // walk back each chain to the common min_height
        let mut tip_ancestor_id = tip_id;
        while tip_ancestor.height > min_height {
            blocks_to_disconnect.push(tip_ancestor_id);
            tip_ancestor_id = tip_ancestor.previous;
            let Some((block_header, _when)) =
                self.block_store.get_block_header(&tip_ancestor_id)?
            else {
                return Err(BlockStorageNotFoundError::BlockHeader(tip_ancestor_id).into());
            };
            tip_ancestor = block_header;
        }

        let mut new_ancestor_id = block.header.previous;
        while new_ancestor.height > min_height {
            blocks_to_connect.insert(0, new_ancestor_id);
            new_ancestor_id = new_ancestor.previous;

            let Some((block_header, _when)) =
                self.block_store.get_block_header(&new_ancestor_id)?
            else {
                return Err(BlockStorageNotFoundError::BlockHeader(new_ancestor_id).into());
            };
            new_ancestor = block_header;
        }

        // scan both chains until we get to the common ancestor
        while new_ancestor != tip_ancestor {
            blocks_to_disconnect.push(tip_ancestor_id);
            blocks_to_connect.insert(0, new_ancestor_id);
            tip_ancestor_id = tip_ancestor.previous;

            let Some((block_header, _when)) =
                self.block_store.get_block_header(&tip_ancestor_id)?
            else {
                return Err(BlockStorageNotFoundError::BlockHeader(tip_ancestor_id).into());
            };
            tip_ancestor = block_header;
            new_ancestor_id = new_ancestor.previous;

            let Some((block_header, _when)) =
                self.block_store.get_block_header(&new_ancestor_id)?
            else {
                return Err(BlockStorageNotFoundError::BlockHeader(new_ancestor_id).into());
            };
            new_ancestor = block_header;
        }

        // we're at common ancestor. disconnect any main chain blocks we need to
        for id in blocks_to_disconnect {
            let Some(block_to_disconnect) = self.block_store.get_block(&id)? else {
                return Err(BlockStorageNotFoundError::Block(id).into());
            };

            self.disconnect_block(&id, &block_to_disconnect, source)
                .await?;
        }

        // connect any new chain blocks we need to
        for id in blocks_to_connect {
            let Some(blocks_to_connect) = self.block_store.get_block(&id)? else {
                return Err(BlockStorageNotFoundError::Block(id).into());
            };

            self.connect_block(&id, &blocks_to_connect, source, true)
                .await?;
        }

        // and finally connect the new block
        self.connect_block(id, block, source, false).await
    }

    /// Update the ledger and transaction queue and notify undo tip channels
    async fn disconnect_block(
        &self,
        id: &BlockID,
        block: &Block,
        source: &SocketAddr,
    ) -> Result<(), ProcessorError> {
        // Update the ledger
        let tx_ids = self.ledger.disconnect_block(id, block)?;

        info!(
            "Block {} has been disconnected, height: {}",
            &id, block.header.height
        );

        // Add newly disconnected non-coinbase transactions back to the queue
        self.tx_queue
            .add_batch(&tx_ids[1..], &block.transactions[1..]);

        // Notify tip change channels
        let tip_change_channels = self.tip_change_channels.lock().await;
        for tip_tx in tip_change_channels.iter() {
            if let Err(err) = tip_tx
                .send(TipChange {
                    block_id: *id,
                    block: block.clone(),
                    source: *source,
                    connect: false,
                    more: false,
                })
                .map_err(ProcessorError::from)
            {
                error!("{err:?}");
            }
        }
        Ok(())
    }

    /// Update the ledger and transaction queue and notify new tip channels
    async fn connect_block(
        &self,
        id: &BlockID,
        block: &Block,
        source: &SocketAddr,
        more: bool,
    ) -> Result<(), ProcessBlockError> {
        // Update the ledger
        let tx_ids = self.ledger.connect_block(id, block)?;

        info!(
            "Block {} is the new tip, height: {}",
            id, block.header.height
        );

        // Remove newly confirmed non-coinbase transactions from the queue
        self.tx_queue
            .remove_batch(&tx_ids[1..], block.header.height, more)?;

        // Notify tip change channels
        let tip_change_channels = self.tip_change_channels.lock().await;

        for tip_tx in tip_change_channels.iter() {
            if let Err(err) = tip_tx
                .send(TipChange {
                    block_id: *id,
                    block: block.clone(),
                    source: *source,
                    connect: true,
                    more,
                })
                .map_err(ProcessBlockError::from)
            {
                error!("{err:?}");
            }
        }
        Ok(())
    }

    /// Try to reconnect the previous tip block when accept_block_continue fails for the new block
    async fn reconnect_tip(
        &self,
        id: &BlockID,
        source: &SocketAddr,
    ) -> Result<(), ProcessBlockError> {
        let Some(block) = self.block_store.get_block(id)? else {
            return Err(BlockStorageNotFoundError::Block(*id).into());
        };

        let Some((_block_header, when)) = self.block_store.get_block_header(id)? else {
            return Err(BlockStorageNotFoundError::BlockHeader(*id).into());
        };

        let Some((prev_header, _when)) =
            self.block_store.get_block_header(&block.header.previous)?
        else {
            return Err(BlockStorageNotFoundError::BlockHeader(block.header.previous).into());
        };

        self.accept_block_continue(id, &block, when, prev_header, source)
            .await
    }

    /// Convenience method to get the current main chain's tip ID, header, and storage time.
    pub fn get_chain_tip_header<T: Ledger, U: BlockStorage>(
        ledger: &Arc<T>,
        block_store: &Arc<U>,
    ) -> Result<Option<(BlockID, BlockHeader, u64)>, ProcessorError> {
        let Some((tip_id, _height)) = ledger.get_chain_tip()? else {
            return Ok(None);
        };

        // get the header
        let Some((tip_header, tip_when)) = block_store.get_block_header(&tip_id)? else {
            return Err(BlockStorageNotFoundError::BlockHeader(tip_id).into());
        };
        Ok(Some((tip_id, tip_header, tip_when)))
    }
}

#[derive(Error, Debug)]
pub enum ProcessorError {
    #[error("block storage")]
    BlockStorage(#[from] BlockStorageError),
    #[error("block storage not found")]
    BlockStorageNotFound(#[from] BlockStorageNotFoundError),
    #[error("channel")]
    Channel(#[from] ChannelError),
    #[error("ledger")]
    Ledger(#[from] LedgerError),
}

impl From<tokio::sync::mpsc::error::SendError<TipChange>> for ProcessorError {
    fn from(err: tokio::sync::mpsc::error::SendError<TipChange>) -> Self {
        Self::Channel(ChannelError::Send("tip change", err.to_string()))
    }
}

impl From<tokio::sync::oneshot::error::RecvError> for ProcessorError {
    fn from(err: tokio::sync::oneshot::error::RecvError) -> Self {
        Self::Channel(ChannelError::OneshotReceive("block result", err))
    }
}

#[derive(Error)]
pub enum ProcessBlockError {
    #[error("chain work invalid {0}, expected {1} for block {2}")]
    ChainWorkInvalid(BlockID, BlockID, BlockID),
    #[error("hash list root mismatch for block {0}")]
    HashListRootMismatch(BlockID),
    #[error("expected height {0} found {1} for block {2}")]
    HeightMismatch(u64, u64, BlockID),
    #[error("height value is too large, block {0}")]
    HeightTooLarge(BlockID),
    #[error("nonce value is too large, block {0}")]
    NonceTooLarge(BlockID),
    #[error("block {0} is an orphan")]
    Orphan(BlockID),
    #[error("proof-of-work insufficient for block {0}")]
    ProofOfWorkInsufficient(BlockID),
    #[error("target is invalid {0}, expected {1} for block {2}")]
    TargetInvalid(BlockID, BlockID, BlockID),
    #[error("time value is too large, block {0}")]
    TimeTooLarge(BlockID),
    #[error("timestamp {0} too far in the future, now {1}, block {2}")]
    TimestampInvalid(u64, u64, BlockID),
    #[error("timestamp is too early for block {0}")]
    TimestampTooEarly(BlockID),
    #[error("transaction count in header doesn't match block {0}")]
    TransactionCountMismatch(BlockID),
    #[error("transaction count too large in header of block {0}")]
    TransactionCountTooLarge(BlockID),

    #[error("block")]
    Block(#[from] BlockError),
    #[error("block storage")]
    BlockStorage(#[from] BlockStorageError),
    #[error("block storage not found")]
    BlockStorageNotFound(#[from] BlockStorageNotFoundError),
    #[error("channel")]
    Channel(#[from] ChannelError),
    #[error("checkpoint")]
    Checkpoint(#[from] CheckpointError),
    #[error("encoding")]
    Encoding(#[from] EncodingError),
    #[error("ledger")]
    Ledger(#[from] LedgerError),
    #[error("ledger not found")]
    LedgerNotFound(#[from] LedgerNotFoundError),
    #[error("processing block transactions")]
    ProcessBlockTransactions(#[from] ProcessBlockTransactionsError),
    #[error("processing transaction")]
    ProcessTransaction(#[from] ProcessTransactionError),
    #[error("processor")]
    Processor(#[source] Box<ProcessorError>),
    #[error("transaction")]
    Transaction(#[from] TransactionError),
    #[error("transaction queue")]
    TransactionQueue(#[from] TransactionQueueError),
}

// needs boxed because it's recursive
impl From<ProcessorError> for ProcessBlockError {
    fn from(value: ProcessorError) -> Self {
        Self::Processor(Box::new(value))
    }
}

impl From<tokio::sync::mpsc::error::SendError<BlockToProcess>> for ProcessBlockError {
    fn from(err: tokio::sync::mpsc::error::SendError<BlockToProcess>) -> Self {
        Self::Channel(ChannelError::Send("block", err.to_string()))
    }
}

impl From<tokio::sync::mpsc::error::SendError<TipChange>> for ProcessBlockError {
    fn from(err: tokio::sync::mpsc::error::SendError<TipChange>) -> Self {
        Self::Channel(ChannelError::Send("tip change", err.to_string()))
    }
}

impl From<tokio::sync::oneshot::error::RecvError> for ProcessBlockError {
    fn from(err: tokio::sync::oneshot::error::RecvError) -> Self {
        Self::Channel(ChannelError::OneshotReceive("process block result", err))
    }
}

impl From<Result<(), ProcessBlockError>> for ProcessBlockError {
    fn from(_err: Result<(), ProcessBlockError>) -> Self {
        Self::Channel(ChannelError::OneshotSend("process block result"))
    }
}

impl_debug_error_chain!(ProcessBlockError, "processing blocking");

#[derive(Error, Debug)]
pub enum ProcessBlockTransactionsError {
    #[error("coinbase pays incorrect amount, block {0}")]
    CoinbaseInvalidAmount(BlockID),
    #[error("first transaction is not a coinbase in block {0}")]
    CoinbaseMissing(BlockID),
    #[error("multiple coinbase transactions in block {0}")]
    CoinbaseMultiple(BlockID),
    #[error("duplicate transaction in block {0}")]
    Duplicate(BlockID),
    #[error("block {0} contains too many transactions {1}, max: {2}")]
    Exceeded(BlockID, usize, u32),
    #[error("transaction {0} is expired, height: {1}, expires: {2}")]
    Expired(TransactionID, u64, u64),
    #[error("missing transaction fee, transaction: {0}")]
    FeeMissing(TransactionID),
    #[error("transaction {0} is immature")]
    Immature(TransactionID),
    #[error("no transactions in block {0}")]
    Missing(BlockID),
    #[error("transaction {0} would have an invalid series")]
    SeriesInvalid(TransactionID),
    #[error("signature verification failed, transaction: {0}")]
    SignatureVerificationFailed(TransactionID),
}

#[derive(Error)]
pub enum ProcessTransactionError {
    #[error("transaction {0} contains too large of an amount")]
    AmountTooLarge(TransactionID),
    #[error("transaction {0} amount too small, minimum is {1:.6}")]
    AmountTooSmall(TransactionID, f64),
    #[error("coinbase can't expire, transaction: {0}")]
    CoinbaseExpired(TransactionID),
    #[error("coinbase can't have a fee, transaction: {0}")]
    CoinbaseFeeNotAllowed(TransactionID),
    #[error("coinbase transaction {0} only allowed in block")]
    CoinbaseInBlockOnly(TransactionID),
    #[error("coinbase can't have a maturity, transaction: {0}")]
    CoinbaseMaturityNotAllowed(TransactionID),
    #[error("coinbase can't have a sender, transaction: {0}")]
    CoinbaseSenderNotAllowed(TransactionID),
    #[error("coinbase can't have a signature, transaction: {0}")]
    CoinbaseSignatureNotAllowed(TransactionID),
    #[error("transaction {0} is already confirmed")]
    ConfirmedAlready(TransactionID),
    #[error("expiration missing, transaction: {0}")]
    ExpirationMissing(TransactionID),
    #[error("expiration too large, transaction: {0}")]
    ExpirationTooLarge(TransactionID),
    #[error("transaction {0} is expired, height: {1}, expires: {2}")]
    Expired(TransactionID, u64, u64),
    #[error("transaction fee missing, transaction: {0}")]
    FeeMissing(TransactionID),
    #[error("transaction {0} contains too large of a fee")]
    FeeTooLarge(TransactionID),
    #[error("transaction {0} is immature")]
    Immature(TransactionID),
    #[error("maturity too large, transaction: {0}")]
    MaturityTooLarge(TransactionID),
    #[error("transaction {0} memo contains invalid utf8 characters")]
    MemoCharactersInvalid(TransactionID),
    #[error("transaction {0} memo length exceeded")]
    MemoLengthExceeded(TransactionID),
    #[error("transaction {0} doesn't pay minimum fee {1:.6}")]
    MinimumFee(TransactionID, f64),
    #[error("nonce value is too large, transaction: {0}")]
    NonceTooLarge(TransactionID),
    #[error("transaction {0} would not be mature")]
    NotMature(TransactionID),
    #[error("no room for transaction {0}, queue is full")]
    QueueIsFull(TransactionID),
    #[error("transaction {0} missing recipient")]
    RecipientInvalid(TransactionID),
    #[error("transaction sender invalid, transaction: {0}")]
    SenderInvalid(TransactionID),
    #[error("transaction sender missing, transaction: {0}")]
    SenderMissing(TransactionID),
    #[error("series invalid, transaction: {0}")]
    SeriesInvalid(TransactionID),
    #[error("series missing, transaction: {0}")]
    SeriesMissing(TransactionID),
    #[error("series too large, transaction: {0}")]
    SeriesTooLarge(TransactionID),
    #[error("transaction signature invalid, transaction: {0}")]
    SignatureInvalid(TransactionID),
    #[error("transaction signature missing, transaction: {0}")]
    SignatureMissing(TransactionID),
    #[error("signature verification failed, transaction: {0}")]
    SignatureVerificationFailed(TransactionID),
    #[error("transaction time too large, transaction: {0}")]
    TimeTooLarge(TransactionID),

    #[error("failed to get transaction index for transaction {0}")]
    LedgerGetTransactionIndex(TransactionID, #[source] LedgerError),

    #[error("channel")]
    Channel(#[from] ChannelError),
    #[error("ledger")]
    Ledger(#[from] LedgerError),
    #[error("ledger not found")]
    LedgerNotFound(#[from] LedgerNotFoundError),
    #[error("transaction")]
    Transaction(#[from] TransactionError),
    #[error("transaction queue")]
    TransactionQueue(#[from] TransactionQueueError),
}

impl From<tokio::sync::mpsc::error::SendError<NewTx>> for ProcessTransactionError {
    fn from(err: tokio::sync::mpsc::error::SendError<NewTx>) -> Self {
        Self::Channel(ChannelError::Send("new tx", err.to_string()))
    }
}

impl From<tokio::sync::mpsc::error::SendError<TxToProcess>> for ProcessTransactionError {
    fn from(err: tokio::sync::mpsc::error::SendError<TxToProcess>) -> Self {
        Self::Channel(ChannelError::Send("tx to process", err.to_string()))
    }
}

impl From<tokio::sync::oneshot::error::RecvError> for ProcessTransactionError {
    fn from(err: tokio::sync::oneshot::error::RecvError) -> Self {
        Self::Channel(ChannelError::OneshotReceive("tx result", err))
    }
}

impl From<Result<(), ProcessTransactionError>> for ProcessTransactionError {
    fn from(_err: Result<(), ProcessTransactionError>) -> Self {
        Self::Channel(ChannelError::OneshotSend("process transaction result"))
    }
}

impl_debug_error_chain!(ProcessTransactionError, "processing transaction");

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_block_creation_reward() {
        let max_halvings = 64;
        let mut previous = INITIAL_COINBASE_REWARD * 2;
        for halvings in 0..max_halvings {
            let height = halvings * BLOCKS_UNTIL_REWARD_HALVING;
            let reward = Processor::block_creation_reward(height);
            assert!(
                reward <= INITIAL_COINBASE_REWARD,
                "Reward {reward} at height {height} greater than initial reward {INITIAL_COINBASE_REWARD}",
            );
            assert_eq!(
                reward,
                previous / 2,
                "Reward {reward} at height {height} not equal to half previous period reward",
            );
            previous = reward
        }
        assert_eq!(
            Processor::block_creation_reward(max_halvings * BLOCKS_UNTIL_REWARD_HALVING),
            0,
            "Expected 0 reward by {max_halvings} halving"
        );
    }

    #[test]
    fn test_compute_max_transactions_per_block() {
        let max_doublings = 64;
        let mut previous = INITIAL_MAX_TRANSACTIONS_PER_BLOCK / 2;

        // verify the max is always doubling as expected
        for doublings in 0..max_doublings {
            let mut height = doublings * BLOCKS_UNTIL_TRANSACTIONS_PER_BLOCK_DOUBLING;
            let max = Processor::compute_max_transactions_per_block(height);
            assert!(
                max >= INITIAL_MAX_TRANSACTIONS_PER_BLOCK,
                "Max {max} at height {height} less than initial"
            );

            let mut expect = previous * 2;
            if expect > MAX_TRANSACTIONS_PER_BLOCK {
                expect = MAX_TRANSACTIONS_PER_BLOCK;
            }
            assert_eq!(
                max, expect,
                "Max {max} at height {height} not equal to expected max {expect}"
            );

            if doublings > 0 {
                let mut previous2 = max;
                // walk back over the previous period and make sure:
                // 1) the max is never greater than this period's first max
                // 2) the max is always <= the previous as we walk back
                height -= 1;
                while height >= (doublings - 1) * BLOCKS_UNTIL_TRANSACTIONS_PER_BLOCK_DOUBLING {
                    let max2 = Processor::compute_max_transactions_per_block(height);
                    assert!(
                        max2 <= max,
                        "Max {max2} at height {height} is greater than next period's first max {max}",
                    );
                    assert!(
                        max2 <= previous2,
                        "Max {} at height {} is greater than previous max {} at height {}",
                        max2,
                        height,
                        previous2,
                        height + 1,
                    );
                    previous2 = max2;
                    if let Some(new_height) = height.checked_sub(1) {
                        height = new_height;
                    } else {
                        break;
                    }
                }
            }
            previous = max;
        }
        let max = Processor::compute_max_transactions_per_block(
            MAX_TRANSACTIONS_PER_BLOCK_EXCEEDED_AT_HEIGHT,
        );
        assert_eq!(
            max, MAX_TRANSACTIONS_PER_BLOCK,
            "Expected {MAX_TRANSACTIONS_PER_BLOCK} at height {MAX_TRANSACTIONS_PER_BLOCK_EXCEEDED_AT_HEIGHT}, found {max}",
        );

        let max = Processor::compute_max_transactions_per_block(
            MAX_TRANSACTIONS_PER_BLOCK_EXCEEDED_AT_HEIGHT + 1,
        );
        assert_eq!(
            max,
            MAX_TRANSACTIONS_PER_BLOCK,
            "Expected {} at height {}, found",
            MAX_TRANSACTIONS_PER_BLOCK,
            MAX_TRANSACTIONS_PER_BLOCK_EXCEEDED_AT_HEIGHT + 1,
        );
        let max = Processor::compute_max_transactions_per_block(
            MAX_TRANSACTIONS_PER_BLOCK_EXCEEDED_AT_HEIGHT - 1,
        );
        assert!(
            max < MAX_TRANSACTIONS_PER_BLOCK,
            "Expected less than max at height {}, found {}",
            MAX_TRANSACTIONS_PER_BLOCK_EXCEEDED_AT_HEIGHT - 1,
            max
        );
    }
}
