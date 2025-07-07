use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ed25519_compact::PublicKey;
use ibig::UBig;
use log::{error, info};
use rand::Rng;
use thiserror::Error;
use tokio::runtime::Handle;
use tokio::sync::mpsc::{channel, unbounded_channel, Receiver, Sender};
use tokio::task::JoinHandle;

use crate::block::{Block, BlockError, BlockHeader, BlockID};
use crate::block_header_hasher::BlockHeaderHasher;
use crate::block_storage_disk::BlockStorageDisk;
use crate::constants::{MAX_NUMBER, MAX_TRANSACTIONS_TO_INCLUDE_PER_BLOCK};
use crate::error::{impl_debug_error_chain, ChannelError, ErrChain};
use crate::ledger::LedgerNotFoundError;
use crate::ledger_disk::LedgerDisk;
use crate::peer::PEER_ADDR_SELF;
use crate::peer_manager::{PeerManager, PeerManagerError};
use crate::processor::{ProcessBlockError, Processor, ProcessorError};
use crate::shutdown::{ShutdownChanReceiver, SpawnedError};
use crate::transaction::Transaction;
use crate::transaction_queue::TransactionQueue;
use crate::transaction_queue_memory::TransactionQueueMemory;
use crate::utils::now_as_secs;

pub type HashUpdateChanTx = Sender<u64>;
pub type HashUpdateChanRx = Receiver<u64>;
pub type HashUpdateChan = (HashUpdateChanTx, HashUpdateChanRx);

/// Tries to mine a new tip block.
pub struct Miner {
    /// receipients of any block rewards we mine
    pub_keys: &'static Vec<PublicKey>,
    /// memo for coinbase of any blocks we mine
    memo: &'static Option<String>,
    block_store: Arc<BlockStorageDisk>,
    tx_queue: Arc<TransactionQueueMemory>,
    ledger: Arc<LedgerDisk>,
    processor: Arc<Processor>,
    num: usize,
    key_index: usize,
    hash_update_chan: HashUpdateChanTx,
    shutdown_chan_rx: ShutdownChanReceiver,
    shutdown_fns: Vec<Box<dyn Fn() + Send + Sync>>,
}

/// Collects hash counts from all miners in order to monitor and display the aggregate hashrate.
pub struct HashrateMonitor {
    num_miners: usize,
    hash_update_chan: HashUpdateChanRx,
    shutdown_chan_rx: ShutdownChanReceiver,
}

impl HashrateMonitor {
    pub fn new(
        num_miners: usize,
        hash_update_chan: HashUpdateChanRx,
        shutdown_chan_rx: ShutdownChanReceiver,
    ) -> Self {
        Self {
            num_miners,
            hash_update_chan,
            shutdown_chan_rx,
        }
    }

    /// Spawns the Hashrate Monitor's main loop.
    pub fn spawn(self) -> JoinHandle<Result<(), SpawnedError>> {
        tokio::spawn(async { self.run().await.map_err(Into::into) })
    }

    /// Runs the Hashrate Monitor's main loop.
    pub async fn run(mut self) -> Result<(), HashrateMonitorError> {
        let mut total_hashes = 0;
        let mut miner_updates = 0;
        let mut last_update = Instant::now();

        loop {
            tokio::select! {
                Some(hashes) = self.hash_update_chan.recv() => {
                    total_hashes += hashes;
                    miner_updates += 1;

                    // miners update every 30 seconds, report every minute (num_miners * 2)
                    if miner_updates == self.num_miners * 2 {
                        let elapsed = last_update.elapsed().as_secs_f64();
                        let hps = total_hashes as f64 / elapsed;
                        info!("Hashrate: {:.2} MH/s", hps/1000_f64/1000_f64);
                        total_hashes = 0;
                        miner_updates = 0;
                        last_update = Instant::now();
                    }
                }

                _ = &mut self.shutdown_chan_rx => {
                    info!("Hashrate monitor shutting down");
                    break Ok(())
                }
            }
        }
    }
}

#[derive(Error, Debug)]
pub enum HashrateMonitorError {}

impl Miner {
    /// Returns a new Miner instance.
    pub fn new(
        pub_keys: &'static Vec<PublicKey>,
        memo: &'static Option<String>,
        block_store: Arc<BlockStorageDisk>,
        tx_queue: Arc<TransactionQueueMemory>,
        ledger: Arc<LedgerDisk>,
        processor: Arc<Processor>,
        hash_update_chan: HashUpdateChanTx,
        num: usize,
        shutdown_chan_rx: ShutdownChanReceiver,
    ) -> Self {
        let key_index = rand::rng().random_range(0..pub_keys.len());

        Self {
            pub_keys,
            memo,
            block_store,
            tx_queue,
            ledger,
            processor,
            num,
            key_index,
            hash_update_chan,
            shutdown_chan_rx,
            shutdown_fns: Vec::new(),
        }
    }

    /// Spawns the miner's main loop
    pub fn spawn(self) -> JoinHandle<Result<(), SpawnedError>> {
        tokio::task::spawn_blocking(|| self.run().map_err(Into::into))
    }

    /// Run the miner's main loop
    pub fn run(mut self) -> Result<(), MinerError> {
        let interval = Duration::from_secs(30);
        let mut ticker = Instant::now() + interval;

        // don't start mining until we think we're synced.
        // we're just wasting time and slowing down the sync otherwise
        let (ibd, _height) =
            PeerManager::is_initial_block_download(&self.ledger, &self.block_store)?;
        if ibd {
            info!("Miner {} waiting for blockchain sync", self.num);
        }

        loop {
            if self.shutdown_chan_rx.try_recv().is_ok() {
                info!("Miner {} shutting down", self.num);
                return Ok(());
            }

            if ticker <= Instant::now() {
                ticker += interval;
                let (ibd, _height) =
                    PeerManager::is_initial_block_download(&self.ledger, &self.block_store)?;
                if !ibd {
                    // time to start mining
                    break;
                }
            }

            thread::sleep(Duration::from_millis(100));
        }

        // Register for tip changes to the processor
        let (tip_change_chan_tx, mut tip_change_chan_rx) = unbounded_channel();
        self.processor
            .register_for_tip_change(tip_change_chan_tx.clone());

        // Register for new transactions
        let (new_tx_chan_tx, mut new_tx_chan_rx) = channel(1);
        self.processor
            .register_for_new_transactions(new_tx_chan_tx.clone());

        // unregister from the processor on shutdown
        {
            let processor = Arc::clone(&self.processor);
            self.shutdown_fns.push(Box::new(move || {
                processor.unregister_for_tip_change(tip_change_chan_tx.clone());
                processor.unregister_for_new_transactions(new_tx_chan_tx.clone());
            }));
        }

        // main mining loop
        let mut hashes = 0;
        let mut median_timestamp = 0;
        let mut block = None;
        let mut target_int = UBig::default();

        loop {
            if let Ok(tip) = tip_change_chan_rx.try_recv() {
                if !tip.connect || tip.more {
                    // only build off newly connected tip blocks
                    continue;
                }

                // give up whatever block we were working on
                info!(
                    "Miner {} received notice of new tip block {}",
                    self.num, tip.block_id
                );

                // start working on a new block
                let mut next_block =
                    self.create_next_block_from_tip(&tip.block_id, &tip.block.header)?;

                // make sure we're at least +1 the median timestamp
                median_timestamp =
                    Processor::compute_median_timestamp(&tip.block.header, &self.block_store)?;

                if next_block.header.time <= median_timestamp {
                    next_block.header.time = median_timestamp + 1;
                }

                // convert our target to a BigInt
                target_int = next_block.header.target.as_big_int();
                block = Some((next_block, BlockHeaderHasher::new()));
            }

            if let Ok(new_tx) = new_tx_chan_rx.try_recv() {
                info!(
                    "Miner {} received notice of new transaction {}",
                    self.num, new_tx.transaction_id
                );

                let Some((block_new_tx, _hasher)) = block.as_mut() else {
                    // we're not working on a block yet
                    continue;
                };

                if MAX_TRANSACTIONS_TO_INCLUDE_PER_BLOCK != 0
                    && block_new_tx.transactions.len()
                        >= MAX_TRANSACTIONS_TO_INCLUDE_PER_BLOCK as usize
                {
                    info!(
                        "Per-block transaction limit hit ({})",
                        block_new_tx.transactions.len()
                    );
                    continue;
                }

                // add the transaction to the block (it updates the coinbase fee)
                if let Err(err) =
                    block_new_tx.add_transaction(new_tx.transaction_id, new_tx.transaction)
                {
                    info!(
                        "Error adding new transaction {} to block: {}",
                        new_tx.transaction_id, err
                    );
                    // abandon the block
                    block = None;
                }
            }

            if self.shutdown_chan_rx.try_recv().is_ok() {
                info!("Miner {} shutting down...", self.num);
                break Ok(());
            }

            if ticker <= Instant::now() {
                ticker += interval;

                // update hash count for hash rate monitor
                self.hash_update_chan.blocking_send(hashes).unwrap();
                hashes = 0;

                if let Some((block, _hasher)) = block.as_mut() {
                    // update block time every so often
                    let now = now_as_secs();
                    if now > median_timestamp {
                        block.header.time = now;
                    }
                }
            }

            if block.is_none() {
                // find the tip to start working off of
                let Some((tip_id, tip_header, _tip_when)) =
                    Processor::get_chain_tip_header(&self.ledger, &self.block_store)?
                else {
                    break Err(LedgerNotFoundError::ChainTipHeader.into());
                };

                // create a new block
                let mut next_block = self.create_next_block_from_tip(&tip_id, &tip_header)?;

                // make sure we're at least +1 the median timestamp
                median_timestamp =
                    match Processor::compute_median_timestamp(&tip_header, &self.block_store) {
                        Ok(v) => v,
                        Err(err) => break Err(err.into()),
                    };

                if next_block.header.time <= median_timestamp {
                    next_block.header.time = median_timestamp + 1;
                }

                // convert our target to a BigInt
                target_int = next_block.header.target.as_big_int();
                block = Some((next_block, BlockHeaderHasher::new()));
            }

            let (candidate_block, hasher) = block.as_mut().unwrap();
            candidate_block.header.id_fast(self.num, hasher);
            hashes += hasher.hashes_per_attempt;

            if hasher.result <= target_int {
                // found a solution
                let (candidate_block, hasher) = block.take().unwrap();
                let id = BlockID::from(hasher.result);
                info!("Miner {} mined new block {}", self.num, &id);

                let handle = Handle::current();
                handle.block_on(async {
                    // process the block
                    if let Err(err) = self
                        .processor
                        .process_candidate_block(id, candidate_block, PEER_ADDR_SELF)
                        .await
                        .map_err(MinerError::ProcessBlock)
                    {
                        error!("{:?}", err);
                    }
                });

                self.key_index = rand::rng().random_range(0..self.pub_keys.len());
            } else {
                // no solution yet
                candidate_block.header.nonce += hasher.hashes_per_attempt;
                if candidate_block.header.nonce > MAX_NUMBER {
                    candidate_block.header.nonce = 0;
                }
            }
        }
    }

    /// Create a new block off of the given tip block.
    pub fn create_next_block_from_tip(
        &self,
        tip_id: &BlockID,
        tip_header: &BlockHeader,
    ) -> Result<Block, MinerError> {
        info!(
            "Miner {} mining new block from current tip {}",
            self.num, &tip_id
        );

        let Some(pub_key) = self.pub_keys.get(self.key_index).cloned() else {
            return Err(MinerError::PublicKeyAtIndexMissing(self.key_index));
        };

        Miner::create_next_block(
            tip_id,
            tip_header,
            &self.tx_queue,
            &self.block_store,
            &self.ledger,
            pub_key,
            self.memo.clone(),
        )
    }

    /// Called by the miner as well as the peer to support get_work.
    pub fn create_next_block(
        tip_id: &BlockID,
        tip_header: &BlockHeader,
        tx_queue: &Arc<TransactionQueueMemory>,
        block_store: &Arc<BlockStorageDisk>,
        ledger: &Arc<LedgerDisk>,
        pub_key: PublicKey,
        memo: Option<String>,
    ) -> Result<Block, MinerError> {
        // fetch transactions to confirm from the queue
        let mut txs = tx_queue.get(MAX_TRANSACTIONS_TO_INCLUDE_PER_BLOCK as usize - 1);

        // calculate total fees
        let mut fees = 0;
        for tx in &txs {
            fees += tx.fee.expect("transaction should have a fee");
        }

        // calculate total block reward
        let new_height = tip_header.height + 1;
        let reward = Processor::block_creation_reward(new_height) + fees;

        // build coinbase
        let tx = Transaction::new(None, pub_key, reward, None, None, None, new_height, memo);

        // prepend coinbase
        txs.insert(0, tx);

        // compute the next target
        let new_target = Processor::compute_target(tip_header, block_store, ledger)
            .map_err(|err| MinerError::ComputeTarget(*tip_id, err))?;

        // create the block
        let block = Block::new(*tip_id, new_height, new_target, tip_header.chain_work, txs)?;

        Ok(block)
    }
}

impl Drop for Miner {
    fn drop(&mut self) {
        for shutdown_fn in &self.shutdown_fns {
            shutdown_fn();
        }
    }
}

#[derive(Error)]
pub enum MinerError {
    #[error("public key at index {0} is missing")]
    PublicKeyAtIndexMissing(usize),
    #[error("failed to compute target for block: {0}")]
    ComputeTarget(BlockID, #[source] ProcessBlockError),

    #[error("channel")]
    Channel(#[from] ChannelError),
    #[error("block")]
    Block(#[from] BlockError),
    #[error("ledger not found")]
    LedgerNotFound(#[from] LedgerNotFoundError),
    #[error("peer manager")]
    PeerManager(#[from] PeerManagerError),
    #[error("processing block")]
    ProcessBlock(#[from] ProcessBlockError),
    #[error("processor")]
    ProcessorError(#[from] ProcessorError),
}

impl_debug_error_chain!(MinerError, "miner");

impl From<tokio::sync::mpsc::error::SendError<u64>> for MinerError {
    fn from(err: tokio::sync::mpsc::error::SendError<u64>) -> Self {
        Self::Channel(ChannelError::Send("hash update", err.to_string()))
    }
}
