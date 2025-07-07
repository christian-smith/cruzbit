use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::from_utf8;
use std::sync::Arc;
use std::time::Duration;

use cuckoofilter::{CuckooFilter, ExportedCuckooFilter};
use ed25519_compact::PublicKey;
use futures::future::Either;
use futures::stream::SplitSink;
use futures::{SinkExt, StreamExt};
use log::{error, info};
use rand::Rng;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{channel, unbounded_channel, UnboundedSender};
use tokio::task::JoinHandle;
use tokio::time::{interval_at, sleep, timeout, Instant};
use tokio_rustls::server::TlsStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::{Error as WsError, Message as WsMessage};
use tokio_tungstenite::{
    connect_async_tls_with_config, Connector, MaybeTlsStream, WebSocketStream,
};

use crate::block::{Block, BlockError, BlockHeader, BlockID};
use crate::block_queue::BlockQueue;
use crate::block_storage::{BlockStorage, BlockStorageError, BlockStorageNotFoundError};
use crate::block_storage_disk::BlockStorageDisk;
use crate::checkpoints::{CHECKPOINTS_ENABLED, LATEST_CHECKPOINT_HEIGHT};
use crate::constants::{
    MAX_MEMO_LENGTH, MAX_PROTOCOL_MESSAGE_LENGTH, MAX_TRANSACTIONS_TO_INCLUDE_PER_BLOCK,
    MIN_AMOUNT_CRUZBITS, MIN_FEE_CRUZBITS,
};
use crate::error::{impl_debug_error_chain, ChannelError, DataError, ErrChain, JsonError};
use crate::ledger::{BranchType, Ledger, LedgerError, LedgerNotFoundError};
use crate::ledger_disk::LedgerDisk;
use crate::miner::{Miner, MinerError};
use crate::peer_manager::{AddrChanSender, PeerManager, PeerManagerError};
use crate::peer_storage::{PeerStorage, PeerStorageError};
use crate::peer_storage_disk::PeerStorageDisk;
use crate::processor::{ProcessBlockError, Processor, ProcessorError};
use crate::protocol::{
    BalanceMessage, BalancesMessage, BlockHeaderMessage, BlockMessage, FilterBlockMessage,
    FilterResultMessage, FilterTransactionQueueMessage, FindCommonAncestorMessage, GetBlockMessage,
    GetWorkMessage, InvBlockMessage, Message, PeerAddressesMessage, PublicKeyBalance,
    PublicKeyTransactionsMessage, PushTransactionMessage, PushTransactionResultMessage,
    SubmitWorkMessage, SubmitWorkResultMessage, TipHeaderMessage, TransactionMessage,
    TransactionRelayPolicyMessage, WorkMessage,
};
use crate::shutdown::{ShutdownChanReceiver, SpawnedError};
use crate::tls::client_config;
use crate::transaction::{Transaction, TransactionError, TransactionID};
use crate::transaction_queue::TransactionQueue;
use crate::transaction_queue_memory::TransactionQueueMemory;
use crate::utils::{now_as_duration, rand_int31};

pub type EitherWebSocketStream =
    Either<WebSocketStream<MaybeTlsStream<TcpStream>>, WebSocketStream<TlsStream<TcpStream>>>;

type WsSink = SplitSink<EitherWebSocketStream, WsMessage>;

/// A peer client in the network. They all speak WebSocket protocol to each other.
/// Peers could be fully validating and mining nodes or simply wallets.
pub struct Peer {
    /// peer connection, left = outbound, right = inbound
    conn: Option<EitherWebSocketStream>,
    genesis_id: &'static BlockID,
    peer_store: Arc<PeerStorageDisk>,
    block_store: Arc<BlockStorageDisk>,
    ledger: Arc<LedgerDisk>,
    processor: Arc<Processor>,
    tx_queue: Arc<TransactionQueueMemory>,
    outbound: bool,
    /// peer-local download queue
    local_download_queue: BlockQueue,
    /// peer-local inflight queue
    local_inflight_queue: Arc<BlockQueue>,
    /// global inflight queue
    global_inflight_queue: Arc<BlockQueue>,
    ignore_blocks: HashMap<BlockID, bool>,
    continuation_block_id: Option<BlockID>,
    last_peer_addresses_received_time: Option<Instant>,
    filter: Option<CuckooFilter<DefaultHasher>>,
    addr_chan_tx: AddrChanSender,
    work: Option<PeerWork>,
    pub_keys: Vec<PublicKey>,
    memo: Option<String>,
    read_limit: u32,
    addr: SocketAddr,
    shutdown_chan_rx: ShutdownChanReceiver,
    shutdown_fns: Vec<Box<dyn Fn() + Send + Sync>>,
}

pub struct PeerWork {
    work_id: u32,
    work_block: Block,
    median_timestamp: u64,
}

type OutChanSender = UnboundedSender<Message>;

/// Timing constants
/// Time allowed to wait for WebSocket connection
pub const CONNECT_WAIT: Duration = Duration::from_secs(10);

/// Time allowed to write a message to the peer
pub const WRITE_WAIT: Duration = Duration::from_secs(30);

/// Time allowed to read the next pong message from the peer
const PONG_WAIT: Duration = Duration::from_secs(120);

/// Send pings to peer with this period. Must be less than PONG_WAIT
const PING_PERIOD: Duration = Duration::from_secs(PONG_WAIT.as_secs() / 2);

/// How often should we refresh this peer's connectivity status with storage
const PEER_STORAGE_REFRESH_PERIOD: Duration = Duration::from_secs(5 * 60);

/// How often should we request peer addresses from a peer
const GET_PEER_ADDRESSES_PERIOD: Duration = Duration::from_secs(60 * 60);

/// Time allowed between processing new blocks before we consider a blockchain sync stalled
const SYNC_WAIT: Duration = Duration::from_secs(2 * 60);

/// Maximum blocks per inv_block message
const MAX_BLOCKS_PER_INV: usize = 500;

/// Maximum local inflight queue size
const INFLIGHT_QUEUE_MAX: usize = 8;

/// Maximum local download queue size
const DOWNLOAD_QUEUE_MAX: usize = MAX_BLOCKS_PER_INV * 10;

pub const PEER_ADDR_SELF: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);

impl Peer {
    /// Returns a new instance of a peer.
    pub fn new(
        conn: Option<EitherWebSocketStream>,
        genesis_id: &'static BlockID,
        peer_store: Arc<PeerStorageDisk>,
        block_store: Arc<BlockStorageDisk>,
        ledger: Arc<LedgerDisk>,
        processor: Arc<Processor>,
        tx_queue: Arc<TransactionQueueMemory>,
        block_queue: Arc<BlockQueue>,
        addr_chan_tx: AddrChanSender,
        addr: SocketAddr,
        shutdown_chan_rx: ShutdownChanReceiver,
    ) -> Self {
        let mut peer = Self {
            conn,
            genesis_id,
            peer_store,
            block_store,
            ledger,
            processor,
            tx_queue,
            local_download_queue: BlockQueue::new(),
            local_inflight_queue: Arc::new(BlockQueue::new()),
            global_inflight_queue: block_queue,
            ignore_blocks: HashMap::new(),
            continuation_block_id: None,
            last_peer_addresses_received_time: None,
            outbound: false,
            filter: None,
            addr_chan_tx,
            work: None,
            pub_keys: Vec::new(),
            memo: None,
            read_limit: 0,
            addr,
            shutdown_chan_rx,
            shutdown_fns: Vec::new(),
        };
        peer.update_read_limit();
        peer
    }

    /// Connects outbound to a peer.
    pub async fn connect(
        &mut self,
        nonce: u32,
        my_addr: Option<SocketAddr>,
    ) -> Result<(), PeerConnectionError> {
        let url = format!("wss://{}/{}", self.addr, &self.genesis_id);
        info!("Connecting to {}", url);

        let mut request = url.into_client_request()?;
        request
            .headers_mut()
            .append("Cruzbit-Peer-Nonce", nonce.to_string().parse()?);

        if let Some(my_addr) = my_addr {
            request
                .headers_mut()
                .append("Cruzbit-Peer-Address", my_addr.to_string().parse()?);
        }

        self.peer_store.on_connect_attempt(self.addr)?;

        let tls_verify = false;
        let client_config = client_config(tls_verify);
        let (conn, _response) = match timeout(
            CONNECT_WAIT,
            connect_async_tls_with_config(
                request,
                None,
                true,
                Some(Connector::Rustls(Arc::new(client_config))),
            ),
        )
        .await
        {
            Err(err) => {
                return Err(PeerConnectionError::Timeout(self.addr, err));
            }
            Ok(Ok(v)) => v,
            Ok(Err(err)) => {
                if let WsError::Http(response) = &err {
                    if response.status() == StatusCode::TOO_MANY_REQUESTS {
                        // the peer is already connected to us inbound.
                        // mark it successful so we try it again in the future.
                        self.peer_store.on_connect_success(self.addr)?;
                        self.peer_store.on_disconnect(self.addr)?;
                    } else {
                        self.peer_store.on_connect_failure(self.addr)?;
                    }
                }

                return Err(PeerConnectionError::Connect(self.addr, err));
            }
        };

        // left is outbound, right is inbound
        self.conn = Some(EitherWebSocketStream::Left(conn));
        self.outbound = true;
        self.peer_store
            .on_connect_success(self.addr)
            .map_err(PeerConnectionError::PeerStorage)
    }

    /// Spawns the Peer's main loop.
    pub fn spawn(self) -> JoinHandle<Result<(), SpawnedError>> {
        tokio::spawn(async { self.run().await.map_err(Into::into) })
    }

    /// Runs the Peer's main loop.
    /// It manages reading and writing to the peer's WebSocket and facilitating the protocol.
    pub async fn run(mut self) -> Result<(), PeerError> {
        let conn = self.conn.take().expect("peer should be connected");
        let (mut ws_sender, mut ws_receiver) = conn.split();

        // on shutdown remove any inflight blocks this peer is no longer going to download
        {
            let local_inflight_queue = Arc::clone(&self.local_inflight_queue);
            let global_inflight_queue = Arc::clone(&self.global_inflight_queue);
            self.on_shutdown(Box::new(move || {
                while let Some(block_in_flight) = local_inflight_queue.peek() {
                    local_inflight_queue.remove(&block_in_flight, &PEER_ADDR_SELF);
                    global_inflight_queue.remove(&block_in_flight, &self.addr);
                }
            }));
        }

        // channel to send outgoing messages
        let (out_chan_tx, mut out_chan_rx) = unbounded_channel();

        // send a find common ancestor request and request peer addresses shortly after connecting
        let (on_connect_chan_tx, mut on_connect_chan_rx) = channel(1);
        tokio::spawn(async move {
            sleep(Duration::from_secs(5)).await;
            if let Err(_err) = on_connect_chan_tx.send(true).await {
                error!("failed to send on-connect, peer must have shut down");
            }
        });

        // written to by the reader to update the current work block for the peer
        let mut get_work_chan = channel::<GetWorkMessage>(1);
        let mut submit_work_chan = channel::<SubmitWorkMessage>(1);

        // register to hear about tip block changes
        let (tip_change_chan_tx, mut tip_change_chan_rx) = unbounded_channel();
        self.processor
            .register_for_tip_change(tip_change_chan_tx.clone());

        // register to hear about new transactions
        let (new_tx_chan_tx, mut new_tx_chan_rx) =
            channel(MAX_TRANSACTIONS_TO_INCLUDE_PER_BLOCK as usize);
        self.processor
            .register_for_new_transactions(new_tx_chan_tx.clone());

        // unregister from the processor on shutdown
        {
            let processor = Arc::clone(&self.processor);
            self.on_shutdown(Box::new(move || {
                processor.unregister_for_tip_change(tip_change_chan_tx.clone());
                processor.unregister_for_new_transactions(new_tx_chan_tx.clone());
            }));
        }

        // send the peer pings
        let mut ticker_ping = interval_at(Instant::now() + PING_PERIOD, PING_PERIOD);

        // update the peer store with the peer's connectivity
        let mut ticker_peer_store_refresh = interval_at(
            Instant::now() + PEER_STORAGE_REFRESH_PERIOD,
            PEER_STORAGE_REFRESH_PERIOD,
        );

        // request new peer addresses
        let mut ticker_get_peer_addresses = interval_at(
            Instant::now() + GET_PEER_ADDRESSES_PERIOD,
            GET_PEER_ADDRESSES_PERIOD,
        );

        // check to see if we need to update work for miners
        let interval = Duration::from_secs(30);
        let mut ticker_update_work_check = interval_at(Instant::now() + interval, interval);

        // update the peer store on disconnection
        if self.outbound {
            let peer_store = Arc::clone(&self.peer_store);
            self.on_shutdown(Box::new(move || {
                if let Err(err) = peer_store
                    .on_disconnect(self.addr)
                    .map_err(PeerError::PeerStorage)
                {
                    error!("{:?}", err);
                }
            }));
        }

        // are we syncing?
        let mut last_new_block_time = Instant::now();
        let (ibd, _height) =
            PeerManager::is_initial_block_download(&self.ledger, &self.block_store)?;

        loop {
            tokio::select! {
                msg = timeout(PONG_WAIT, ws_receiver.next()) => {
                    let message = match msg {
                        Err(err) => {
                            break Err(PeerConnectionError::Timeout(self.addr, err).into())
                        }
                        Ok(Some(Ok(v))) => v,
                        Ok(Some(Err(err))) => {
                            break Err(PeerConnectionError::Websocket(err).into())
                        }
                        Ok(None) => {
                            break Err(PeerConnectionError::Dropped(self.addr).into())
                        },
                    };

                    // new message from peer
                    match message {
                        WsMessage::Text(ref json) => {
                            // sanitize inputs
                            if let Err(err) = from_utf8(json.as_bytes()).map_err(|err| PeerError::MessageNotUtf8(self.addr, DataError::String(err))) {
                                break Err(err)
                            }

                            let message = match serde_json::from_str::<Message>(json).map_err(|err| PeerError::MessageInvalid(self.addr, JsonError::Deserialize(err))) {
                                Ok(v) => v,
                                Err(err) => {
                                    break Err(err)
                                }
                            };

                            // hangup if the peer is sending oversized messages (other than blocks)
                            if !matches!(message, Message::Block(_))
                                && json.len() > MAX_PROTOCOL_MESSAGE_LENGTH
                            {
                                break Err(PeerError::MessageLengthExceeded(
                                    json.len(),
                                    message.to_string(),
                                    self.addr
                                ))
                            }

                            match message {
                                Message::Block(Some(b)) => {
                                    if let Some(block) = b.block {
                                        if let Err(err) = self.on_block(block, ibd, &out_chan_tx).await {
                                            error!("{:?}, from: {}", err, self.addr);
                                            continue

                                        } else {
                                            last_new_block_time = Instant::now();
                                        }
                                    } else {
                                        break Err(PeerError::EmptyBlockReceived(self.addr))
                                    }
                                }

                                Message::FilterAdd(fa) => {
                                    if let Err(err) = self.on_filter_add(fa.public_keys, &out_chan_tx).await {
                                        error!("{:?}, from: {}", err, self.addr);
                                        continue
                                    }
                                }

                                Message::FilterLoad(fl) => {
                                    if let Err(err) = self.on_filter_load(fl.r#type, fl.filter, &out_chan_tx).await {
                                        error!("{:?}, from: {}", err, self.addr);
                                        continue
                                    }
                                }

                                Message::FindCommonAncestor(fca) => {
                                    let length = fca.block_ids.len();
                                    for (i, id) in
                                        fca.block_ids.into_iter().enumerate()
                                    {
                                        match self
                                            .on_find_common_ancestor(&id, i, length, &out_chan_tx).await {
                                                Ok(ok) => {
                                                    if ok {
                                                        break
                                                    }
                                                },
                                                Err(err) => {
                                                    error!("{:?}, from: {}", err, self.addr);
                                                    // don't need to process more
                                                    break
                                                }
                                            }
                                    }
                                }

                                Message::GetBalance(gb) => {
                                    if let Err(err) = self.on_get_balance(gb.public_key, &out_chan_tx).await {
                                        error!("{:?}, from: {}", err, self.addr);
                                        continue;

                                    }
                                }

                                Message::GetBalances(gb) => {
                                    if let Err(err) = self.on_get_balances(gb.public_keys, &out_chan_tx).await {
                                        error!("{:?}, from: {}", err, self.addr);
                                        continue
                                    }
                                }

                                Message::GetBlock(gb) => {
                                    if let Err(err) = self.on_get_block(gb.block_id, &out_chan_tx).await {
                                        error!("{:?}, from: {}", err, self.addr);
                                        continue
                                    }
                                }

                                Message::GetBlockByHeight(gbbh) => {
                                    if let Err(err) = self.on_get_block_by_height(gbbh.height, &out_chan_tx).await {
                                        error!("{:?}, from: {}", err, self.addr);
                                        continue
                                    }
                                }

                                Message::GetBlockHeader(gbh) => {
                                    if let Err(err) = self.on_get_block_header(gbh.block_id, &out_chan_tx).await {
                                        error!("{:?}, from: {}", err, self.addr);
                                        continue
                                    }
                                }

                                Message::GetBlockHeaderByHeight(gbhbh) => {
                                    if let Err(err) = self
                                        .on_get_block_header_by_height(gbhbh.height, &out_chan_tx).await {
                                            error!("{:?}, from: {}", err, self.addr);
                                            continue
                                        }
                                }

                                Message::GetFilterTransactionQueue => {
                                    if let Err(err) = self.on_get_filter_transaction_queue(&out_chan_tx).await {
                                        error!("{:?}, from: {}", err, self.addr);
                                        continue
                                    }
                                }

                                Message::GetPeerAddresses => {
                                    if let Err(err) = self.on_get_peer_addresses(&out_chan_tx).await {
                                        error!("{:?}, from: {}", err, self.addr);
                                        continue
                                    }
                                }

                                Message::GetPublicKeyTransactions(gpkt) => {
                                    if let Err(err) = self
                                        .on_get_public_key_transactions(
                                            gpkt.public_key,
                                            gpkt.start_height,
                                            gpkt.end_height,
                                            gpkt.start_index,
                                            gpkt.limit,
                                            &out_chan_tx
                                        ).await {
                                            error!("{:?}, from: {}", err, self.addr);
                                            continue
                                        }
                                }

                                Message::GetTipHeader => {
                                    if let Err(err) = self.on_get_tip_header(&out_chan_tx).await {
                                        error!("{:?}, from: {}", err, self.addr);
                                        continue
                                    }
                                }

                                Message::GetTransaction(gt) => {
                                    if let Err(err) = self.on_get_transaction(gt.transaction_id, &out_chan_tx).await {
                                        error!("{:?}, from: {}", err, self.addr);
                                        continue
                                    }
                                }

                                Message::GetTransactionResult(ptr) => {
                                    if let Some(err) = ptr.error {
                                        error!("{:?}, from: {}", err, self.addr);}
                                }

                                Message::GetTransactionRelayPolicy => {
                                    out_chan_tx.send(Message::TransactionRelayPolicy(TransactionRelayPolicyMessage {
                                        min_fee: MIN_FEE_CRUZBITS,
                                        min_amount: MIN_AMOUNT_CRUZBITS,
                                    }))?;
                                }

                                Message::GetWork(gw) => {
                                    info!("Received get_work message, from: {}", self.addr);
                                    get_work_chan.0.send(gw).await?;
                                }

                                Message::InvBlock(inv) => {
                                    let block_ids_len = inv.block_ids.len();
                                    for (i, id) in
                                        inv.block_ids.into_iter().enumerate()
                                    {
                                        if let Err(err) = self.on_inv_block(id, i, block_ids_len, &out_chan_tx).await {
                                            error!("{:?}, from: {}", err, self.addr);
                                            continue
                                        }
                                    }
                                }

                                Message::PeerAddresses(pa) => {
                                    if let Err(err) = self.on_peer_addresses(pa.addresses).await {
                                        error!("{:?}, from: {}", err, self.addr);
                                        continue
                                    }
                                }

                                Message::PushTransaction(pt) => {
                                    if let Err(err) = self.on_push_transaction(pt.transaction, &out_chan_tx).await {
                                        error!("{:?}, from: {}", err, self.addr);
                                        continue
                                    }
                                }

                                Message::PushTransactionResult(ptr) => {
                                    if let Some(err) = ptr.error {
                                        error!("{}, from: {}", err, self.addr);
                                    }
                                }

                                Message::SubmitWork(sw) => {
                                    info!("Received submit_work message, from: {}", self.addr);
                                    submit_work_chan.0.send(sw).await?;
                                }

                                _ => {
                                    error!("Unknown message: {}, from: {}", message, self.addr);}
                            }
                        }

                        WsMessage::Close(_) => {
                            info!(
                                "Received close message from: {}",
                                self.addr
                            );
                            break Ok(())
                        }

                        WsMessage::Pong(_) => {
                            // handle pongs
                            if ibd {
                                // handle stalled blockchain syncs
                                let (ibd, _height) = PeerManager::is_initial_block_download(&self.ledger, &self.block_store)?;
                                let elapsed = last_new_block_time.elapsed();
                                if ibd && elapsed > SYNC_WAIT {
                                    break Err(PeerError::SyncStalled(self.addr))
                                }
                            } else {
                                // try processing the queue in case we've been blocked by another client
                                // and their attempt has now expired
                                self.process_download_queue(&out_chan_tx).await?;
                            }
                        }

                        // ignore other message types
                        _ => {},
                    };
                }

                msg = out_chan_rx.recv() => {
                    match msg {
                        Some(message) => {
                            let json = serde_json::to_string(&message).map_err(JsonError::Serialize)?;
                            self.send_with_timeout(&mut ws_sender, WsMessage::Text(json)).await?;
                        },
                        None => {
                            // close the connection if the tx is dropped
                            self.send_with_timeout(&mut ws_sender, WsMessage::Close(None)).await?;
                        }
                    }
                }

                Some(tip) = tip_change_chan_rx.recv() => {
                    // update read limit if necessary
                    self.update_read_limit();

                    if tip.connect && !tip.more {
                        // only build off newly connected tip blocks.
                        // create and send out new work if necessary
                        self.create_new_work_block(&tip.block_id, &tip.block.header, &out_chan_tx).await?;
                    }

                    if tip.source == self.addr {
                        continue
                    }

                    if tip.connect {
                        // new tip announced, notify the peer
                        let inv = Message::InvBlock(InvBlockMessage {
                            block_ids: vec![tip.block_id]
                        });
                        // send it
                        let json = serde_json::to_string(&inv).map_err(JsonError::Serialize)?;
                        self.send_with_timeout(&mut ws_sender, WsMessage::Text(json)).await?;
                    }

                    // potentially create a filter_block
                    let fb = match self.create_filter_block(tip.block_id, tip.block) {
                        Ok(Some(v)) => v,
                        Ok(None) => continue,
                        Err(err) => {
                            error!("{:?}, to: {}", err, self.addr);
                            continue
                        }
                    };

                    // send it
                    let transactions_len = fb.transactions.len();

                    let (message, r#type) = if !tip.connect {
                        (Message::FilterBlockUndo(fb), "filter_block_undo")
                    } else {
                        (Message::FilterBlock(fb), "filter_block")
                    };

                    info!("Sending {} with {} transaction(s), to: {}", r#type, transactions_len, self.addr);
                    let json = serde_json::to_string(&message).map_err(JsonError::Serialize)?;
                    self.send_with_timeout(&mut ws_sender, WsMessage::Text(json)).await?;
                }

                Some(new_tx) = new_tx_chan_rx.recv() => {
                    if new_tx.source == self.addr {
                        // this is who sent it to us
                        continue
                    }

                    if !self.filter_lookup(&new_tx.transaction) {
                        continue
                    }

                    // newly verified transaction announced, relay to peer
                    let push_tx = Message::PushTransaction(PushTransactionMessage {
                        transaction: new_tx.transaction,
                    });
                    let json = serde_json::to_string(&push_tx).map_err(JsonError::Serialize)?;
                    self.send_with_timeout(&mut ws_sender, WsMessage::Text(json)).await?;
                }

                Some(_) = on_connect_chan_rx.recv() => {
                    // send a new peer a request to find a common ancestor
                    self.send_find_common_ancestor(None, Some(&mut ws_sender), &out_chan_tx).await?;

                    // send a get_peer_addresses to request peers
                    info!("Sending get_peer_addresses to: {}", self.addr);
                    let message = Message::GetPeerAddresses;
                    let json = serde_json::to_string(&message).map_err(JsonError::Serialize)?;
                    self.send_with_timeout(&mut ws_sender, WsMessage::Text(json)).await?;
                }

                Some(gw) = get_work_chan.1.recv() => {
                    if let Err(err) = self.on_get_work(gw, &out_chan_tx).await {
                        error!("{:?}, from: {}", err, self.addr);
                    }
                }

                Some(sw) = submit_work_chan.1.recv() => {
                    if let Err(err) = self.on_submit_work(sw, &out_chan_tx).await {
                        error!("{:?}, from: {}", err, self.addr);
                    }
                }

                _ = ticker_ping.tick() => {
                    self.send_with_timeout(&mut ws_sender, WsMessage::Ping(vec![])).await?;
                }

                _ = ticker_peer_store_refresh.tick(), if self.outbound => {
                    // periodically refresh our connection time
                    if let Err(err) = self.peer_store.on_connect_success(self.addr).map_err(PeerError::PeerStorage) {
                        error!("{:?}, from: {}", err, self.addr);
                    }
                }

                _ = ticker_get_peer_addresses.tick() => {
                    // periodically send a get_peer_addresses
                    info!("Sending get_peer_addresses to: {}", self.addr);
                    let message = Message::GetPeerAddresses;
                    let json = serde_json::to_string(&message).map_err(JsonError::Serialize)?;
                    self.send_with_timeout(&mut ws_sender, WsMessage::Text(json)).await?;
                }

                _ = ticker_update_work_check.tick(), if self.work.is_some() => {
                    let work = self.work.as_ref().expect("work should exist");
                    let tx_count = work.work_block.transactions.len();
                    if tx_count == MAX_TRANSACTIONS_TO_INCLUDE_PER_BLOCK as usize {
                        // already at capacity
                        continue
                    }
                    if tx_count - 1 != self.tx_queue.len() {
                        let Some((tip_id, tip_header, _tip_when)) = Processor::get_chain_tip_header(&self.ledger, &self.block_store)? else {
                            break Err(LedgerNotFoundError::ChainTip.into())
                        };
                        self.create_new_work_block(&tip_id, &tip_header, &out_chan_tx).await?;
                    }
                }

                _ = &mut self.shutdown_chan_rx => {
                    ws_sender.close().await.map_err(PeerConnectionError::Websocket)?;
                    break Ok(())
                }
            }
        }
    }

    /// Handle a message from a peer indicating block inventory available for download
    async fn on_inv_block(
        &mut self,
        id: BlockID,
        index: usize,
        length: usize,
        out_chan_tx: &OutChanSender,
    ) -> Result<(), PeerError> {
        info!("Received inv_block: {}, from: {}", id, self.addr);

        if length > MAX_BLOCKS_PER_INV {
            return Err(PeerError::InvBlockMaxBlocks(length, MAX_BLOCKS_PER_INV));
        }

        // is it on the ignore list?
        if self.ignore_blocks.get(&id).is_some() {
            info!("Ignoring block {}, from: {}", id, self.addr);
            return Ok(());
        }

        // do we have it queued or inflight already?
        if self.local_download_queue.exists(&id) || self.local_inflight_queue.exists(&id) {
            info!(
                "Block {} is already queued or inflight for download, from: {}",
                id, self.addr
            );
            return Ok(());
        }

        // have we processed it?
        let branch_type = self.ledger.get_branch_type(&id)?;
        if branch_type != BranchType::Unknown {
            info!("Already processed block {}", id);
            if length > 1 && index + 1 == length {
                // we might be on a deep side chain. this will get us the next 500 blocks
                return self
                    .send_find_common_ancestor(Some(id), None, out_chan_tx)
                    .await;
            }
            return Ok(());
        }

        if self.local_download_queue.len() >= DOWNLOAD_QUEUE_MAX {
            info!(
                "Too many blocks in the download queue {}, max: {}, for: {}",
                self.local_download_queue.len(),
                DOWNLOAD_QUEUE_MAX,
                self.addr
            );
            // don't return an error just stop adding them to the queue
            return Ok(());
        }

        // add block to this peer's download queue
        self.local_download_queue.add(&id, &PEER_ADDR_SELF);

        // process the download queue
        self.process_download_queue(out_chan_tx).await
    }

    /// Handle a request for a block from a peer
    async fn on_get_block(
        &mut self,
        id: BlockID,
        out_chan_tx: &OutChanSender,
    ) -> Result<(), PeerError> {
        info!("Received get_block: {}, from: {}", id, self.addr);
        self.get_block(id, out_chan_tx).await
    }

    /// Handle a request for a block by height from a peer
    async fn on_get_block_by_height(
        &mut self,
        height: u64,
        out_chan_tx: &OutChanSender,
    ) -> Result<(), PeerError> {
        info!(
            "Received get_block_by_height: {}, from: {}",
            height, self.addr
        );
        let id = match self.ledger.get_block_id_for_height(height) {
            Ok(Some(v)) => v,
            Ok(None) => {
                // not found
                out_chan_tx.send(Message::Block(None))?;
                return Err(LedgerNotFoundError::BlockIDForHeight(height).into());
            }
            Err(err) => {
                // not found
                out_chan_tx.send(Message::Block(None))?;
                return Err(err.into());
            }
        };

        self.get_block(id, out_chan_tx).await
    }

    async fn get_block(
        &mut self,
        id: BlockID,
        out_chan_tx: &OutChanSender,
    ) -> Result<(), PeerError> {
        // fetch the block
        let block_json = match self.block_store.get_block_bytes(&id) {
            Ok(Some(v)) => v,
            Ok(None) => {
                // not found
                out_chan_tx.send(Message::Block(Some(Box::new(BlockMessage {
                    block_id: id,
                    block: None,
                }))))?;

                return Err(BlockStorageNotFoundError::BlockBytes(id).into());
            }
            Err(err) => {
                // not found
                out_chan_tx.send(Message::Block(Some(Box::new(BlockMessage {
                    block_id: id,
                    block: None,
                }))))?;

                return Err(err.into());
            }
        };

        // send out the raw bytes
        let mut body = Vec::new();
        body.extend_from_slice(br#"{"block_id":""#);
        body.extend_from_slice(id.as_hex().as_bytes());
        body.extend_from_slice(br#"","block":"#);
        body.extend_from_slice(&block_json);
        body.extend_from_slice(br#"}"#);

        let block_message =
            serde_json::from_slice::<BlockMessage>(&body).map_err(JsonError::Deserialize)?;
        out_chan_tx.send(Message::Block(Some(Box::new(block_message))))?;

        // was this the last block in the inv we sent in response to a find common ancestor request?
        if let Some(ref continuation_block_id) = self.continuation_block_id {
            if id == *continuation_block_id {
                info!(
                    "Received get_block for continuation block {}, from: {}",
                    id, self.addr
                );

                self.continuation_block_id = None;

                // send an inv for our tip block to prompt the peer to
                // send another find common ancestor request to complete its download of the chain.
                let chain_tip = match self.ledger.get_chain_tip().map_err(PeerError::Ledger) {
                    Ok(v) => v,
                    Err(err) => {
                        error!("{:?}", err);
                        return Ok(());
                    }
                };

                if let Some((tip_id, _height)) = chain_tip {
                    out_chan_tx.send(Message::InvBlock(InvBlockMessage {
                        block_ids: vec![tip_id],
                    }))?;
                }
            }
        }

        Ok(())
    }

    /// Handle receiving a block from a peer. Returns true if the block was newly processed and accepted.
    async fn on_block(
        &mut self,
        block: Block,
        ibd: bool,
        out_chan_tx: &OutChanSender,
    ) -> Result<bool, PeerError> {
        // the message has the ID in it but we can't trust that.
        // it's provided as convenience for trusted peering relationships only
        let id = block.id()?;

        info!("Received block: {}, from: {}", id, self.addr);

        match self.local_inflight_queue.peek() {
            Some(peek) => {
                if peek != id {
                    // disconnect misbehaving peer
                    return Err(PeerError::ReceivedUnrequestedBlock);
                }
            }
            None => {
                // disconnect misbehaving peer
                return Err(PeerError::ReceivedUnrequestedBlock);
            }
        };

        // don't process low difficulty blocks
        if !ibd && CHECKPOINTS_ENABLED && block.header.height < LATEST_CHECKPOINT_HEIGHT {
            // don't disconnect them. they may need us to find out about the real chain
            self.local_inflight_queue.remove(&id, &PEER_ADDR_SELF);
            self.global_inflight_queue.remove(&id, &self.addr);

            // ignore future inv_blocks for this block
            self.ignore_blocks.insert(id, true);
            if self.ignore_blocks.len() > MAX_BLOCKS_PER_INV {
                // they're intentionally sending us bad blocks
                return Err(PeerError::MaxIgnoreListSizeExceeded);
            }

            return Err(PeerError::BlockAtHeightLessThanCheckpoint(
                id,
                block.header.height,
                LATEST_CHECKPOINT_HEIGHT,
            ));
        }

        let mut accepted = false;

        // is it an orphan?
        match self.block_store.get_block_header(&block.header.previous) {
            Ok(Some((_header, _height))) => {
                // process the block
                if let Err(err) = self
                    .processor
                    .process_candidate_block(id, block, self.addr)
                    .await
                {
                    // TODO: disconnect from peer here
                    // disconnect a peer that sends us a bad block
                    return Err(err.into());
                }
                // newly accepted block
                accepted = true;

                // remove it from the inflight queues only after we process it
                self.local_inflight_queue.remove(&id, &PEER_ADDR_SELF);
                self.global_inflight_queue.remove(&id, &self.addr);
            }
            Ok(None) => {
                self.local_inflight_queue.remove(&id, &PEER_ADDR_SELF);
                self.global_inflight_queue.remove(&id, &self.addr);

                info!(
                    "Block {} is an orphan, sending find_common_ancestor to: {}",
                    id, self.addr
                );

                // send a find common ancestor request
                self.send_find_common_ancestor(None, None, out_chan_tx)
                    .await?;
            }
            Err(err) => {
                self.local_inflight_queue.remove(&id, &PEER_ADDR_SELF);
                self.global_inflight_queue.remove(&id, &self.addr);
                return Err(err.into());
            }
        };

        // see if there are any more blocks to download right now
        self.process_download_queue(out_chan_tx).await?;

        Ok(accepted)
    }

    /// Try requesting blocks that are in the download queue
    async fn process_download_queue(
        &mut self,
        out_chan_tx: &OutChanSender,
    ) -> Result<(), PeerError> {
        // fill up as much of the inflight queue as possible
        let mut queued = 0;

        while self.local_inflight_queue.len() < INFLIGHT_QUEUE_MAX {
            // next block to download
            let Some(block_to_download) = self.local_download_queue.peek() else {
                // no more blocks in the queue
                break;
            };

            // double-check if it's been processed since we last checked
            let branch_type = self.ledger.get_branch_type(&block_to_download)?;
            if branch_type != BranchType::Unknown {
                // it's been processed. remove it and check the next one
                info!(
                    "Block {} has been processed, removing from download queue for: {}",
                    block_to_download, self.addr
                );
                self.local_download_queue
                    .remove(&block_to_download, &PEER_ADDR_SELF);
                continue;
            }

            // add block to the global inflight queue with this peer as the owner
            {
                if !self
                    .global_inflight_queue
                    .add(&block_to_download, &self.addr)
                {
                    // another peer is downloading it right now.
                    // wait to see if they succeed before trying to download any others
                    info!(
                        "Block {} is being downloaded already from another peer",
                        block_to_download
                    );
                    break;
                }
            }

            // pop it off the local download queue
            self.local_download_queue
                .remove(&block_to_download, &PEER_ADDR_SELF);

            // mark it inflight locally
            self.local_inflight_queue
                .add(&block_to_download, &PEER_ADDR_SELF);
            queued += 1;

            // request it
            info!(
                "Sending get_block for {}, to: {}",
                block_to_download, self.addr
            );
            out_chan_tx.send(Message::GetBlock(GetBlockMessage {
                block_id: block_to_download,
            }))?;
        }

        if queued > 0 {
            info!(
                "Requested {} block(s) for download, from: {}",
                queued, self.addr
            );
            info!(
                "Queue size: {}, peer inflight: {}, global inflight: {}, for: {}",
                self.local_download_queue.len(),
                self.local_inflight_queue.len(),
                self.global_inflight_queue.len(),
                self.addr
            );
        }

        Ok(())
    }

    /// Send a message to look for a common ancestor with a peer
    /// Might be called from reader or writer context. sender means we're in the writer context
    async fn send_find_common_ancestor(
        &self,
        mut start_id: Option<BlockID>,
        ws_sender: Option<&mut WsSink>,
        out_chan_tx: &OutChanSender,
    ) -> Result<(), PeerError> {
        info!("Sending find_common_ancestor to: {}", self.addr);

        let mut height = match start_id {
            Some(id) => {
                let Some((header, _when)) = self.block_store.get_block_header(&id)? else {
                    info!("No header for block {}", id);
                    return Ok(());
                };
                header.height
            }
            None => {
                let Some((id_tip, height_tip)) = self.ledger.get_chain_tip()? else {
                    return Ok(());
                };
                start_id = Some(id_tip);
                height_tip
            }
        };

        let mut block_id = start_id;
        let mut ids = Vec::new();
        let mut step = 1;
        while let Some(id) = block_id {
            if id == *self.genesis_id {
                break;
            }
            ids.push(id);
            let depth = height - step;
            if depth == 0 {
                break;
            }
            block_id = match self
                .ledger
                .get_block_id_for_height(depth)
                .map_err(PeerError::Ledger)
            {
                Ok(v) => v,
                Err(err) => {
                    error!("{:?}", err);
                    return Ok(());
                }
            };
            if ids.len() > 10 {
                step *= 2;
            }
            height = depth;
        }
        ids.push(*self.genesis_id);
        let message = Message::FindCommonAncestor(FindCommonAncestorMessage { block_ids: ids });

        // send immediately if the sender is passed in
        if let Some(ws_sender) = ws_sender {
            let json = serde_json::to_string(&message).map_err(JsonError::Serialize)?;
            self.send_with_timeout(ws_sender, WsMessage::Text(json))
                .await
                .map_err(PeerError::PeerConnection)?;
            return Ok(());
        }
        out_chan_tx.send(message)?;

        Ok(())
    }

    /// Handle a find common ancestor message from a peer
    async fn on_find_common_ancestor(
        &mut self,
        id: &BlockID,
        index: usize,
        length: usize,
        out_chan_tx: &OutChanSender,
    ) -> Result<bool, PeerError> {
        info!(
            "Received find_common_ancestor: {}, index: {}, length: {}, from: {}",
            id, index, length, self.addr
        );

        let Some((header, _when)) = self.block_store.get_block_header(id)? else {
            return Ok(false);
        };

        // have we processed it?
        let branch_type = self.ledger.get_branch_type(id)?;
        if branch_type != BranchType::Main {
            // not on the main branch
            return Ok(false);
        }

        info!(
            "Common ancestor found: {}, height: {}, with: {}",
            id, header.height, self.addr
        );

        let mut ids = Vec::new();
        let mut height = header.height + 1;

        while ids.len() < MAX_BLOCKS_PER_INV {
            let Some(next_id) = self.ledger.get_block_id_for_height(height)? else {
                break;
            };
            info!(
                "Queueing inv for block {}, height: {}, to: {}",
                next_id, height, self.addr
            );
            ids.push(next_id);
            height += 1;
        }

        if !ids.is_empty() {
            // save the last ID so after the peer requests it we can trigger it to
            // send another find common ancestor request to finish downloading the rest of the chain
            let continuation_block_id = ids[ids.len() - 1];
            info!(
                "Sending inv_block with {} IDs, continuation block: {}, to: {}",
                ids.len(),
                continuation_block_id,
                self.addr
            );
            self.continuation_block_id = Some(continuation_block_id);

            out_chan_tx.send(Message::InvBlock(InvBlockMessage { block_ids: ids }))?;
        }

        Ok(true)
    }

    /// Handle a request for a block header from a peer
    async fn on_get_block_header(
        &self,
        id: BlockID,
        out_chan_tx: &OutChanSender,
    ) -> Result<(), PeerError> {
        info!("Received get_block_header: {}, from: {}", id, self.addr);

        self.get_block_header(id, out_chan_tx).await
    }

    /// Handle a request for a block header by ID from a peer
    async fn on_get_block_header_by_height(
        &self,
        height: u64,
        out_chan_tx: &OutChanSender,
    ) -> Result<(), PeerError> {
        info!(
            "Received get_block_header_by_height: {}, from: {}",
            height, self.addr
        );
        let id = match self.ledger.get_block_id_for_height(height) {
            Ok(Some(v)) => v,
            Ok(None) => {
                // not found
                out_chan_tx.send(Message::BlockHeader(None))?;
                return Err(LedgerNotFoundError::BlockIDForHeight(height).into());
            }
            Err(err) => {
                // not found
                out_chan_tx.send(Message::BlockHeader(None))?;
                return Err(err.into());
            }
        };

        self.get_block_header(id, out_chan_tx).await
    }

    async fn get_block_header(
        &self,
        block_id: BlockID,
        out_chan_tx: &OutChanSender,
    ) -> Result<(), PeerError> {
        let (header, _when) = match self.block_store.get_block_header(&block_id) {
            Ok(Some(v)) => v,
            Ok(None) => {
                // not found
                out_chan_tx.send(Message::BlockHeader(Some(BlockHeaderMessage {
                    block_id,
                    block_header: None,
                })))?;

                return Err(BlockStorageNotFoundError::BlockHeader(block_id).into());
            }
            Err(err) => {
                // not found
                out_chan_tx.send(Message::BlockHeader(Some(BlockHeaderMessage {
                    block_id,
                    block_header: None,
                })))?;

                return Err(err.into());
            }
        };
        out_chan_tx.send(Message::BlockHeader(Some(BlockHeaderMessage {
            block_id,
            block_header: Some(header),
        })))?;

        Ok(())
    }

    /// Handle a request for a public key's balancep
    async fn on_get_balance(
        &self,
        pub_key: PublicKey,
        out_chan_tx: &OutChanSender,
    ) -> Result<(), PeerError> {
        info!("Received get_balance from {}", self.addr);

        let (balances, tip_id, tip_height) =
            match self.ledger.get_public_key_balances(vec![pub_key]) {
                Ok(v) => v,
                Err(err) => {
                    out_chan_tx.send(Message::Balance(BalanceMessage {
                        block_id: None,
                        height: None,
                        public_key: Some(pub_key),
                        balance: None,
                        error: Some(err.to_string()),
                    }))?;

                    return Err(err.into());
                }
            };

        let mut balance = 0;
        for (_pub_key, bal) in balances {
            balance = bal;
        }

        out_chan_tx.send(Message::Balance(BalanceMessage {
            block_id: Some(tip_id),
            height: Some(tip_height),
            public_key: Some(pub_key),
            balance: Some(balance),
            error: None,
        }))?;

        Ok(())
    }

    /// Handle a request for a set of public key balances.
    async fn on_get_balances(
        &self,
        pub_keys: Vec<PublicKey>,
        out_chan_tx: &OutChanSender,
    ) -> Result<(), PeerError> {
        info!(
            "Received get_balances (count: {}) from: {}",
            pub_keys.len(),
            self.addr
        );

        let max_public_keys = 64;
        if pub_keys.len() > max_public_keys {
            let err = PeerBalancesError::PublicKeysExceeded(max_public_keys);
            out_chan_tx.send(Message::Balances(BalancesMessage {
                error: Some(err.to_string()),
                block_id: None,
                height: None,
                balances: None,
            }))?;

            return Err(err.into());
        }

        let (balances, tip_id, tip_height) = match self.ledger.get_public_key_balances(pub_keys) {
            Ok(v) => v,
            Err(err) => {
                out_chan_tx.send(Message::Balances(BalancesMessage {
                    block_id: None,
                    height: None,
                    balances: None,
                    error: Some(err.to_string()),
                }))?;
                return Err(err.into());
            }
        };

        let mut pub_key_balances = Vec::with_capacity(balances.len());
        for (public_key, balance) in balances {
            pub_key_balances.push(PublicKeyBalance {
                public_key,
                balance,
            });
        }
        out_chan_tx.send(Message::Balances(BalancesMessage {
            block_id: Some(tip_id),
            height: Some(tip_height),
            balances: Some(pub_key_balances),
            error: None,
        }))?;

        Ok(())
    }

    /// Handle a request for a public key's transactions over a given height range
    async fn on_get_public_key_transactions(
        &self,
        pub_key: PublicKey,
        start_height: u64,
        end_height: u64,
        start_index: u32,
        mut limit: usize,
        out_chan_tx: &OutChanSender,
    ) -> Result<(), PeerError> {
        info!("Received get_public_key_transactions from {}", self.addr);
        // enforce our limit
        if limit > 32 || limit == 0 {
            limit = 32;
        }

        // get the indices for all transactions for the given public key
        // over the given range of block heights
        let (block_ids, indices, stop_height, stop_index) =
            match self.ledger.get_public_key_transaction_indices_range(
                pub_key,
                start_height,
                end_height,
                start_index,
                limit,
            ) {
                Ok(v) => v,
                Err(err) => {
                    out_chan_tx.send(Message::PublicKeyTransactions(
                        PublicKeyTransactionsMessage {
                            public_key: None,
                            start_height: None,
                            stop_height: None,
                            stop_index: None,
                            filter_blocks: None,
                            error: Some(err.to_string()),
                        },
                    ))?;

                    return Err(err.into());
                }
            };

        // build filter blocks from the indices
        let mut fbs = Vec::new();

        for (i, block_id) in block_ids.into_iter().enumerate() {
            // fetch transaction and header
            let (tx, block_header) = match self.block_store.get_transaction(&block_id, indices[i]) {
                Ok((Some(tx), header)) => (tx, header),
                Ok((None, _header)) => {
                    let err = PeerError::PublicKeyTransactionNotFound(block_id, indices[i]);
                    error!("{:?}", err);
                    continue;
                }
                Err(err) => {
                    // odd case. just log it and continue
                    let err =
                        PeerError::PublicKeyTransactionBlockStorage(block_id, indices[i], err);
                    error!("{:?}", err);
                    continue;
                }
            };

            // figure out where to put it
            if fbs.is_empty() {
                // new block
                let fb = FilterBlockMessage {
                    block_id,
                    header: block_header,
                    transactions: vec![tx],
                };
                fbs.push(fb)
            } else if fbs[fbs.len() - 1].block_id != block_id {
                // new block
                let fb = FilterBlockMessage {
                    block_id,
                    header: block_header,
                    transactions: vec![tx],
                };
                fbs.push(fb);
            } else {
                // transaction is from the same block
                let last_index = fbs.len() - 1;
                let fb = &mut fbs[last_index];
                fb.transactions.push(tx);
            };
        }

        out_chan_tx.send(Message::PublicKeyTransactions(
            PublicKeyTransactionsMessage {
                public_key: Some(pub_key),
                start_height: Some(start_height),
                stop_height: Some(stop_height),
                stop_index: Some(stop_index),
                filter_blocks: Some(fbs),
                error: None,
            },
        ))?;

        Ok(())
    }

    /// Handle a request for a transaction
    async fn on_get_transaction(
        &self,
        tx_id: TransactionID,
        out_chan_tx: &OutChanSender,
    ) -> Result<(), PeerError> {
        info!(
            "Received get_transaction for {}, from: {}",
            tx_id, self.addr
        );

        let (block_id, index) = match self.ledger.get_transaction_index(&tx_id) {
            Ok(Some(v)) => v,
            Ok(None) => {
                // not found
                out_chan_tx.send(Message::Transaction(TransactionMessage {
                    block_id: None,
                    height: None,
                    transaction_id: tx_id,
                    transaction: None,
                }))?;

                return Err(LedgerNotFoundError::TransactionAtIndex(tx_id).into());
            }
            Err(err) => {
                // not found
                out_chan_tx.send(Message::Transaction(TransactionMessage {
                    block_id: None,
                    height: None,
                    transaction_id: tx_id,
                    transaction: None,
                }))?;

                return Err(err.into());
            }
        };

        let (tx, block_header) = match self.block_store.get_transaction(&block_id, index) {
            Ok((Some(tx), header)) => (tx, header),
            Ok((None, header)) => {
                // odd case but send back what we know at least
                out_chan_tx.send(Message::Transaction(TransactionMessage {
                    block_id: Some(block_id),
                    height: Some(header.height),
                    transaction_id: tx_id,
                    transaction: None,
                }))?;

                return Err(
                    BlockStorageNotFoundError::TransactionAtBlockIndex(block_id, index).into(),
                );
            }
            Err(err) => {
                // odd case but send back what we know at least
                out_chan_tx.send(Message::Transaction(TransactionMessage {
                    block_id: Some(block_id),
                    height: None,
                    transaction_id: tx_id,
                    transaction: None,
                }))?;

                return Err(err.into());
            }
        };

        out_chan_tx.send(Message::Transaction(TransactionMessage {
            block_id: Some(block_id),
            height: Some(block_header.height),
            transaction_id: tx_id,
            transaction: Some(tx),
        }))?;

        Ok(())
    }

    /// Handle a request for a block header of the tip of the main chain from a peer
    async fn on_get_tip_header(&self, out_chan_tx: &OutChanSender) -> Result<(), PeerError> {
        info!("Received get_tip_header, from: {}", self.addr);
        let (tip_id, tip_header, tip_when) =
            match Processor::get_chain_tip_header(&self.ledger, &self.block_store) {
                Ok(Some(v)) => v,
                Ok(None) => {
                    // shouldn't be possible
                    out_chan_tx.send(Message::TipHeader(None))?;
                    return Err(LedgerNotFoundError::ChainTipHeader.into());
                }
                Err(err) => {
                    // shouldn't be possible
                    out_chan_tx.send(Message::TipHeader(None))?;
                    return Err(err.into());
                }
            };
        out_chan_tx.send(Message::TipHeader(Some(TipHeaderMessage {
            block_id: tip_id,
            block_header: tip_header,
            time_seen: tip_when,
        })))?;

        Ok(())
    }

    /// Handle receiving a transaction from a peer
    async fn on_push_transaction(
        &self,
        tx: Transaction,
        out_chan_tx: &OutChanSender,
    ) -> Result<(), PeerError> {
        let id = match tx.id() {
            Ok(v) => v,
            Err(err) => {
                out_chan_tx.send(Message::PushTransactionResult(
                    PushTransactionResultMessage {
                        transaction_id: None,
                        error: Some(err.to_string()),
                    },
                ))?;
                return Err(err.into());
            }
        };

        info!("Received push_transaction: {}, from: {}", id, self.addr);

        // process the transaction if this is the first time we've seen it
        let mut err_str = None;
        if !self.tx_queue.exists(&id) {
            if let Err(err) = self
                .processor
                .process_candidate_transaction(&id, &tx, &self.addr)
                .await
            {
                err_str = Some(format!("{:?}", err));
            }
        };

        out_chan_tx.send(Message::PushTransactionResult(
            PushTransactionResultMessage {
                transaction_id: Some(id),
                error: err_str,
            },
        ))?;

        Ok(())
    }

    /// Handle a request to set a transaction filter for the connection
    async fn on_filter_load(
        &mut self,
        filter_type: String,
        exported_filter: ExportedCuckooFilter,
        out_chan_tx: &OutChanSender,
    ) -> Result<(), PeerError> {
        info!(
            "Received filter_load (size: {}), from: {}",
            exported_filter.length, self.addr
        );

        // check filter type
        if filter_type != "cuckoo" {
            let err = PeerFilterError::TypeUnsupported(filter_type);
            out_chan_tx.send(Message::FilterResult(Some(FilterResultMessage {
                error: err.to_string(),
            })))?;

            return Err(err.into());
        }

        // check limit
        let max_size = 1 << 16;
        if exported_filter.length > max_size {
            let err = PeerFilterError::SizeExceeded(max_size);
            out_chan_tx.send(Message::FilterResult(Some(FilterResultMessage {
                error: err.to_string(),
            })))?;

            return Err(err.into());
        }

        // decode it
        let filter = CuckooFilter::<DefaultHasher>::from(exported_filter);
        if filter.is_empty() {
            let err = PeerFilterError::CreateFailed;
            out_chan_tx.send(Message::FilterResult(Some(FilterResultMessage {
                error: err.to_string(),
            })))?;

            return Err(err.into());
        }

        // set the filter
        self.filter = Some(filter);

        // send the empty result
        out_chan_tx.send(Message::FilterResult(None))?;

        Ok(())
    }

    /// Handle a request to add a set of public keys to the filter
    async fn on_filter_add(
        &mut self,
        pub_keys: Vec<PublicKey>,
        out_chan_tx: &OutChanSender,
    ) -> Result<(), PeerError> {
        info!(
            "Received filter_add (public keys: {}), from: {}",
            pub_keys.len(),
            self.addr
        );

        // check limit
        let max_public_keys = 256;
        if pub_keys.len() > max_public_keys {
            let err = PeerFilterError::PublicKeysExceeded(max_public_keys);
            out_chan_tx.send(Message::FilterResult(Some(FilterResultMessage {
                error: err.to_string(),
            })))?;
            return Err(err.into());
        }

        // set the filter if it's not set
        let ok: Result<(), PeerFilterError> = (|| {
            if self.filter.is_none() {
                self.filter = Some(CuckooFilter::with_capacity(1 << 16));
            }
            let filter = self.filter.as_mut().expect("filter should exist");

            // perform the inserts
            for pub_key in pub_keys {
                if filter.add(&pub_key).is_err() {
                    return Err(PeerFilterError::InsertFailed);
                }
            }

            Ok(())
        })();

        // send the result
        let message = if let Err(err) = ok {
            Message::FilterResult(Some(FilterResultMessage {
                error: err.to_string(),
            }))
        } else {
            Message::FilterResult(None)
        };
        out_chan_tx.send(message)?;

        Ok(())
    }

    /// Send back a filtered view of the transaction queue
    async fn on_get_filter_transaction_queue(
        &self,
        out_chan_tx: &OutChanSender,
    ) -> Result<(), PeerError> {
        info!("Received get_filter_transaction_queue, from: {}", self.addr);

        let message = if self.filter.is_none() {
            Message::FilterTransactionQueue(FilterTransactionQueueMessage {
                transactions: None,
                error: Some(FilterTransactionQueueError::FilterMissing.to_string()),
            })
        } else {
            let transactions = self.tx_queue.get(0);
            let mut ftq_transactions = Vec::new();
            for tx in transactions {
                if self.filter_lookup(&tx) {
                    ftq_transactions.push(tx);
                }
            }
            Message::FilterTransactionQueue(FilterTransactionQueueMessage {
                transactions: Some(ftq_transactions),
                error: None,
            })
        };
        out_chan_tx.send(message)?;

        Ok(())
    }

    /// Returns true if the transaction is of interest to the peer
    fn filter_lookup(&self, tx: &Transaction) -> bool {
        match self.filter {
            Some(ref filter) => {
                if !tx.is_coinbase()
                    && filter.contains(&tx.from.expect("transaction should have a sender"))
                {
                    return true;
                }

                filter.contains(&tx.to)
            }
            None => true,
        }
    }

    /// Called from the writer context
    fn create_filter_block(
        &self,
        id: BlockID,
        block: Block,
    ) -> Result<Option<FilterBlockMessage>, PeerError> {
        if self.filter.is_none() {
            // nothing to do
            return Ok(None);
        }

        // create a filter block
        let mut fb = FilterBlockMessage {
            block_id: id,
            header: block.header,
            transactions: Vec::new(),
        };

        // filter out transactions the peer isn't interested in
        for tx in &block.transactions {
            if self.filter_lookup(tx) {
                fb.transactions.push(tx.clone());
            }
        }

        Ok(Some(fb))
    }

    /// Received a request for peer addresses
    async fn on_get_peer_addresses(&self, out_chan_tx: &OutChanSender) -> Result<(), PeerError> {
        info!("Received get_peer_addresses message, from: {}", self.addr);

        // get up to 32 peers that have been connected to within the last 3 hours
        let time_ago = Duration::from_secs(3 * 60 * 60);
        let since = now_as_duration() - time_ago;
        let addresses = self
            .peer_store
            .get_since(32, since)?
            .into_iter()
            .map(|addr| addr.to_string())
            .collect::<Vec<_>>();

        if !addresses.is_empty() {
            out_chan_tx.send(Message::PeerAddresses(PeerAddressesMessage { addresses }))?;
        }

        Ok(())
    }

    /// Received a list of addresses
    async fn on_peer_addresses(&mut self, addresses: Vec<String>) -> Result<(), PeerError> {
        info!(
            "Received peer_addresses message with {} address(es), from: {}",
            addresses.len(),
            self.addr
        );

        let elapsed = match self.last_peer_addresses_received_time {
            Some(time) => time.elapsed(),
            None => Duration::MAX,
        };

        if elapsed < GET_PEER_ADDRESSES_PERIOD - Duration::from_secs(2 * 60) {
            // don't let a peer flood us with peer addresses
            info!(
                "Ignoring peer addresses, time since last addresses: {}",
                elapsed.as_secs()
            );
            return Ok(());
        }
        self.last_peer_addresses_received_time = Some(Instant::now());

        let limit = 32;
        for (i, addr) in addresses.into_iter().enumerate() {
            if i == limit {
                break;
            }
            // notify the peer manager
            self.addr_chan_tx.send(addr).await?;
        }

        Ok(())
    }

    /// Called when work has been received
    async fn on_get_work(
        &mut self,
        gw: GetWorkMessage,
        out_chan_tx: &OutChanSender,
    ) -> Result<(), PeerError> {
        let ok = if self.work.is_some() {
            Err(PeerGetWorkError::WorkBlockExists)
        } else if gw.public_keys.is_empty() {
            Err(PeerGetWorkError::WorkBlockNoPublicKeys)
        } else if gw.memo.len() > MAX_MEMO_LENGTH {
            Err(PeerGetWorkError::WorkBlockMaxMemoLengthExceeded(
                MAX_MEMO_LENGTH,
                gw.memo.len(),
            ))
        } else {
            match Processor::get_chain_tip_header(&self.ledger, &self.block_store) {
                Ok(Some((tip_id, tip_header, _tip_when))) => {
                    // create and send out new work
                    self.pub_keys = gw.public_keys;
                    self.memo = Some(gw.memo);
                    self.create_new_work_block(&tip_id, &tip_header, out_chan_tx)
                        .await?;
                    Ok(())
                }
                Ok(None) => Err(LedgerNotFoundError::ChainTipHeader.into()),
                Err(err) => Err(PeerGetWorkError::Processor(self.addr, err)),
            }
        };

        if let Err(ref err) = ok {
            out_chan_tx.send(Message::Work(WorkMessage {
                work_id: None,
                header: None,
                min_time: None,
                error: Some(err.to_string()),
            }))?;
        }

        ok.map_err(Into::into)
    }

    /// Create a new work block for a mining peer.
    async fn create_new_work_block(
        &mut self,
        tip_id: &BlockID,
        tip_header: &BlockHeader,
        out_chan_tx: &OutChanSender,
    ) -> Result<(), PeerError> {
        if self.pub_keys.is_empty() {
            // peer doesn't want work
            return Ok(());
        }

        let work_id = rand_int31();
        let peer_work = match Processor::compute_median_timestamp(tip_header, &self.block_store)
            .map_err(PeerError::ProcessorComputingMedianTimestamp)
        {
            Ok(median_timestamp) => {
                let key_index = rand::rng().random_range(0..self.pub_keys.len());
                match Miner::create_next_block(
                    tip_id,
                    tip_header,
                    &self.tx_queue,
                    &self.block_store,
                    &self.ledger,
                    self.pub_keys[key_index],
                    self.memo.clone(),
                )
                .map_err(PeerError::MinerCreateNextWorkBlock)
                {
                    Ok(work_block) => Ok(PeerWork {
                        work_id,
                        work_block,
                        median_timestamp,
                    }),
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        };

        // create a new block
        let message = match peer_work {
            Ok(ref peer_work) => Message::Work(WorkMessage {
                work_id: Some(peer_work.work_id),
                header: Some(peer_work.work_block.header.clone()),
                min_time: Some(peer_work.median_timestamp + 1),
                error: None,
            }),
            Err(ref err) => Message::Work(WorkMessage {
                work_id: Some(work_id),
                header: None,
                min_time: None,
                error: Some(err.to_string()),
            }),
        };
        out_chan_tx.send(message)?;
        self.work = peer_work.ok();

        Ok(())
    }

    /// Handle a submission of mining work.
    async fn on_submit_work(
        &mut self,
        sw: SubmitWorkMessage,
        out_chan_tx: &OutChanSender,
    ) -> Result<(), PeerError> {
        let block_id = if sw.work_id == 0 {
            Err(PeerSubmitWorkError::WorkIdMissing)
        } else {
            match sw.header.id() {
                Ok(id) => {
                    if let Some(ref mut work) = self.work {
                        if sw.work_id != work.work_id {
                            Err(PeerSubmitWorkError::WorkIdInvalid(work.work_id, sw.work_id))
                        } else {
                            work.work_block.header = sw.header;
                            match self
                                .processor
                                .process_candidate_block(id, work.work_block.clone(), self.addr)
                                .await
                            {
                                Ok(_) => Ok(id),
                                Err(err) => Err(err.into()),
                            }
                        }
                    } else {
                        Err(PeerSubmitWorkError::WorkIdPeerMissing)
                    }
                }
                Err(err) => Err(err.into()),
            }
        };

        let message = if let Err(ref err) = block_id {
            Message::SubmitWorkResult(SubmitWorkResultMessage {
                work_id: sw.work_id,
                error: Some(err.to_string()),
            })
        } else {
            Message::SubmitWorkResult(SubmitWorkResultMessage {
                work_id: sw.work_id,
                error: None,
            })
        };
        out_chan_tx.send(message)?;

        if let Err(err) = block_id {
            Err(err.into())
        } else {
            Ok(())
        }
    }

    /// Update the read limit if necessary
    fn update_read_limit(&mut self) {
        let (ok, height) = PeerManager::is_initial_block_download(&self.ledger, &self.block_store)
            .unwrap_or_else(|err| panic!("{:?}", err));

        if ok {
            // TODO: do something smarter about this
            self.read_limit = 0;
            return;
        }

        // transactions are <500 bytes so this gives us significant wiggle room
        let max_transactions = Processor::compute_max_transactions_per_block(height + 1);
        self.read_limit = max_transactions * 1024;
    }

    /// Send outgoing messages with a write timeout period
    async fn send_with_timeout(
        &self,
        ws_sender: &mut WsSink,
        message: WsMessage,
    ) -> Result<(), PeerConnectionError> {
        match timeout(WRITE_WAIT, ws_sender.send(message)).await {
            Err(err) => Err(PeerConnectionError::Timeout(self.addr, err)),
            Ok(Err(err)) => Err(err.into()),
            _ => Ok(()),
        }
    }

    /// Specifies a handler to call when the peer connection is closed.
    pub fn on_shutdown(&mut self, shutdown_fn: impl Fn() + 'static + Send + Sync) {
        self.shutdown_fns.push(Box::new(shutdown_fn));
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        // peer is shutting down
        if self.conn.is_none() {
            info!("Closed connection with: {}", self.addr);
        }

        for shutdown_fn in &self.shutdown_fns {
            shutdown_fn();
        }
    }
}

#[derive(Error)]
pub enum PeerError {
    #[error("block {0} at height {1} less than latest checkpoint height {2}")]
    BlockAtHeightLessThanCheckpoint(BlockID, u64, u64),
    #[error("received empty block, from {0}")]
    EmptyBlockReceived(SocketAddr),
    #[error("received empty transaction")]
    EmptyTransactionReceive,
    #[error("{0} blocks IDs is more than {1} maximum per inv_block")]
    InvBlockMaxBlocks(usize, usize),
    #[error("max block ignore list size exceeded")]
    MaxIgnoreListSizeExceeded,
    #[error("received invalid message, from: {0}")]
    MessageInvalid(SocketAddr, #[source] JsonError),
    #[error("received too large ({0} bytes) of a '{1}' message, from: {2}")]
    MessageLengthExceeded(usize, String, SocketAddr),
    #[error("received non-utf8 clean message, from: {0}")]
    MessageNotUtf8(SocketAddr, #[source] DataError),
    #[error("retrieving transaction history, block: {0}, index: {1} -> block storage")]
    PublicKeyTransactionBlockStorage(BlockID, u32, #[source] BlockStorageError),
    #[error("retrieving transaction history, block: {0}, index: {1}: no transaction found")]
    PublicKeyTransactionNotFound(BlockID, u32),
    #[error("received unrequested block")]
    ReceivedUnrequestedBlock,
    #[error("sync has stalled, disconnecting from from: {0}")]
    SyncStalled(SocketAddr),

    #[error("miner -> creating next block")]
    MinerCreateNextWorkBlock(#[source] MinerError),
    #[error("processor -> computing median timestamp")]
    ProcessorComputingMedianTimestamp(#[source] ProcessorError),

    #[error("peer balances")]
    PeerBalances(#[from] PeerBalancesError),
    #[error("peer connection")]
    PeerConnection(#[from] PeerConnectionError),
    #[error("peer filter")]
    PeerFilter(#[from] PeerFilterError),
    #[error("peer get work")]
    PeerGetWork(#[from] PeerGetWorkError),
    #[error("peer submit work")]
    PeerSubmitWork(#[from] PeerSubmitWorkError),

    #[error("block")]
    Block(#[from] BlockError),
    #[error("block storage")]
    BlockStorage(#[from] BlockStorageError),
    #[error("block storage not found")]
    BlockStorageNotFound(#[from] BlockStorageNotFoundError),
    #[error("channel")]
    Channel(#[from] ChannelError),
    #[error("json")]
    Json(#[from] JsonError),
    #[error("ledger")]
    Ledger(#[from] LedgerError),
    #[error("ledger not found")]
    LedgerNotFound(#[from] LedgerNotFoundError),
    #[error("peer manager")]
    PeerManager(#[from] PeerManagerError),
    #[error("peer storage")]
    PeerStorage(#[from] PeerStorageError),
    #[error("processing block")]
    ProcessBlock(#[from] ProcessBlockError),
    #[error("processor")]
    Processor(#[from] ProcessorError),
    #[error("transaction")]
    Transaction(#[from] TransactionError),
}

impl_debug_error_chain!(PeerError, "peer");

impl From<tokio::sync::mpsc::error::SendError<GetWorkMessage>> for PeerError {
    fn from(err: tokio::sync::mpsc::error::SendError<GetWorkMessage>) -> Self {
        Self::Channel(ChannelError::Send("get work", err.to_string()))
    }
}

impl From<tokio::sync::mpsc::error::SendError<Message>> for PeerError {
    fn from(err: tokio::sync::mpsc::error::SendError<Message>) -> Self {
        Self::Channel(ChannelError::Send("out", err.to_string()))
    }
}

impl From<tokio::sync::mpsc::error::SendError<String>> for PeerError {
    fn from(err: tokio::sync::mpsc::error::SendError<String>) -> Self {
        Self::Channel(ChannelError::Send("addr", err.to_string()))
    }
}

impl From<tokio::sync::mpsc::error::SendError<SubmitWorkMessage>> for PeerError {
    fn from(err: tokio::sync::mpsc::error::SendError<SubmitWorkMessage>) -> Self {
        Self::Channel(ChannelError::Send("submit work", err.to_string()))
    }
}

#[derive(Error, Debug)]
pub enum PeerConnectionError {
    #[error("failed accepting incoming from: {0}")]
    Accept(SocketAddr, #[source] tokio_tungstenite::tungstenite::Error),
    #[error("failed connecting to peer: {0}")]
    Connect(SocketAddr, #[source] tokio_tungstenite::tungstenite::Error),
    #[error("websocket connection lost, closing...")]
    Dropped(SocketAddr),
    #[error("connection timeout for peer: {0}")]
    Timeout(SocketAddr, #[source] tokio::time::error::Elapsed),

    #[error("peer storage")]
    PeerStorage(#[from] PeerStorageError),

    #[error("websocket header")]
    HttpHeaderValue(#[from] tokio_tungstenite::tungstenite::http::header::InvalidHeaderValue),
    #[error("websocket")]
    Websocket(#[from] tokio_tungstenite::tungstenite::Error),
}

/// Error type associated with cruzbit protocol messages
#[derive(Error, Debug)]
pub enum FilterTransactionQueueError {
    #[error("No filter set")]
    FilterMissing,
}

/// Error type associated with cruzbit protocol messages
#[derive(Error, Debug)]
pub enum PeerBalanceError {
    #[error("ledger")]
    Ledger(#[from] LedgerError),
}

/// Error type associated with cruzbit protocol messages
#[derive(Error, Debug)]
pub enum PeerBalancesError {
    #[error("Too many public keys, limit: {0}")]
    PublicKeysExceeded(usize),
}

/// Error type associated with cruzbit protocol messages
#[derive(Error, Debug)]
pub enum PeerFilterError {
    #[error("Failed to create filter")]
    CreateFailed,
    #[error("Unable to insert into filter")]
    InsertFailed,
    #[error("Too many public keys, limit: {0}")]
    PublicKeysExceeded(usize),
    #[error("Filter too large, max {0}")]
    SizeExceeded(usize),
    #[error("Unsupported filter type {0}")]
    TypeUnsupported(String),
}

/// Error type associated with cruzbit protocol messages
#[derive(Error, Debug)]
pub enum PeerGetWorkError {
    #[error("Work block already exists")]
    WorkBlockExists,
    #[error("Work block max memo length ({0}) exceeded: {1}")]
    WorkBlockMaxMemoLengthExceeded(usize, usize),
    #[error("Work block has no public keys")]
    WorkBlockNoPublicKeys,

    #[error("ledger not found")]
    LedgerNotFound(#[from] LedgerNotFoundError),

    #[error("getting chain tip header, for: {0}")]
    Processor(SocketAddr, #[source] ProcessorError),
}

/// Error type associated with cruzbit protocol messages
#[derive(Error, Debug)]
pub enum PeerSubmitWorkError {
    #[error("Unexpected work id {0}, found {1}")]
    WorkIdInvalid(u32, u32),
    #[error("No work id set")]
    WorkIdMissing,
    #[error("No work id set on peer")]
    WorkIdPeerMissing,

    #[error("block id")]
    Block(#[from] BlockError),
    #[error("processing work block")]
    ProcessBlock(#[from] ProcessBlockError),
}
