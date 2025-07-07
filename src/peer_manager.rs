use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::{from_utf8, FromStr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use log::{error, info};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use rand::seq::{IteratorRandom, SliceRandom};
use rand::Rng;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinHandle;
use tokio::time::{interval_at, sleep_until, timeout, Instant};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::http::{header, StatusCode};
use tokio_tungstenite::tungstenite::Error as WsError;

use crate::block::BlockID;
use crate::block_queue::BlockQueue;
use crate::block_storage_disk::BlockStorageDisk;
use crate::checkpoints::{CHECKPOINTS_ENABLED, LATEST_CHECKPOINT_HEIGHT};
use crate::constants::{
    MAX_INBOUND_PEER_CONNECTIONS_FROM_SAME_HOST, MAX_OUTBOUND_PEER_CONNECTIONS, MAX_TIP_AGE,
};
use crate::dns::query_for_peers;
use crate::error::{
    impl_debug_error_chain, ChannelError, DataError, ErrChain, ParsingError, SocketError,
};
use crate::irc::IRC;
use crate::ledger_disk::LedgerDisk;
use crate::peer::{EitherWebSocketStream, Peer, PeerConnectionError};
use crate::peer_storage::{PeerStorage, PeerStorageError};
use crate::peer_storage_disk::PeerStorageDisk;
use crate::processor::{Processor, ProcessorError};
use crate::protocol::PROTOCOL;
use crate::shutdown::{shutdown_channel, Shutdown, ShutdownChanReceiver, SpawnedError};
use crate::tls::{self, generate_self_signed_cert_and_key, server_config, TlsError};
use crate::transaction_queue_memory::TransactionQueueMemory;
use crate::utils::{addr_is_reserved, now_as_secs, rand_int31, resolve_host};

pub type AddrChanSender = Sender<String>;
pub type AddrChan = (AddrChanSender, Mutex<Option<Receiver<String>>>);

/// Manages incoming and outgoing peer connections on behalf of the client.
/// It also manages finding peers to connect to.
pub struct PeerManager {
    genesis_id: &'static BlockID,
    peer_store: Arc<PeerStorageDisk>,
    block_store: Arc<BlockStorageDisk>,
    ledger: Arc<LedgerDisk>,
    processor: Arc<Processor>,
    tx_queue: Arc<TransactionQueueMemory>,
    block_queue: Arc<BlockQueue>,
    data_dir: PathBuf,
    my_external_ip: Option<IpAddr>,
    peer: Option<SocketAddr>,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
    port: u16,
    inbound_limit: usize,
    accept: bool,
    accepting: AtomicBool,
    irc: bool,
    dns_seed: bool,
    ban_map: &'static HashMap<String, bool>,
    in_peers: RwLock<HashMap<SocketAddr, Shutdown>>,
    in_peer_count_by_host: RwLock<HashMap<SocketAddr, usize>>,
    out_peers: RwLock<HashMap<SocketAddr, Shutdown>>,
    addr_chan: AddrChan,
    peer_nonce: u32,
    open: AtomicBool,
    server_shutdown: Mutex<Option<Shutdown>>,
    irc_shutdown: Mutex<Option<Shutdown>>,
    shutdown_chan_rx: Mutex<Option<ShutdownChanReceiver>>,
}

impl PeerManager {
    /// Returns a new PeerManager instance.
    pub fn new(
        genesis_id: &'static BlockID,
        peer_store: Arc<PeerStorageDisk>,
        block_store: Arc<BlockStorageDisk>,
        ledger: Arc<LedgerDisk>,
        processor: Arc<Processor>,
        tx_queue: Arc<TransactionQueueMemory>,
        data_dir: PathBuf,
        my_external_ip: Option<IpAddr>,
        peer: Option<SocketAddr>,
        cert_path: Option<PathBuf>,
        key_path: Option<PathBuf>,
        port: u16,
        inbound_limit: usize,
        accept: bool,
        ban_map: &'static HashMap<String, bool>,
        irc: bool,
        dns_seed: bool,
        open: bool,
        shutdown_chan_rx: ShutdownChanReceiver,
    ) -> Arc<Self> {
        let addr_chan = channel(10000);
        Arc::new(Self {
            genesis_id,
            peer_store,
            block_store,
            ledger,
            processor,
            tx_queue,
            block_queue: Arc::new(BlockQueue::new()),
            data_dir,
            my_external_ip,
            peer,
            cert_path,
            key_path,
            port,
            inbound_limit,
            accept,
            // not accepting connections initially
            accepting: AtomicBool::new(false),
            irc,
            dns_seed,
            ban_map,
            in_peers: RwLock::new(HashMap::new()),
            in_peer_count_by_host: RwLock::new(HashMap::new()),
            out_peers: RwLock::new(HashMap::new()),
            addr_chan: (addr_chan.0, Mutex::new(Some(addr_chan.1))),
            peer_nonce: rand_int31(),
            open: AtomicBool::new(open),
            server_shutdown: Mutex::new(None),
            irc_shutdown: Mutex::new(None),
            shutdown_chan_rx: Mutex::new(Some(shutdown_chan_rx)),
        })
    }

    /// Spawns the PeerManager's main loop.
    pub fn spawn(self: Arc<Self>) -> JoinHandle<Result<(), SpawnedError>> {
        tokio::spawn(async move { self.run().await.map_err(Into::into) })
    }

    /// Runs the PeerManager's main loop.
    /// It determines our connectivity and manages sourcing peer addresses from seed sources
    /// as well as maintaining full outbound connections and accepting inbound connections.
    pub async fn run(self: &Arc<Self>) -> Result<(), PeerManagerError> {
        if let Some(peer) = self.peer {
            // store the explicitly specified outbound peer
            if let Err(err) = self
                .peer_store
                .store(peer)
                .map_err(|err| PeerManagerError::SavePeer(peer, err))
            {
                error!("{:?}", err);
            };
        } else {
            // query dns seeds for peers
            match query_for_peers().await {
                Ok(addresses) => {
                    for addr in addresses {
                        info!("Got peer address from DNS: {}", addr);
                        self.addr_chan.0.send(addr).await?;
                    }
                }
                Err(err) => {
                    error!("{:?}", err);
                }
            };

            // handle IRC seeding
            if self.irc {
                let mut port = self.port;
                if !self.open.load(Ordering::Relaxed) || !self.accept {
                    // don't advertise ourself as available for inbound connections
                    port = 0;
                }

                let (shutdown_chan_tx, shutdown_chan_rx) = shutdown_channel();
                match IRC::connect(
                    port,
                    self.genesis_id,
                    self.addr_chan.0.clone(),
                    shutdown_chan_rx,
                )
                .await
                {
                    Ok(irc) => {
                        let handle = irc.spawn();
                        let mut irc_shutdown = self.irc_shutdown.lock().unwrap();
                        *irc_shutdown = Some(Shutdown::new(handle, shutdown_chan_tx));
                    }
                    Err(err) => {
                        error!("{:?}", err);
                    }
                };
            }
        }

        // handle listening for inbound peers
        if let Err(err) = self.listen_for_peers().await {
            error!("{:?}", err);
        }

        // try connecting to some saved peers
        if let Err(err) = self.connect_to_peers().await {
            error!("{:?}", err);
        }

        // try connecting out to peers every 5 minutes
        let ticker_interval = Duration::from_secs(5 * 60);
        let mut ticker = interval_at(Instant::now() + ticker_interval, ticker_interval);

        let mut addr_chan_rx = self.addr_chan.1.lock().unwrap().take().unwrap();
        let mut shutdown_chan_rx = self.shutdown_chan_rx.lock().unwrap().take().unwrap();

        // main loop
        loop {
            tokio::select! {
                Some(addr_str) = addr_chan_rx.recv() => {
                    // validate the address
                    let addr = match self.validate_peer_address(addr_str).map_err(PeerManagerError::PeerValidation) {
                        Ok(v) => v,
                        Err(err) => {
                            error!("{:?}", err);
                            continue
                        }
                    };

                    // is it banned?
                    if self.ban_map.get(&addr.ip().to_string()).is_some() {
                        info!("Ignoring banned host: {}", addr.ip());
                        continue
                    }

                    // store the peer
                    match self.peer_store.store(addr).map_err(|err| PeerManagerError::SavePeer(addr, err)) {
                        Ok(ok) => {
                            if !ok {
                                // we already knew about this peer address
                                continue
                            }
                            info!("Discovered new peer: {}", addr);

                            // try connecting to some saved peers
                            if let Err(err) = self.connect_to_peers().await {
                                error!("{:?}", err);
                                continue
                            }
                        }
                        Err(err) => {
                            error!("{:?}", err);
                            continue
                        }
                    }
                }

                _ = ticker.tick() => {
                    let out_count = self.outbound_peer_count();
                    let in_count = self.inbound_peer_count();
                    info!("Have {} outbound connections and {} inbound connections", out_count, in_count);

                    // handle listening for inbound peers
                    if let Err(err) = self.listen_for_peers().await {
                        error!("{:?}", err);
                    }

                    if self.dns_seed && rand::rng().random_range(0..2) == 1 {
                        // drop a peer so we can try another
                        self.drop_random_peer().await;
                    }

                    // periodically try connecting to some saved peers
                    if let Err(err) = self.connect_to_peers().await {
                        error!("{:?}", err);
                    }
                }

                _ = &mut shutdown_chan_rx => {
                    info!("Peer manager shutting down");
                    self.shutdown().await;
                    break Ok(())
                }
            }
        }
    }

    /// Shutdown peers, http server and irc
    pub async fn shutdown(&self) {
        let mut shutdowns = Vec::new();

        // collect all outbound connected peers
        let out_peers = {
            let mut out_peers = self.out_peers.write().unwrap();
            out_peers
                .drain()
                .map(|(_addr, shutdown)| shutdown)
                .collect::<Vec<_>>()
        };
        shutdowns.extend(out_peers);

        // collect all inbound connected peers
        let in_peers = {
            let mut in_peers = self.in_peers.write().unwrap();
            in_peers
                .drain()
                .map(|(_addr, shutdown)| shutdown)
                .collect::<Vec<_>>()
        };
        shutdowns.extend(in_peers);

        // collect http server shutdown if it's running
        if let Some(server_shutdown) = self.server_shutdown.lock().unwrap().take() {
            shutdowns.push(server_shutdown);
        }

        // collect irc shutdown if it's running
        if let Some(irc_shutdown) = self.irc_shutdown.lock().unwrap().take() {
            shutdowns.push(irc_shutdown)
        }

        // shut everything down
        for shutdown in shutdowns {
            shutdown.send().await;
        }
    }

    fn inbound_peer_count(&self) -> usize {
        self.in_peers.read().unwrap().len()
    }

    fn outbound_peer_count(&self) -> usize {
        self.out_peers.read().unwrap().len()
    }

    /// Try connecting to some recent peers
    async fn connect_to_peers(self: &Arc<Self>) -> Result<(), PeerManagerError> {
        if let Some(peer) = self.peer {
            if self.outbound_peer_count() != 0 {
                // only connect to the explicitly requested peer once
                return Ok(());
            }

            // try reconnecting to the explicit peer
            info!("Attempting to connect to: {}", peer);
            self.connect(&peer).await?;
            info!("Connected to peer: {}", peer);
            return Ok(());
        }

        // are we syncing?
        let (ibd, _height) =
            PeerManager::is_initial_block_download(&self.ledger, &self.block_store)?;

        let want = if ibd {
            // only connect to 1 peer until we're synced.
            // If this client is a bad actor we'll find out about the real
            // chain as soon as we think we're done with them and find more peers
            1
        } else {
            // otherwise try to keep us maximally connected
            MAX_OUTBOUND_PEER_CONNECTIONS
        };

        let mut count = self.outbound_peer_count();
        let mut need = want.saturating_sub(count);
        if need == 0 {
            return Ok(());
        }

        let mut tried = HashMap::new();

        info!(
            "Have {} outbound connections, want {}. Trying some peer addresses now",
            count, want
        );

        // try to satisfy desired outbound peer count
        while need > 0 {
            let addrs = self.peer_store.get(need)?;
            if addrs.is_empty() {
                // no more attempts possible at the moment
                info!("No more peer addresses to try right now");
                return Ok(());
            }
            for addr in addrs {
                if tried.get(&addr).is_some() {
                    // we already tried this peer address.
                    // this shouldn't really be necessary if peer storage is respecting
                    // proper retry intervals but it doesn't hurt to be safe
                    info!(
                        "Already tried to connect to {} this time, will try again later",
                        addr
                    );
                    return Ok(());
                }
                tried.insert(addr, true);

                // is it banned?
                if self.ban_map.get(&addr.ip().to_string()).is_some() {
                    info!("Skipping and removing banned host: {}", addr.ip());
                    if let Err(err) = self
                        .peer_store
                        .delete(addr)
                        .map_err(|err| PeerManagerError::RemovePeer(addr, err))
                    {
                        error!("{:?}", err);
                    }
                    continue;
                }

                info!("Attempting to connect to: {}", addr);
                match self.connect(&addr).await {
                    Ok(_) => {
                        info!("Connected to peer: {}", &addr);
                    }
                    Err(err) => {
                        error!("{:?}", err);
                    }
                }
            }
            count = self.outbound_peer_count();
            need = want - count;
        }

        info!(
            "Have {} outbound connections. Done trying new peer addresses",
            count
        );

        Ok(())
    }

    /// Connect to a peer
    async fn connect(self: &Arc<Self>, addr: &SocketAddr) -> Result<(), PeerManagerError> {
        let my_addr = if self.accepting.load(Ordering::Relaxed)
            && self.open.load(Ordering::Relaxed)
            && self.my_external_ip.is_some()
        {
            // advertise ourself as open
            self.my_external_ip
                .map(|my_external_ip| SocketAddr::from((my_external_ip, self.port)))
        } else {
            None
        };

        let (shutdown_chan_tx, shutdown_chan_rx) = shutdown_channel();
        let mut peer = Peer::new(
            None,
            self.genesis_id,
            Arc::clone(&self.peer_store),
            Arc::clone(&self.block_store),
            Arc::clone(&self.ledger),
            Arc::clone(&self.processor),
            Arc::clone(&self.tx_queue),
            Arc::clone(&self.block_queue),
            self.addr_chan.0.clone(),
            *addr,
            shutdown_chan_rx,
        );

        if !self.check_outbound_set(addr) {
            return Err(PeerValidationError::TooManyConnections.into());
        }

        // connect to the peer
        peer.connect(self.peer_nonce, my_addr).await?;

        let arc_self = Arc::clone(self);
        let addr = *addr;
        peer.on_shutdown(move || {
            arc_self.remove_from_outbound_set(&addr);
        });

        let handle = peer.spawn();
        let shutdown = Shutdown::new(handle, shutdown_chan_tx);
        self.add_to_outbound_set(&addr, shutdown);

        Ok(())
    }

    /// Check to see if it's time to start accepting connections and do so if necessary
    async fn listen_for_peers(self: &Arc<Self>) -> Result<(), PeerManagerError> {
        // client is launched with no_accept
        if !self.accept {
            return Ok(());
        }
        // this is true when we start listening for peers
        if self.accepting.load(Ordering::Relaxed) {
            return Ok(());
        }

        // don't accept new connections while we're syncing
        let (ibd, _height) = Self::is_initial_block_download(&self.ledger, &self.block_store)?;
        if ibd {
            info!("We're still syncing. Not accepting new connections yet");
            return Ok(());
        }

        self.accepting.store(true, Ordering::Relaxed);
        if let Err(err) = self.accept_connections() {
            error!("{:?}", err);
        }

        // give us some time to generate a certificate and start listening
        // so we can correctly report connectivity to outbound peers
        sleep_until(Instant::now() + Duration::from_secs(1)).await;

        if !self.open.load(Ordering::Relaxed) {
            // if we don't yet think we're open try connecting to ourself to see if maybe we are.
            // if the user manually forwarded a port on their router this is when we'd find out.
            info!("Checking to see if we're open for public inbound connections");
            if let Some(my_external_ip) = self.my_external_ip {
                let my_addr = SocketAddr::from((my_external_ip, self.port));
                if self.peer_store.store(my_addr).is_ok() {
                    if let Err(PeerManagerError::PeerConnection(PeerConnectionError::Connect(
                        _addr,
                        WsError::Http(response),
                    ))) = self.connect(&my_addr).await
                    {
                        if response.status() == StatusCode::LOOP_DETECTED {
                            self.open.store(true, Ordering::Relaxed);
                        }
                    }

                    let out_peer = self.out_peers.write().unwrap().remove(&my_addr);
                    if let Some(shutdown) = out_peer {
                        shutdown.send().await;
                    }
                }
                if self.open.load(Ordering::Relaxed) {
                    info!("Open for public inbound connections");
                } else {
                    info!("Not open for public inbound connections");
                }
            }
        }

        Ok(())
    }

    /// Accept incoming peer connections
    fn accept_connections(self: &Arc<Self>) -> Result<(), PeerManagerError> {
        let (cert_path, key_path) = match (self.cert_path.as_ref(), self.key_path.as_ref()) {
            (Some(cert_path), Some(key_path)) => (cert_path.clone(), key_path.clone()),
            _ => {
                // generate new certificate and key for tls on each run
                info!("Generating TLS certificate and key");
                match generate_self_signed_cert_and_key(&self.data_dir) {
                    Ok((cert_path, key_path)) => (cert_path, key_path),
                    Err(err) => return Err(err.into()),
                }
            }
        };

        let bind_v4v6 = format!("[::]:{}", self.port);
        let addr = SocketAddr::from_str(&bind_v4v6).map_err(ParsingError::IpAddress)?;
        let (shutdown_chan_tx, shutdown_chan_rx) = shutdown_channel();
        let server_config = server_config(&cert_path, &key_path)?;
        let server = HttpServer::new(addr, server_config, Arc::clone(self), shutdown_chan_rx);
        let mut server_shutdown = self.server_shutdown.lock().unwrap();
        *server_shutdown = Some(Shutdown::new(server.spawn(), shutdown_chan_tx));

        Ok(())
    }

    /// Helper to check if outbound peers will fit
    fn check_outbound_set(&self, addr: &SocketAddr) -> bool {
        let out_peers = self.out_peers.read().unwrap();

        if out_peers.len() == MAX_OUTBOUND_PEER_CONNECTIONS {
            // too many connections
            return false;
        }

        if out_peers.contains_key(addr) {
            // already connected
            return false;
        }

        true
    }

    /// Helper to add peers to the outbound set
    fn add_to_outbound_set(&self, addr: &SocketAddr, shutdown: Shutdown) {
        let mut out_peers = self.out_peers.write().unwrap();
        out_peers.insert(*addr, shutdown);
        info!("Outbound peer count: {}", out_peers.len());
    }

    /// Helper to check if in peers will fit
    fn check_inbound_set(&self, addr: SocketAddr) -> bool {
        let in_peers = self.in_peers.read().unwrap();
        if in_peers.len() == self.inbound_limit {
            // too many connections
            return false;
        }
        if in_peers.get(&addr).is_some() {
            // already connected
            return false;
        }

        true
    }

    /// Helper to add peers to the inbound set if they'll fit
    fn add_to_inbound_set(&self, addr: SocketAddr, shutdown: Shutdown) -> bool {
        // update the count for this IP
        let mut in_peer_count_by_host = self.in_peer_count_by_host.write().unwrap();
        match in_peer_count_by_host.get_mut(&addr) {
            Some(count) => {
                *count += 1;
            }
            None => {
                in_peer_count_by_host.insert(addr, 1);
            }
        }
        let mut in_peers = self.in_peers.write().unwrap();
        in_peers.insert(addr, shutdown);
        info!("Inbound peer count: {}", in_peers.len());

        true
    }

    /// Helper to check if a peer address exists in the outbound set
    fn exists_in_outbound_set(&self, addr: &SocketAddr) -> bool {
        self.out_peers.read().unwrap().get(addr).is_some()
    }

    /// Helper to remove peers from the outbound set
    fn remove_from_outbound_set(&self, addr: &SocketAddr) {
        let mut out_peers = self.out_peers.write().unwrap();
        if let Some(_shutdown) = out_peers.remove(addr) {
            info!("Outbound peer count: {}", out_peers.len());
        }
    }

    /// Helper to remove peers from the inbound set
    fn remove_from_inbound_set(&self, addr: &SocketAddr) {
        // we parsed this address on the way in so an error isn't possible
        let mut in_peers = self.in_peers.write().unwrap();
        if let Some(_shutdown) = in_peers.remove(addr) {
            info!("Inbound peer count: {}", in_peers.len());
        }

        let mut in_peer_count_by_host = self.in_peer_count_by_host.write().unwrap();
        if let Entry::Occupied(mut count) = in_peer_count_by_host.entry(*addr) {
            *count.get_mut() -= 1;
            if *count.get() == 0 {
                count.remove_entry();
            }
        };
    }

    /// Drop a random peer. Used by seeders.
    async fn drop_random_peer(&self) {
        let out_peer = {
            let mut out_peers = self.out_peers.write().unwrap();
            out_peers
                .keys()
                .choose(&mut rand::rng())
                .cloned()
                .and_then(|addr| out_peers.remove_entry(&addr))
        };
        if let Some((addr, shutdown)) = out_peer {
            info!("Dropping random peer: {}", addr);
            shutdown.send().await;
        }
    }

    /// Validate a peer addresses
    fn validate_peer_address(&self, addr_str: String) -> Result<SocketAddr, PeerValidationError> {
        // resolve address
        let addr = resolve_host(&addr_str)
            .map_err(|err| PeerValidationError::ResolveFailed(addr_str, err))?;

        // don't accept ourself
        if self.my_external_ip == Some(addr.ip()) && self.port == addr.port() {
            return Err(PeerValidationError::IsOurs(addr));
        }

        // filter out local networks
        if addr_is_reserved(&addr) {
            return Err(PeerValidationError::IsLocal(addr));
        }

        Ok(addr)
    }

    /// Returns true if it appears we're still syncing the block chain.
    pub fn is_initial_block_download(
        ledger: &Arc<LedgerDisk>,
        block_store: &Arc<BlockStorageDisk>,
    ) -> Result<(bool, u64), PeerManagerError> {
        let Some((_tip_id, tip_header, _when)) =
            Processor::get_chain_tip_header(ledger, block_store)?
        else {
            return Ok((true, 0));
        };

        if CHECKPOINTS_ENABLED && tip_header.height < LATEST_CHECKPOINT_HEIGHT {
            return Ok((true, tip_header.height));
        }

        let now = now_as_secs();
        Ok((tip_header.time < (now - MAX_TIP_AGE), tip_header.height))
    }
}

#[derive(Error)]
pub enum PeerManagerError {
    #[error("failed to remove peer, address: {0}")]
    RemovePeer(SocketAddr, #[source] PeerStorageError),
    #[error("failed to save peer, address: {0}")]
    SavePeer(SocketAddr, #[source] PeerStorageError),

    #[error("peer connection")]
    PeerConnection(#[from] PeerConnectionError),
    #[error("peer storage")]
    PeerStorage(#[from] PeerStorageError),
    #[error("peer validation")]
    PeerValidation(#[from] PeerValidationError),

    #[error("channel")]
    Channel(#[from] ChannelError),
    #[error("parsing")]
    Parsing(#[from] ParsingError),
    #[error("processor")]
    Processor(#[from] ProcessorError),
    #[error("tls")]
    Tls(#[from] TlsError),

    #[error("network interface")]
    NetworkInterface(#[from] network_interface::Error),
}

impl_debug_error_chain!(PeerManagerError, "peer manager");

impl From<tokio::sync::mpsc::error::SendError<String>> for PeerManagerError {
    fn from(err: tokio::sync::mpsc::error::SendError<String>) -> Self {
        Self::Channel(ChannelError::Send("addr", err.to_string()))
    }
}

#[derive(Error, Debug)]
pub enum PeerValidationError {
    #[error("ip {0} is in local address space")]
    IsLocal(SocketAddr),
    #[error("peer address is ours {0}")]
    IsOurs(SocketAddr),
    #[error("failed to resolve peer address {0}")]
    ResolveFailed(String, #[source] ParsingError),
    #[error("too many connections")]
    TooManyConnections,
}

/// Server to listen for and handle incoming secure WebSocket connections
pub struct HttpServer {
    socket_addr: SocketAddr,
    server_config: Arc<ServerConfig>,
    peer_manager: Arc<PeerManager>,
    shutdown_chan_rx: ShutdownChanReceiver,
}

impl HttpServer {
    pub fn new(
        socket_addr: SocketAddr,
        server_config: Arc<ServerConfig>,
        peer_manager: Arc<PeerManager>,
        shutdown_chan_rx: ShutdownChanReceiver,
    ) -> Self {
        Self {
            socket_addr,
            server_config,
            peer_manager,
            shutdown_chan_rx,
        }
    }

    /// Spawns the HttpServer's main loop.
    pub fn spawn(mut self) -> JoinHandle<Result<(), SpawnedError>> {
        tokio::spawn(async move { self.run().await.map_err(Into::into) })
    }

    /// Runs the HttpServer's main loop.
    pub async fn run(&mut self) -> Result<(), HttpServerError> {
        let listener = match TcpListener::bind(self.socket_addr)
            .await
            .map_err(|err| SocketError::BindTcp(self.socket_addr, err))
        {
            Ok(v) => v,
            Err(err) => {
                error!("{:?}", err);
                return Ok(());
            }
        };
        loop {
            tokio::select! {
                Ok((stream, remote_addr)) = listener.accept() => {
                    let server_config = Arc::clone(&self.server_config);

                    if let Ok(tls_stream) = TlsAcceptor::from(server_config).accept(stream).await {
                        if let Err(err) = self.handle_connection(tls_stream, remote_addr).await {
                            error!("{:?}", err);
                            continue;
                        }
                    }
                }

                _ = &mut self.shutdown_chan_rx => {
                    break Ok(())
                }
            }
        }
    }

    async fn handle_connection(
        &self,
        tls_stream: TlsStream<TcpStream>,
        remote_addr: SocketAddr,
    ) -> Result<(), HttpServerError> {
        // handle incoming connection upgrade requests
        let callback = |request: &Request, mut response: Response| {
            // append our protocol header
            response.headers_mut().append(
                header::SEC_WEBSOCKET_PROTOCOL,
                PROTOCOL
                    .parse()
                    .expect("websocket protocol failed to parse"),
            );

            // is it banned?
            if self
                .peer_manager
                .ban_map
                .get(&remote_addr.ip().to_string())
                .is_some()
            {
                info!("Rejecting connection from banned host: {}", remote_addr);
                *response.status_mut() = StatusCode::FORBIDDEN;
                return Ok(response);
            }

            // check the connection limit for this peer address
            if !self.check_host_connection_limit(&remote_addr) {
                info!(
                    "Too many connections from this peer's host: {}",
                    &remote_addr
                );
                *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;

                return Ok(response);
            }

            // check the peer nonce
            if let Some(their_nonce_header) = request.headers().get("Cruzbit-Peer-Nonce") {
                match their_nonce_header
                    .to_str()
                    .map_err(ParsingError::HttpHeader)
                {
                    Ok(nonce_str) => {
                        match nonce_str.parse::<u32>().map_err(ParsingError::Integer) {
                            Ok(nonce) if nonce == self.peer_manager.peer_nonce => {
                                info!("Received connection with our own nonce");
                                *response.status_mut() = StatusCode::LOOP_DETECTED;
                                return Ok(response);
                            }
                            Ok(_) => {
                                // nonce is different
                            }
                            Err(err) => {
                                let err = HttpServerError::HeaderNonceInvalid(err);
                                error!("{:?}", err);
                            }
                        }
                    }
                    Err(err) => {
                        let err = HttpServerError::HeaderNonceInvalid(err);
                        error!("{:?}", err);
                    }
                }
            };

            // if they set their address it means they think they are open
            let header_addr = match request.headers().get("Cruzbit-Peer-Address") {
                Some(header) => match header.to_str().map_err(|err| {
                    HttpServerError::HeaderPeerAddressInvalid(ParsingError::HttpHeader(err))
                }) {
                    Ok(header_addr_str) => {
                        // validate the address
                        match self
                            .peer_manager
                            .validate_peer_address(header_addr_str.to_owned())
                            .map_err(HttpServerError::PeerValidation)
                        {
                            Ok(header_addr) => Some(header_addr),
                            Err(err) => {
                                error!("{:?}", err);
                                // don't proceed to save it
                                None
                            }
                        }
                    }
                    Err(err) => {
                        error!("{:?}", err);
                        None
                    }
                },
                None => None,
            };

            if let Some(addr) = header_addr {
                // see if we're already connected outbound to them
                if self.peer_manager.exists_in_outbound_set(&addr) {
                    info!("Already connected to {}, dropping inbound connection", addr);
                    // write back error reply
                    *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                    return Ok(response);
                } else {
                    // save their address for later use
                    if let Err(err) = self.peer_manager.peer_store.store(addr) {
                        info!("Error saving peer: {}, address: {}", err, &addr);
                    }
                }
            };

            Ok(response)
        };

        // accept the new websocket
        let conn = match accept_hdr_async(tls_stream, callback).await {
            Ok(v) => v,
            Err(err) => {
                return Err(PeerConnectionError::Accept(remote_addr, err).into());
            }
        };

        let (shutdown_chan_tx, shutdown_chan_rx) = shutdown_channel();
        let mut peer = Peer::new(
            Some(EitherWebSocketStream::Right(conn)),
            self.peer_manager.genesis_id,
            Arc::clone(&self.peer_manager.peer_store),
            Arc::clone(&self.peer_manager.block_store),
            Arc::clone(&self.peer_manager.ledger),
            Arc::clone(&self.peer_manager.processor),
            Arc::clone(&self.peer_manager.tx_queue),
            Arc::clone(&self.peer_manager.block_queue),
            self.peer_manager.addr_chan.0.clone(),
            remote_addr,
            shutdown_chan_rx,
        );

        if !self.peer_manager.check_inbound_set(remote_addr) {
            return Ok(());
        }

        let peer_manager = Arc::clone(&self.peer_manager);
        peer.on_shutdown(move || {
            peer_manager.remove_from_inbound_set(&remote_addr);
        });

        info!("New peer connection from: {}", &remote_addr);
        let handle = peer.spawn();
        let shutdown = Shutdown::new(handle, shutdown_chan_tx);
        self.peer_manager.add_to_inbound_set(remote_addr, shutdown);

        Ok(())
    }

    /// Returns false if this host has too many inbound connections already.
    fn check_host_connection_limit(&self, addr: &SocketAddr) -> bool {
        // filter out local networks
        if addr_is_reserved(addr) {
            // no limit for loopback peers
            return true;
        }

        match self
            .peer_manager
            .in_peer_count_by_host
            .read()
            .unwrap()
            .get(addr)
        {
            Some(count) => *count < MAX_INBOUND_PEER_CONNECTIONS_FROM_SAME_HOST,
            None => true,
        }
    }
}

#[derive(Error)]
pub enum HttpServerError {
    #[error("nonce in header is invalid")]
    HeaderNonceInvalid(#[source] ParsingError),
    #[error("peer address in header is invalid")]
    HeaderPeerAddressInvalid(#[source] ParsingError),

    #[error("peer connection")]
    PeerConnection(#[from] PeerConnectionError),
    #[error("peer validation")]
    PeerValidation(#[from] PeerValidationError),
}

impl_debug_error_chain!(HttpServerError, "http server");

/// Do any of our local IPs match our external IP?
pub fn have_local_ip_match(external_ip: &IpAddr) -> Result<bool, PeerManagerError> {
    let ifaces = NetworkInterface::show()?;
    for i in ifaces {
        for address in &i.addr {
            if address.ip() == *external_ip {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Determine external IP address
pub async fn determine_external_ip() -> Option<IpAddr> {
    // attempt to obtain ip with fallbacks
    let mut ip_services = [
        "api.ipify.org",
        "checkip.amazonaws.com",
        "icanhazip.com",
        "ident.me",
        "myip.dnsomatic.com",
        "whatismyip.akamai.com",
    ];
    ip_services.shuffle(&mut rand::rng());

    async fn try_connect(host: &str) -> Result<Option<IpAddr>, ExternalIpError> {
        let addr = resolve_host(&format!("{}:443", host))?;
        let stream = timeout(Duration::from_secs(5), TcpStream::connect(&addr))
            .await
            .map_err(ExternalIpError::Timeout)?
            .map_err(|err| SocketError::SendTo(addr, err))?;
        let dnsname = ServerName::try_from(host)?.to_owned();
        let client_config = tls::client_config(false);
        let connector = TlsConnector::from(Arc::new(client_config));
        let mut tls_stream = connector
            .connect(dnsname, stream)
            .await
            .map_err(|err| ExternalIpError::Socket(SocketError::TlsConnect(addr, err)))?;
        let content = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            host
        );
        tls_stream
            .write_all(&content.into_bytes())
            .await
            .map_err(|err| SocketError::SendTo(addr, err))?;
        let mut buffer = Vec::new();
        tls_stream
            .read_to_end(&mut buffer)
            .await
            .map_err(|err| SocketError::ReceiveFrom(addr, err))?;
        let response = from_utf8(&buffer).map_err(DataError::String)?;
        let body = response.trim_matches(char::from(0));
        let line = body
            .split('\n')
            .filter(|line| !line.trim().is_empty())
            .last()
            .map(str::to_string);
        match line {
            Some(ip_string) => {
                let addr = IpAddr::from_str(ip_string.as_str()).map_err(ParsingError::IpAddress)?;
                info!("Found external IP: {}", addr);
                Ok(Some(addr))
            }
            None => Ok(None),
        }
    }

    for (i, host) in ip_services.into_iter().enumerate() {
        if i > 0 {
            info!("Retrying...");
        }
        match try_connect(host).await {
            Ok(ip) => {
                if ip.is_some() {
                    return ip;
                }
            }
            Err(err) => {
                error!("{:?}", err);
            }
        }
    }

    None
}

#[derive(Error)]
pub enum ExternalIpError {
    #[error("connection timeout")]
    Timeout(#[source] tokio::time::error::Elapsed),

    #[error("data")]
    Data(#[from] DataError),
    #[error("socket")]
    Socket(#[from] SocketError),
    #[error("parsing")]
    Parsing(#[from] ParsingError),

    #[error("dns")]
    DnsName(#[from] tokio_rustls::rustls::pki_types::InvalidDnsNameError),
}

impl_debug_error_chain!(ExternalIpError, "external ip");
