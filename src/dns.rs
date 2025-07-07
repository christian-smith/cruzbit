use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use domain::base::iana::Rcode;
use domain::base::{Message, MessageBuilder, Name, Rtype, StaticCompressor, StreamTarget};
use domain::rdata::{Aaaa, AllRecordData, A};
use log::{error, info};
use rand::seq::SliceRandom;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::constants::DEFAULT_CRUZBIT_PORT;
use crate::error::{impl_debug_error_chain, ErrChain, ParsingError, SocketError};
use crate::peer_storage::{PeerStorage, PeerStorageError};
use crate::peer_storage_disk::PeerStorageDisk;
use crate::shutdown::{ShutdownChanReceiver, SpawnedError};
use crate::utils::{now_as_duration, resolve_host};

const DNAME: &str = "client.cruzbit";

const SEEDERS: &[&str] = &["45.32.6.23:8831", "66.117.62.146:8831", "dns.cruzb.it:8831"];

/// Returns known peers in response to DNS queries.
pub struct DnsSeeder {
    peer_store: Arc<PeerStorageDisk>,
    sock: UdpSocket,
    port: u16,
    my_external_ip: Option<IpAddr>,
    shutdown_chan_rx: ShutdownChanReceiver,
}

impl DnsSeeder {
    /// Creates a new DNS seeder given a PeerStorage interface.
    pub async fn new(
        peer_store: Arc<PeerStorageDisk>,
        port: u16,
        my_external_ip: Option<IpAddr>,
        shutdown_chan_rx: ShutdownChanReceiver,
    ) -> Self {
        let sock = UdpSocket::bind(format!("0.0.0.0:{port}"))
            .await
            .expect("dns seeder couldn't bind to address");

        Self {
            peer_store,
            sock,
            port,
            my_external_ip,
            shutdown_chan_rx,
        }
    }

    /// Spawns the DNS Seeder's main loop.
    pub fn spawn(self) -> JoinHandle<Result<(), SpawnedError>> {
        tokio::spawn(async move { self.run().await.map_err(Into::into) })
    }

    /// Runs the DNS Seeder's main loop.
    pub async fn run(mut self) -> Result<(), DnsSeederError> {
        let mut buf = vec![0; 512];

        loop {
            tokio::select! {
                recv = self.sock.recv_from(&mut buf) => {
                    match recv.map_err(|err| DnsSeederError::Socket(SocketError::Receive(err))) {
                        Ok((len, addr)) => {
                            let data = &buf[..len];
                            let request = match Message::from_octets(data).map_err(DnsSeederError::ShortMessage) {
                                Ok(v) => v,
                                Err(err) => {
                                    error!("{err:?}");
                                    continue;
                                }
                            };

                           if let Err(err) = self.handle_query(request, addr).await {
                               error!("{err:?}");
                               continue;
                           };
                        },
                        Err(err) => {
                            error!("{err:?}");
                            continue;
                        }
                    }
                }

                _ = &mut self.shutdown_chan_rx => {
                    info!("DNS Seeder shutting down");
                    break Ok(())
                }
            }
        }
    }

    async fn handle_query(
        &self,
        request: Message<&[u8]>,
        src: SocketAddr,
    ) -> Result<(), DnsSeederError> {
        let q = match request.question().next() {
            Some(Ok(v)) => v,
            Some(Err(err)) => return Err(DnsSeederError::ParseQuestion(err)),
            None => return Err(DnsSeederError::NoValue),
        };

        if q.qname().to_string() == DNAME && q.qtype() == Rtype::A {
            // get up to 128 peers that we've connected to in the last 48 hours
            let mut addresses = self
                .peer_store
                .get_since(128, now_as_duration() - Duration::from_secs(48 * 60 * 60))?;

            // add ourself
            if let Some(my_external_ip) = self.my_external_ip {
                addresses.push(SocketAddr::from((my_external_ip, self.port)));
            }

            // shuffle them
            addresses.shuffle(&mut rand::rng());

            let answer = MessageBuilder::new_vec();
            let mut answer = answer.start_answer(&request, Rcode::NOERROR)?;

            // return at most 4
            let limit = 4;
            for (i, addr) in addresses.iter().enumerate() {
                if i == limit {
                    break;
                }
                if addr.port() != DEFAULT_CRUZBIT_PORT {
                    continue;
                }
                if let IpAddr::V4(ip) = addr.ip() {
                    answer.push((q.qname(), 3600, A::new(ip)))?;
                } else if let IpAddr::V6(ip) = addr.ip() {
                    answer.push((q.qname(), 3600, Aaaa::new(ip)))?;
                }
            }

            self.sock
                .send_to(answer.as_slice(), src)
                .await
                .map_err(|err| SocketError::SendTo(src, err))?;
        }

        Ok(())
    }
}

/// Query DNS seeders
pub async fn query_for_peers() -> Result<Vec<String>, DnsSeederError> {
    let addr = SocketAddr::from_str("0.0.0.0:0").unwrap();
    let socket = UdpSocket::bind(addr)
        .await
        .map_err(|err| SocketError::BindUdp(addr, err))?;

    let msg = MessageBuilder::from_target(StaticCompressor::new(StreamTarget::new_vec())).unwrap();
    let mut msg = msg.question();
    msg.push((Name::<Vec<u8>>::from_str(DNAME).unwrap(), Rtype::A))?;
    let message = msg.finish().into_target();

    let mut peers = Vec::new();

    async fn handle_query(
        socket: &UdpSocket,
        addr: SocketAddr,
        message: &StreamTarget<Vec<u8>>,
    ) -> Result<Vec<String>, DnsSeederError> {
        socket
            .send_to(message.as_dgram_slice(), addr)
            .await
            .map_err(|err| DnsSeederError::Socket(SocketError::SendTo(addr, err)))?;

        let mut buffer = vec![0; 1232];
        let _ = timeout(Duration::from_secs(5), socket.recv_from(&mut buffer))
            .await
            .map_err(|err| DnsSeederError::QueryTimeout(addr, err))?;

        let response = Message::from_octets(buffer).map_err(DnsSeederError::ShortMessage)?;
        let mut peers = Vec::new();

        let answers = response
            .answer()
            .map_err(|err| DnsSeederError::Parsing(ParsingError::DnsData(err)))?;

        for record in answers.limit_to::<AllRecordData<_, _>>() {
            let a = record.map_err(DnsSeederError::ParseQuestion)?;

            info!("Seeder returned: {}", a.data());
            let peer = format!("{}:{}", a.data(), DEFAULT_CRUZBIT_PORT);
            peers.push(peer);
        }

        Ok(peers)
    }

    for seeder in SEEDERS.iter().map(|addr| resolve_host(addr)) {
        let seeder = match seeder {
            Ok(v) => v,
            Err(err) => {
                error!("{err:?}");
                continue;
            }
        };

        match handle_query(&socket, seeder, &message).await {
            Ok(seeder_peers) => peers.extend(seeder_peers),
            Err(err) => {
                error!("{err:?}");
                continue;
            }
        }
    }

    Ok(peers)
}

#[derive(Error)]
pub enum DnsSeederError {
    #[error("received no value")]
    NoValue,
    #[error("failed to parse question")]
    ParseQuestion(#[source] domain::base::wire::ParseError),
    #[error("connecting timeout querying seeder: {0}")]
    QueryTimeout(SocketAddr, #[source] tokio::time::error::Elapsed),

    #[error("parsing")]
    Parsing(#[from] ParsingError),
    #[error("peer storage")]
    PeerStorage(#[from] PeerStorageError),
    #[error("socket")]
    Socket(#[from] SocketError),

    #[error("dns message builder")]
    MessageBuilder(#[from] domain::base::message_builder::PushError),
    #[error("dns message")]
    ShortMessage(#[from] domain::base::message::ShortMessage),
}

impl_debug_error_chain!(DnsSeederError, "dns seeder");
