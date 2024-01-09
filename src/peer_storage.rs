use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;

use crate::error::{DataError, DbError, EncodingError, ParsingError};

/// An interface for storing peer addresses and information about their connectivity.
pub trait PeerStorage {
    /// Stores a peer address. Returns true if the peer was newly added to storage.
    fn store(&self, addr: SocketAddr) -> Result<bool, PeerStorageError>;

    /// Returns some peers for us to attempt to connect to.
    fn get(&self, count: usize) -> Result<Vec<SocketAddr>, PeerStorageError>;

    /// Returns some peers to tell others about last active less than "when" ago.
    fn get_since(&self, count: usize, when: Duration) -> Result<Vec<SocketAddr>, PeerStorageError>;

    /// Is called to explicitly remove a peer address from storage.
    fn delete(&self, addr: SocketAddr) -> Result<(), PeerStorageError>;

    /// Is called prior to attempting to connect to the peer.
    fn on_connect_attempt(&self, addr: SocketAddr) -> Result<(), PeerStorageError>;

    /// Is called upon successful handshake with the peer.
    fn on_connect_success(&self, addr: SocketAddr) -> Result<(), PeerStorageError>;

    /// Is called upon connection failure.
    fn on_connect_failure(&self, addr: SocketAddr) -> Result<(), PeerStorageError>;

    /// Is called upon disconnection.
    fn on_disconnect(&self, addr: SocketAddr) -> Result<(), PeerStorageError>;
}

#[derive(Error, Debug)]
pub enum PeerStorageError {
    #[error("data")]
    Data(#[from] DataError),
    #[error("db")]
    Db(#[from] DbError),
    #[error("encoding")]
    Encoding(#[from] EncodingError),
    #[error("parsing")]
    Parsing(#[from] ParsingError),
    #[error("peer storage not found")]
    PeerStorageNotFound(#[from] PeerStorageNotFoundError),
}

#[derive(Error, Debug)]
pub enum PeerStorageNotFoundError {
    #[error("peer info for {0} not found")]
    PeerInfo(SocketAddr),
    #[error("peer {0} not found")]
    Peer(SocketAddr),
}
