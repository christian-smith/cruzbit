use std::error::Error as StdError;
use std::fmt::{self, Write};
use std::net::{AddrParseError, SocketAddr};
use std::num::ParseIntError;
use std::path::PathBuf;

use thiserror::Error;

/// Helper to display an error's chain of sources
pub trait ErrChain {
    fn chain(&self) -> Result<String, fmt::Error>;
}

impl<E: ?Sized + StdError> ErrChain for E {
    fn chain(&self) -> Result<String, fmt::Error> {
        let mut buf = String::new();
        write!(buf, "{}", self)?;
        for err in std::iter::successors(self.source(), |&error| error.source()) {
            write!(buf, " -> {}", err)?;
        }
        Ok(buf)
    }
}

#[macro_export]
macro_rules! impl_debug_error_chain {
    ($t:ident, $type:expr) => {
        impl std::fmt::Debug for $t
        where
            $t: $crate::error::ErrChain,
        {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{} -> {}", $type, self.chain()?)
            }
        }
    };
}
pub use impl_debug_error_chain;

#[derive(Error, Debug)]
pub enum ChannelError {
    #[error("receive on {0} channel")]
    OneshotReceive(
        &'static str,
        #[source] tokio::sync::oneshot::error::RecvError,
    ),
    #[error("send on {0} channel")]
    OneshotSend(&'static str),
    #[error("receive on {0} channel: {1}")]
    Receive(&'static str, String),
    #[error("send on {0} channel: {1}")]
    Send(&'static str, String),
}

#[derive(Error, Debug)]
pub enum DataError {
    #[error("bytes not found")]
    NotFound,
    #[error("invalid bytes for public key")]
    PublicKey(#[source] std::array::TryFromSliceError),
    #[error("invalid bytes for string")]
    String(#[source] std::str::Utf8Error),
    #[error("invalid bytes for u32")]
    U32(#[source] std::array::TryFromSliceError),
    #[error("invalid bytes for u64")]
    U64(#[source] std::array::TryFromSliceError),

    #[error(transparent)]
    Ed25519(#[from] ed25519_compact::Error),
}

#[derive(Error, Debug)]
pub enum DbError {
    #[error("failed to open database at: {0}")]
    Open(PathBuf, #[source] leveldb::error::Error),
    #[error("failed to read")]
    Read(#[source] leveldb::error::Error),
    #[error("failed to repair database at: {0}")]
    Repair(PathBuf, #[source] leveldb::error::Error),
    #[error("failed to write")]
    Write(#[source] leveldb::error::Error),
    #[error("failed to write batch")]
    WriteBatch(#[source] leveldb::error::Error),
}

#[derive(Error, Debug)]
pub enum EncodingError {
    #[error("failed to base64 decode bytes: {0}")]
    Base64Decode(base64ct::Error),
    #[error("failed to base64 encode bytes: {0}")]
    Base64Encode(base64ct::InvalidLengthError),
    #[error("failed to bincode decode bytes, db may be using gob (golang)")]
    BincodeDecode(#[source] Box<bincode::ErrorKind>),
    #[error("failed to bincode encode bytes")]
    BincodeEncode(#[source] Box<bincode::ErrorKind>),
    #[error("failed to hex decode bytes")]
    HexDecode(#[source] faster_hex::Error),
    #[error("failed to hex encode bytes")]
    HexEncode(#[source] faster_hex::Error),
    #[error("failed to decode pem")]
    Pem,
}

#[derive(Error, Debug)]
pub enum FileError {
    #[error("failed to compress file at: {0}")]
    Compress(PathBuf, #[source] std::io::Error),
    #[error("failed to create file at: {0}")]
    Create(PathBuf, #[source] std::io::Error),
    #[error("failed to decompress file at: {0}")]
    Decompress(PathBuf, #[source] std::io::Error),
    #[error("failed to open file at: {0}")]
    Open(PathBuf, #[source] std::io::Error),
    #[error("failed to read file at: {0}")]
    Read(PathBuf, #[source] std::io::Error),
    #[error("failed to write to file at: {0}")]
    Write(PathBuf, #[source] std::io::Error),
}

#[derive(Error, Debug)]
pub enum JsonError {
    #[error("failed to deserialize")]
    Deserialize(#[source] serde_json::error::Error),
    #[error("failed to serialize")]
    Serialize(#[source] serde_json::error::Error),
}

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("private key")]
    PrivateKeyDecode(#[source] EncodingError),
}

#[derive(Error, Debug)]
pub enum ParsingError {
    #[error("failed to parse dns data")]
    DnsData(#[source] domain::base::wire::ParseError),
    #[error("failed to parse http header")]
    HttpHeader(#[source] tokio_tungstenite::tungstenite::http::header::ToStrError),
    #[error("failed to parse integer")]
    Integer(#[source] ParseIntError),
    #[error("failed to parse ip address")]
    IpAddress(#[source] AddrParseError),
    #[error("failed to resolve ip address")]
    ToSocketAddr(#[source] std::io::Error),
}

#[derive(Error, Debug)]
pub enum SocketError {
    #[error("failed to bind to tcp socket: {0}")]
    BindTcp(SocketAddr, #[source] std::io::Error),
    #[error("failed to bind to udp socket: {0}")]
    BindUdp(SocketAddr, #[source] std::io::Error),
    #[error("failed to receive on socket")]
    Receive(#[source] std::io::Error),
    #[error("failed to receive on socket from: {0}")]
    ReceiveFrom(SocketAddr, #[source] std::io::Error),
    #[error("failed to send on socket to: {0}")]
    SendTo(SocketAddr, #[source] std::io::Error),
    #[error("failed to tls connect on stream: {0}")]
    TlsConnect(SocketAddr, #[source] std::io::Error),
}
