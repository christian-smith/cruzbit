use std::collections::hash_map::DefaultHasher;
use std::mem;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use argon2::{Algorithm, Argon2, Params, Version};
use crypto_secretbox::aead::{Aead, KeyInit};
use crypto_secretbox::XSalsa20Poly1305;
use cuckoofilter::{CuckooError, CuckooFilter};
use ed25519_compact::{KeyPair, PublicKey, SecretKey};
use futures::stream::SplitSink;
use futures::{SinkExt, StreamExt};
use leveldb::batch::{Batch, WriteBatch};
use leveldb::database::{self, Database};
use leveldb::iterator::{Iterable, LevelDBIterator};
use leveldb::options::{Options, ReadOptions, WriteOptions};
use log::{error, info};
use rand::RngCore;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{
    connect_async_tls_with_config, Connector, MaybeTlsStream, WebSocketStream,
};

use crate::block::{BlockHeader, BlockID};
use crate::error::{impl_debug_error_chain, ChannelError, DataError, DbError, ErrChain, JsonError};
use crate::peer::{PeerConnectionError, CONNECT_WAIT, WRITE_WAIT};
use crate::protocol::{
    FilterBlockMessage, FilterLoadMessage, GetBalanceMessage, GetPublicKeyTransactionsMessage,
    GetTransactionMessage, Message, PublicKeyTransactionsMessage, PushTransactionMessage,
};
use crate::shutdown::{shutdown_channel, Shutdown, ShutdownChanReceiver, SpawnedError};
use crate::tls::client_config;
use crate::transaction::{AsBase64, Transaction, TransactionError, TransactionID};

pub type TransactionCallback = Box<dyn Fn(&Arc<Wallet>, PushTransactionMessage) + Send + Sync>;
pub type FilterBlockCallback = Box<dyn Fn(&Arc<Wallet>, FilterBlockMessage) + Send + Sync>;

type OutChanSender = Sender<(Message, ResultChanSender)>;
type OutChanReceiver = Receiver<(Message, ResultChanSender)>;
type ResultChanSender = oneshot::Sender<WalletResult>;

/// Used to hold the result of synchronous requests
struct WalletResult {
    err: Option<ConnectionHandlerError>,
    message: Option<Message>,
}

struct WalletConnection {
    out_chan_tx: OutChanSender,
    shutdown: Shutdown,
}

struct WalletInner {
    passphrase: String,
    filter: CuckooFilter<DefaultHasher>,
    transaction_callback: Option<TransactionCallback>,
    filter_block_callback: Option<FilterBlockCallback>,
}

/// Wallet manages keys and transactions on behalf of a user.
pub struct Wallet {
    inner: Mutex<WalletInner>,
    connection: AsyncMutex<Option<WalletConnection>>,
    db: Database,
}

impl Wallet {
    /// Returns a new Wallet instance.
    pub fn new(wallet_db_path: PathBuf) -> Result<Arc<Self>, WalletError> {
        let mut options = Options::new();
        options.create_if_missing = true;
        let db = Database::open(&wallet_db_path, &options)
            .map_err(|err| DbError::Open(wallet_db_path, err))?;
        let wallet = Arc::new(Self {
            inner: Mutex::new(WalletInner {
                passphrase: "".to_owned(),
                filter: CuckooFilter::new(),
                transaction_callback: None,
                filter_block_callback: None,
            }),
            connection: AsyncMutex::new(None),
            db,
        });
        wallet.initialize_filter()?;

        Ok(wallet)
    }

    pub fn set_passphrase(&self, passphrase: String) -> Result<bool, WalletError> {
        // test that the passphrase was the most recent used
        let mut inner = self.inner();
        let pub_key = match self
            .db
            .get_u8(&ReadOptions::new(), &[NEWEST_PUBLIC_KEY_PREFIX])
            .map_err(DbError::Read)?
        {
            Some(v) => PublicKey::from_slice(&v[..]).map_err(DataError::Ed25519)?,
            None => {
                inner.passphrase = passphrase;
                return Ok(true);
            }
        };

        // fetch the private key
        let priv_key_db_key = encode_private_key_db_key(pub_key);
        let Some(encrypted_priv_key) = self
            .db
            .get_u8(&ReadOptions::new(), &priv_key_db_key)
            .map_err(DbError::Read)?
        else {
            return Ok(false);
        };

        // decrypt it
        decrypt_private_key(&encrypted_priv_key, &passphrase)?;

        // set it
        inner.passphrase = passphrase;

        Ok(true)
    }

    /// Generates, encrypts and stores new private keys and returns the public keys.
    pub fn new_keys(&self, count: usize) -> Result<Vec<PublicKey>, WalletError> {
        let mut inner = self.inner();
        let mut pub_keys = Vec::with_capacity(count);
        let batch = WriteBatch::new();

        for i in 0..count {
            // generate a new key
            let keypair = KeyPair::generate();
            let pub_key = keypair.pk;
            let priv_key = keypair.sk;
            pub_keys.push(pub_key);

            // encrypt the private key
            let encrypted_priv_key = encrypt_private_key(&priv_key, &inner.passphrase)?;
            let decrypted_priv_key = decrypt_private_key(&encrypted_priv_key, &inner.passphrase)?;

            // safety check
            if decrypted_priv_key != priv_key {
                return Err(WalletError::EncryptKeyMismatch);
            }

            // store the key
            let priv_key_db_key = encode_private_key_db_key(pub_key);
            batch.put_u8(&priv_key_db_key, &encrypted_priv_key);
            if i + 1 == count {
                batch.put_u8(&[NEWEST_PUBLIC_KEY_PREFIX], &pub_key[..])
            }

            // update the filter
            if let Err(err) = inner.filter.add(&pub_key[..]) {
                let err = WalletError::FilterInsertFailed(err);
                error!("{:?}", err);
            }
        }

        let wo = WriteOptions { sync: true };
        self.db.write(&wo, &batch).map_err(DbError::WriteBatch)?;

        Ok(pub_keys)
    }

    /// Adds an existing key pair to the database.
    pub fn add_key(&self, pub_key: PublicKey, priv_key: SecretKey) -> Result<(), WalletError> {
        // encrypt the private key
        let inner = self.inner();
        let encrypted_priv_key = encrypt_private_key(&priv_key, &inner.passphrase)?;
        let decrypted_priv_key = decrypt_private_key(&encrypted_priv_key, &inner.passphrase)?;

        // safety check
        if decrypted_priv_key != priv_key {
            return Err(WalletError::EncryptKeyMismatch);
        }

        // store the key
        let priv_key_db_key = encode_private_key_db_key(pub_key);
        let wo = WriteOptions { sync: true };
        self.db
            .put_u8(&wo, &priv_key_db_key, &encrypted_priv_key)
            .map_err(DbError::Write)?;

        Ok(())
    }

    /// Returns all of the public keys from the database.
    pub fn get_keys(&self) -> Result<Vec<PublicKey>, WalletError> {
        let priv_key_db_key = [PRIVATE_KEY_PREFIX];
        let mut pub_keys = Vec::new();

        let iter = self
            .db
            .keys_iter(&ReadOptions::new())
            .prefix(&priv_key_db_key);

        for key in iter {
            let pub_key = decode_private_key_db_key(&key)?;
            pub_keys.push(pub_key)
        }

        Ok(pub_keys)
    }

    /// Retrieve a private key for a given public key
    pub fn get_private_key(&self, pub_key: PublicKey) -> Result<Option<SecretKey>, WalletError> {
        // fetch the private key
        let priv_key_db_key = encode_private_key_db_key(pub_key);
        match self
            .db
            .get_u8(&ReadOptions::new(), &priv_key_db_key)
            .map_err(DbError::Read)?
        {
            Some(encrypted_priv_key) => {
                let inner = self.inner();
                let priv_key = decrypt_private_key(&encrypted_priv_key, &inner.passphrase)?;
                Ok(Some(priv_key))
            }
            None => Ok(None),
        }
    }

    /// Creates a ConnectionHandler that connects and interfaces with a peer
    pub async fn connect(
        self: &Arc<Self>,
        peer: SocketAddr,
        genesis_id: &BlockID,
        tls_verify: bool,
    ) -> Result<(), WalletError> {
        if !self.is_connected().await {
            let (shutdown_chan_tx, shutdown_chan_rx) = shutdown_channel();
            let (out_chan_tx, out_chan_rx) = channel(1);
            let mut connection_handler =
                ConnectionHandler::new(Arc::downgrade(self), out_chan_rx, shutdown_chan_rx);
            connection_handler
                .connect(peer, genesis_id, tls_verify)
                .await?;
            let shutdown = Shutdown::new(connection_handler.spawn(), shutdown_chan_tx);
            *self.connection.lock().await = Some(WalletConnection {
                out_chan_tx,
                shutdown,
            });
        }

        Ok(())
    }

    /// Returns true if the wallet is connected to a peer.
    pub async fn is_connected(&self) -> bool {
        let connection = self.connection.lock().await;
        if let Some(connection) = connection.as_ref() {
            return !connection.shutdown.is_finished();
        }

        false
    }

    /// Sets a callback to receive new transactions relevant to the wallet.
    pub fn set_transaction_callback(&self, callback: TransactionCallback) {
        self.inner().transaction_callback = Some(callback)
    }

    /// Sets a callback to receive new filter blocks with confirmed transactions relevant to this wallet.
    pub fn set_filter_block_callback(&self, callback: FilterBlockCallback) {
        self.inner().filter_block_callback = Some(callback);
    }

    /// Returns a public key's balance as well as the current block height.
    pub async fn get_balance(&self, pub_key: &PublicKey) -> Result<(u64, u64), WalletError> {
        let (result_chan_tx, result_chan_rx) = oneshot::channel();
        let mut conn = self.connection.lock().await;
        let conn = conn.as_mut().unwrap();
        conn.out_chan_tx
            .send((
                Message::GetBalance(GetBalanceMessage {
                    public_key: *pub_key,
                }),
                result_chan_tx,
            ))
            .await?;

        let result = result_chan_rx.await?;
        if let Some(err) = result.err {
            return Err(WalletError::ConnectionHandler(err));
        }
        let Some(Message::Balance(b)) = result.message else {
            return Err(WalletError::WalletResultMissing);
        };

        Ok((
            b.balance.expect("result should have a balance"),
            b.height.expect("result should have a height"),
        ))
    }

    /// Returns a set of public key balances as well as the current block height.
    /// Returns the current tip of the main chain's header.
    pub async fn get_tip_header(&self) -> Result<(BlockID, BlockHeader), WalletError> {
        let (result_chan_tx, result_chan_rx) = oneshot::channel();
        let mut conn = self.connection.lock().await;
        let conn = conn.as_mut().unwrap();
        conn.out_chan_tx
            .send((Message::GetTipHeader, result_chan_tx))
            .await?;

        let result = result_chan_rx.await?;
        if let Some(err) = result.err {
            return Err(WalletError::ConnectionHandler(err));
        }
        let Some(Message::TipHeader(Some(th))) = result.message else {
            return Err(WalletError::WalletResultMissing);
        };

        Ok((th.block_id, th.block_header))
    }

    /// Returns the peer's transaction relay policy.
    pub async fn get_transaction_relay_policy(&self) -> Result<(u64, u64), WalletError> {
        let (result_chan_tx, result_chan_rx) = oneshot::channel();
        let mut conn = self.connection.lock().await;
        let conn = conn.as_mut().unwrap();
        conn.out_chan_tx
            .send((Message::GetTransactionRelayPolicy, result_chan_tx))
            .await?;

        let result = result_chan_rx.await?;
        if let Some(err) = result.err {
            return Err(WalletError::ConnectionHandler(err));
        }

        let Some(Message::TransactionRelayPolicy(trp)) = result.message else {
            return Err(WalletError::WalletResultMissing);
        };

        Ok((trp.min_fee, trp.min_amount))
    }

    /// Sets the filter for the connection.
    pub async fn set_filter(&self) -> Result<(), WalletError> {
        let (result_chan_tx, result_chan_rx) = oneshot::channel();
        let filter = self.inner().filter.export();
        let mut conn = self.connection.lock().await;
        let conn = conn.as_mut().unwrap();
        conn.out_chan_tx
            .send((
                Message::FilterLoad(FilterLoadMessage {
                    r#type: "cuckoo".to_owned(),
                    filter,
                }),
                result_chan_tx,
            ))
            .await?;

        let result = result_chan_rx.await?;
        if let Some(err) = result.err {
            return Err(WalletError::ConnectionHandler(err));
        }

        match result.message {
            Some(Message::FilterResult(None)) => Ok(()),
            Some(Message::FilterResult(Some(fr))) => Err(WalletError::FilterResult(fr.error)),
            _ => Err(WalletError::WalletResultMissing),
        }
    }

    /// Send creates, signs and pushes a transaction out to the network.
    pub async fn send(
        &self,
        from: PublicKey,
        to: PublicKey,
        amount: u64,
        fee: u64,
        mut matures: Option<u64>,
        mut expires: Option<u64>,
        memo: Option<String>,
    ) -> Result<TransactionID, WalletError> {
        // fetch the private key
        let priv_key_db_key = encode_private_key_db_key(from);
        let Some(encrypted_priv_key) = self
            .db
            .get_u8(&ReadOptions::new(), &priv_key_db_key)
            .map_err(DbError::Read)?
        else {
            return Err(WalletNotFoundError::PublicKey(from).into());
        };

        // decrypt it
        let priv_key = decrypt_private_key(&encrypted_priv_key, &self.inner().passphrase)?;

        // get the current tip header
        let (_block_id, header) = self.get_tip_header().await?;

        // set these relative to the current height
        if let Some(matures) = matures.as_mut() {
            *matures += header.height;
        }
        if let Some(expires) = expires.as_mut() {
            *expires += header.height;
        }

        // create the transaction
        let mut tx = Transaction::new(
            Some(from),
            to,
            amount,
            Some(fee),
            matures,
            expires,
            header.height,
            memo,
        );

        // sign it
        tx.sign(priv_key)?;

        // push it
        let (result_chan_tx, result_chan_rx) = oneshot::channel();
        let mut conn = self.connection.lock().await;
        let conn = conn.as_mut().unwrap();
        conn.out_chan_tx
            .send((
                Message::PushTransaction(PushTransactionMessage { transaction: tx }),
                result_chan_tx,
            ))
            .await?;

        let result = result_chan_rx.await?;
        if let Some(err) = result.err {
            return Err(WalletError::ConnectionHandler(err));
        }
        let Some(Message::PushTransactionResult(ptr)) = result.message else {
            return Err(WalletError::WalletResultMissing);
        };

        if let Some(err) = ptr.error {
            Err(WalletError::PushTransactionResultMessage(err))
        } else if let Some(transaction_id) = ptr.transaction_id {
            Ok(transaction_id)
        } else {
            Err(WalletError::WalletResultNotFound)
        }
    }

    /// Retrieves information about a historic transaction.
    pub async fn get_transaction(
        &self,
        id: TransactionID,
    ) -> Result<(Option<Transaction>, Option<BlockID>, Option<u64>), WalletError> {
        let (result_chan_tx, result_chan_rx) = oneshot::channel();
        let mut conn = self.connection.lock().await;
        let conn = conn.as_mut().unwrap();
        conn.out_chan_tx
            .send((
                Message::GetTransaction(GetTransactionMessage { transaction_id: id }),
                result_chan_tx,
            ))
            .await?;

        let result = result_chan_rx.await?;
        if let Some(err) = result.err {
            return Err(WalletError::ConnectionHandler(err));
        }

        let Some(Message::Transaction(t)) = result.message else {
            return Err(WalletError::WalletResultMissing);
        };

        Ok((t.transaction, t.block_id, t.height))
    }

    /// Retrieves information about historic transactions involving the given public key.
    pub async fn get_public_key_transactions(
        &self,
        public_key: PublicKey,
        start_height: u64,
        end_height: u64,
        start_index: u32,
        limit: usize,
    ) -> Result<(u64, u64, u32, Option<Vec<FilterBlockMessage>>), WalletError> {
        let (result_chan_tx, result_chan_rx) = oneshot::channel();
        let mut conn = self.connection.lock().await;
        let conn = conn.as_mut().unwrap();
        conn.out_chan_tx
            .send((
                Message::GetPublicKeyTransactions(GetPublicKeyTransactionsMessage {
                    public_key,
                    start_height,
                    start_index,
                    end_height,
                    limit,
                }),
                result_chan_tx,
            ))
            .await?;

        let result = result_chan_rx.await?;
        if let Some(err) = result.err {
            return Err(WalletError::ConnectionHandler(err));
        }
        let Some(Message::PublicKeyTransactions(pkt)) = result.message else {
            return Err(WalletError::WalletResultMissing);
        };

        if let Some(error) = pkt.error {
            Err(WalletError::PublicKeyTransactionResultMessage(error))
        } else if let PublicKeyTransactionsMessage {
            public_key: _public_key,
            start_height: Some(start_height),
            stop_height: Some(stop_height),
            stop_index: Some(stop_index),
            filter_blocks,
            error: _error,
        } = pkt
        {
            Ok((start_height, stop_height, stop_index, filter_blocks))
        } else {
            Err(WalletError::WalletResultNotFound)
        }
    }

    /// Verifies that the private key associated with the given public key is intact in the database.
    pub fn verify_key(&self, pub_key: PublicKey) -> Result<(), WalletError> {
        // fetch the private key
        let priv_key_db_key = encode_private_key_db_key(pub_key);
        let Some(encrypted_priv_key) = self
            .db
            .get_u8(&ReadOptions::new(), &priv_key_db_key)
            .map_err(DbError::Read)?
        else {
            return Err(WalletNotFoundError::PrivateKey(pub_key).into());
        };

        // decrypt it
        let priv_key = decrypt_private_key(&encrypted_priv_key, &self.inner().passphrase)?;

        // check to make sure it can be used to derive the same public key
        let pub_key_derived = priv_key.public_key();
        if pub_key_derived != pub_key {
            return Err(WalletError::PrivateKeyDerive);
        }

        Ok(())
    }

    /// Called by WalletConnection for a FilterBlockMessage
    fn on_filter_block(self: &Arc<Self>, fb: FilterBlockMessage) {
        let Some(ref filter_block_callback) = self.inner().filter_block_callback else {
            return;
        };
        filter_block_callback(self, fb);
    }

    /// Called by WalletConnection for a PushTransactionMessage
    fn on_push_transaction(self: &Arc<Self>, pt: PushTransactionMessage) {
        if let Some(transaction_callback) = self.inner().transaction_callback.as_ref() {
            transaction_callback(self, pt);
        }
    }

    /// Is called to shutdown the wallet
    pub async fn shutdown(&self) -> Result<(), WalletError> {
        let mut conn = self.connection.lock().await;
        let Some(conn) = conn.take() else {
            return Ok(());
        };
        conn.shutdown.send().await;

        Ok(())
    }

    /// Initialize the filter
    fn initialize_filter(&self) -> Result<(), WalletError> {
        let mut capacity = 4096;

        let pub_keys = self.get_keys()?;
        if pub_keys.len() > capacity / 2 {
            capacity = pub_keys.len() * 2;
        }

        let mut inner = self.inner();
        inner.filter = CuckooFilter::with_capacity(capacity);

        for pub_key in pub_keys {
            if let Err(err) = inner.filter.add(&pub_key[..]) {
                let err = WalletError::FilterInsertFailed(err);
                error!("{:?}", err);
            }
        }

        Ok(())
    }

    /// Attempt to repair a corrupt walletdb
    pub fn repair_db(wallet_db_path: PathBuf) -> Result<(), WalletError> {
        database::management::repair(&wallet_db_path, &Options::new())
            .map_err(|err| DbError::Repair(wallet_db_path, err))?;
        Ok(())
    }

    /// Helper to retrieve inner values
    fn inner(&self) -> MutexGuard<WalletInner> {
        self.inner.lock().unwrap()
    }
}

/// leveldb schema
/// n         -> newest public key
/// k{pubkey} -> encrypted private key
const NEWEST_PUBLIC_KEY_PREFIX: u8 = b'n';
const PRIVATE_KEY_PREFIX: u8 = b'k';
const PREFIX_LENGTH: usize = 1;

type PrivateKeyDbKey = [u8; PREFIX_LENGTH + PublicKey::BYTES];

fn encode_private_key_db_key(pub_key: PublicKey) -> PrivateKeyDbKey {
    let mut key: PrivateKeyDbKey = [0u8; mem::size_of::<PrivateKeyDbKey>()];
    key[0] = PRIVATE_KEY_PREFIX;
    key[1..].copy_from_slice(&pub_key[..]);
    key
}

fn decode_private_key_db_key(key: &[u8]) -> Result<PublicKey, WalletError> {
    let pub_key = PublicKey::from_slice(&key[PREFIX_LENGTH..][..PublicKey::BYTES])
        .map_err(DataError::Ed25519)?;
    Ok(pub_key)
}

// encryption utility functions

/// NaCl secretbox encrypt a private key with an Argon2id key derived from passphrase
fn encrypt_private_key(priv_key: &SecretKey, passphrase: &str) -> Result<Vec<u8>, WalletError> {
    let salt = generate_salt();
    let secret_key = stretch_passphrase(passphrase, &salt)?;
    let mut nonce = [0u8; XSalsa20Poly1305::NONCE_SIZE];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut nonce);
    let secretbox = XSalsa20Poly1305::new(&secret_key.into());
    let encrypted = secretbox.encrypt(&nonce.into(), &priv_key[..])?;

    // prepend the salt
    let mut encrypted_priv_key = Vec::with_capacity(encrypted.len() + ARGON_SALT_LENGTH);
    encrypted_priv_key.extend_from_slice(&salt);
    encrypted_priv_key.extend_from_slice(&nonce);
    encrypted_priv_key.extend_from_slice(&encrypted);

    Ok(encrypted_priv_key)
}

/// NaCl secretbox decrypt a private key with an Argon2id key derived from passphrase
fn decrypt_private_key(
    encrypted_priv_key: &[u8],
    passphrase: &str,
) -> Result<SecretKey, WalletError> {
    let salt = &encrypted_priv_key[..ARGON_SALT_LENGTH];
    let secret_key = stretch_passphrase(passphrase, salt)?;
    let mut nonce = [0u8; XSalsa20Poly1305::NONCE_SIZE];
    nonce.copy_from_slice(&encrypted_priv_key[ARGON_SALT_LENGTH..][..XSalsa20Poly1305::NONCE_SIZE]);
    let secretbox = XSalsa20Poly1305::new(&secret_key.into());
    let decrypted_priv_key = secretbox.decrypt(
        &nonce.into(),
        &encrypted_priv_key[ARGON_SALT_LENGTH + XSalsa20Poly1305::NONCE_SIZE..],
    )?;

    Ok(SecretKey::from_slice(&decrypted_priv_key[..]).map_err(DataError::Ed25519)?)
}

const ARGON_SALT_LENGTH: usize = 16;
const ARGON_KEY_LENGTH: usize = 32;
const ARGON_TIME: u32 = 1;
const ARGON_MEMORY: u32 = 64 * 1024;
const ARGON_THREADS: u32 = 4;

/// Generate a suitable salt for use with Argon2id
fn generate_salt() -> [u8; ARGON_SALT_LENGTH] {
    let mut salt = [0u8; ARGON_SALT_LENGTH];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut salt);
    salt
}

/// Stretch passphrase into a 32 byte key with Argon2id
fn stretch_passphrase(
    passphrase: &str,
    salt: &[u8],
) -> Result<[u8; ARGON_KEY_LENGTH], WalletError> {
    let mut output_key_material = [0u8; ARGON_KEY_LENGTH];
    let params = Params::new(
        ARGON_MEMORY,
        ARGON_TIME,
        ARGON_THREADS,
        Some(ARGON_KEY_LENGTH),
    )?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(
        passphrase.as_bytes(),
        salt,
        &mut output_key_material,
    )?;

    Ok(output_key_material)
}

#[derive(Error)]
pub enum WalletError {
    #[error("unable to encrypt/decrypt private keys")]
    EncryptKeyMismatch,
    #[error("unable to insert into filter")]
    FilterInsertFailed(#[source] CuckooError),
    #[error("filter result: {0}")]
    FilterResult(String),
    #[error("private key cannot be used to derive the same public key. possibly corrupt.")]
    PrivateKeyDerive,
    #[error("public key transaction result message: {0}")]
    PublicKeyTransactionResultMessage(String),
    #[error("transaction result message: {0}")]
    PushTransactionResultMessage(String),
    #[error("wallet result is missing")]
    WalletResultMissing,
    #[error("empty result returned")]
    WalletResultNotFound,

    #[error("connection handler")]
    ConnectionHandler(#[from] ConnectionHandlerError),
    #[error("wallet not found")]
    WalletNotFound(#[from] WalletNotFoundError),

    #[error("channel")]
    Channel(#[from] ChannelError),
    #[error("data")]
    Data(#[from] DataError),
    #[error("db")]
    Db(#[from] DbError),
    #[error("peer connection")]
    PeerConnnection(#[from] PeerConnectionError),
    #[error("transaction")]
    Transaction(#[from] TransactionError),

    #[error("argon2: {0}")]
    Argon2(argon2::Error),
    #[error("secretbox: {0}")]
    Secretbox(crypto_secretbox::Error),
}

impl_debug_error_chain!(WalletError, "wallet");

impl From<tokio::sync::mpsc::error::SendError<(Message, ResultChanSender)>> for WalletError {
    fn from(err: tokio::sync::mpsc::error::SendError<(Message, ResultChanSender)>) -> Self {
        Self::Channel(ChannelError::Send("out", err.to_string()))
    }
}

impl From<tokio::sync::oneshot::error::RecvError> for WalletError {
    fn from(err: tokio::sync::oneshot::error::RecvError) -> Self {
        Self::Channel(ChannelError::OneshotReceive("wallet result", err))
    }
}

impl From<argon2::Error> for WalletError {
    fn from(err: argon2::Error) -> Self {
        Self::Argon2(err)
    }
}

impl From<crypto_secretbox::Error> for WalletError {
    fn from(err: crypto_secretbox::Error) -> Self {
        Self::Secretbox(err)
    }
}

#[derive(Error, Debug)]
pub enum WalletNotFoundError {
    #[error("public key not found: {}", .0.as_base64())]
    PublicKey(PublicKey),
    #[error("private key not found for public key: {}", .0.as_base64())]
    PrivateKey(PublicKey),
}

type WsSink = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, WsMessage>;

struct WebSocket {
    websocket: Option<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    addr: SocketAddr,
}

struct ConnectionHandler {
    wallet: Weak<Wallet>,
    conn: Option<WebSocket>,
    /// outgoing messages and results for synchronous requests
    out_chan_rx: OutChanReceiver,
    shutdown_chan_rx: ShutdownChanReceiver,
}

impl ConnectionHandler {
    pub fn new(
        wallet: Weak<Wallet>,
        out_chan_rx: OutChanReceiver,
        shutdown_chan_rx: ShutdownChanReceiver,
    ) -> Self {
        Self {
            wallet,
            conn: None,
            out_chan_rx,
            shutdown_chan_rx,
        }
    }

    /// Connects to a peer for transaction history, balance information, and sending new transactions.
    /// The threat model assumes the peer the wallet is speaking to is not an adversary.
    pub async fn connect(
        &mut self,
        addr: SocketAddr,
        genesis_id: &BlockID,
        tls_verify: bool,
    ) -> Result<(), PeerConnectionError> {
        let url = format!("wss://{}/{}", addr, &genesis_id);
        let request = url.into_client_request()?;

        // by default clients skip verification as most peers are using ephemeral certificates and keys.
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
                return Err(PeerConnectionError::Timeout(addr, err));
            }
            Ok(Ok(v)) => v,
            Ok(Err(err)) => {
                return Err(PeerConnectionError::Connect(addr, err));
            }
        };

        self.conn = Some(WebSocket {
            websocket: Some(conn),
            addr,
        });

        Ok(())
    }

    pub fn spawn(self) -> JoinHandle<Result<(), SpawnedError>> {
        tokio::spawn(async { self.run().await.map_err(Into::into) })
    }

    /// Executes the Wallet's main loop.
    /// It manages reading and writing to the peer WebSocket.
    pub async fn run(mut self) -> Result<(), ConnectionHandlerError> {
        let conn = self.conn.as_mut().unwrap().websocket.take().unwrap();
        let (mut ws_sender, mut ws_receiver) = conn.split();
        let mut result_chan = None;

        // reader / writer loop
        loop {
            tokio::select! {
                Some((message, result_chan_tx)) = self.out_chan_rx.recv() => {
                    let json = match serde_json::to_string(&message).map_err(JsonError::Deserialize) {
                        Ok(v) => v,
                        Err(err) => {
                            result_chan_tx.send(WalletResult{
                                err: Some(err.into()),
                                message: None
                            })?;
                            break Ok(())
                        }
                    };

                    // send outgoing message to peer
                    if let Err(err) = self.send_with_timeout(&mut ws_sender, WsMessage::Text(json)).await {
                        result_chan_tx.send(WalletResult {
                            err: Some(err.into()),
                            message: None
                        })?;
                        break Ok(())
                    } else {
                        result_chan = Some(result_chan_tx);
                    }
                }

                // new message from peer
                msg = ws_receiver.next() => {
                    let message = match msg {
                        Some(Ok(v)) => v,
                        Some(Err(err)) => {
                            if let Some(result_chan) = result_chan.take() {
                                result_chan.send(WalletResult {
                                    err: Some(err.into()),
                                    message: None
                                })?;
                            } else {
                                break Err(PeerConnectionError::Websocket(err).into())
                            }
                            break Ok(())
                        }
                        None => {
                            break Err(PeerConnectionError::Dropped(self.addr()).into())
                        }
                    };

                    match message {
                        WsMessage::Text(ref json) => {
                            let message = match serde_json::from_str::<Message>(json).map_err(JsonError::Deserialize) {
                                Ok(v) => v,
                                Err(err) => {
                                    if let Some(result_chan) = result_chan.take() {
                                        result_chan.send(WalletResult{
                                            err: Some(err.into()),
                                            message: None
                                        })?;
                                    } else {
                                        break Err(err.into())
                                    }
                                    break Ok(())
                                }
                            };

                            match message {
                                Message::FilterBlock(fb) => {
                                    self.wallet.upgrade().unwrap().on_filter_block(fb);
                                }

                                Message::PushTransaction(pt) => {
                                    self.wallet.upgrade().unwrap().on_push_transaction(pt);
                                }

                                Message::Balance(_) |
                                Message::FilterResult(_) |
                                Message::PublicKeyTransactions(_) |
                                Message::PushTransactionResult(_) |
                                Message::TipHeader(_) |
                                Message::Transaction(_) |
                                Message::TransactionRelayPolicy(_) => {
                                    if let Some(result_chan) = result_chan.take() {
                                        result_chan.send(WalletResult {
                                            message: Some(message),
                                            err: None
                                        })?;
                                    }
                                },

                                // other message types
                                _ => {}
                            }
                        }

                        WsMessage::Close(_) => {
                            info!(
                                "Received close message from: {}",
                                self.addr()
                            );
                            break Ok(())
                        }

                        // other websocket messages
                        _ => {}
                    }
                }

                _ = &mut self.shutdown_chan_rx => {
                    ws_sender.close().await.map_err(PeerConnectionError::Websocket)?;
                    break Ok(())
                }
            }
        }
    }

    fn addr(&self) -> SocketAddr {
        self.conn.as_ref().expect("expected connection").addr
    }

    /// Send outgoing messages with a write timeout period
    async fn send_with_timeout(
        &self,
        ws_sender: &mut WsSink,
        message: WsMessage,
    ) -> Result<(), PeerConnectionError> {
        match timeout(WRITE_WAIT, ws_sender.send(message)).await {
            Err(err) => Err(PeerConnectionError::Timeout(self.addr(), err)),
            Ok(Err(err)) => Err(err.into()),
            _ => Ok(()),
        }
    }
}

impl Drop for ConnectionHandler {
    fn drop(&mut self) {
        if let Some(ref conn) = self.conn {
            info!("Closed connection with: {}", conn.addr);
        }
    }
}

#[derive(Error)]
pub enum ConnectionHandlerError {
    #[error("channel")]
    Channel(#[from] ChannelError),
    #[error("json")]
    Json(#[from] JsonError),
    #[error("peer connection")]
    PeerConnection(#[from] PeerConnectionError),

    #[error("websocket message")]
    WsMessage(#[from] tokio_tungstenite::tungstenite::Error),
}

impl_debug_error_chain!(ConnectionHandlerError, "connection handler");

impl From<WalletResult> for ConnectionHandlerError {
    fn from(_err: WalletResult) -> Self {
        Self::Channel(ChannelError::OneshotSend("wallet result"))
    }
}

#[cfg(test)]
mod test {
    use ed25519_compact::KeyPair;

    use super::*;

    #[test]
    fn test_private_key_encryption() {
        let priv_key = KeyPair::generate().sk;
        let passphrase = "the quick brown fox whatever whatever";
        let encrypted_priv_key = encrypt_private_key(&priv_key, passphrase).unwrap();
        let decrypted_priv_key = decrypt_private_key(&encrypted_priv_key, "nope");
        assert!(matches!(
            decrypted_priv_key,
            Err(WalletError::Secretbox(crypto_secretbox::aead::Error))
        ));

        let decrypted_priv_key = decrypt_private_key(&encrypted_priv_key, passphrase);
        assert!(decrypted_priv_key.is_ok(), "decryption failed");
        assert_eq!(
            decrypted_priv_key.unwrap(),
            priv_key,
            "private key mismatch after decryption"
        );
    }
}
