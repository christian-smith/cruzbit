use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::{from_utf8, FromStr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use leveldb::database::batch::{Batch, WriteBatch};
use leveldb::database::{Database, DatabaseReader};
use leveldb::iterator::{Iterable, LevelDBIterator};
use leveldb::options::{Options, ReadOptions, WriteOptions};
use leveldb::snapshots::Snapshots;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::error::{DataError, DbError, EncodingError, ParsingError};
use crate::peer_storage::{PeerStorage, PeerStorageError, PeerStorageNotFoundError};
use crate::utils::now_as_duration;

/// New peers get a random last_attempt between 0 and 1 << 30 seconds (about 34 years from Unix epoch).
/// This ensures that they are tried before any previously attempted peers (which have real timestamps),
/// and that they are tried in random order relative to each other
const NEW_PEER_LAST_ATTEMPT_MAX: u64 = 1 << 30;

const U64_LENGTH: usize = std::mem::size_of::<u64>();

/// PeerStorageDisk is an on-disk implementation of the PeerStorage interface using LevelDB.
pub struct PeerStorageDisk {
    db: Database,
    connected_peers: Mutex<HashMap<SocketAddr, bool>>,
}

impl PeerStorageDisk {
    /// Returns a new PeerStorageDisk instance.
    pub fn new(db_path: PathBuf) -> Result<Arc<Self>, PeerStorageError> {
        let mut options = Options::new();
        options.create_if_missing = true;
        let db = Database::open(&db_path, &options).map_err(|err| DbError::Open(db_path, err))?;

        Ok(Arc::new(PeerStorageDisk {
            db,
            connected_peers: Mutex::new(HashMap::new()),
        }))
    }

    /// Helper to lookup peer info
    fn get_peer_info(
        addr: SocketAddr,
        db: &impl DatabaseReader,
    ) -> Result<Option<PeerInfo>, PeerStorageError> {
        let key = compute_peer_key(addr);
        let Some(encoded) = db
            .get_u8(&ReadOptions::new(), &key)
            .map_err(DbError::Read)?
        else {
            return Ok(None);
        };
        let info = decode_peer_info(encoded)?;

        Ok(Some(info))
    }

    /// Helper to delete a peer
    fn delete_peer(
        &self,
        addr: SocketAddr,
        last_attempt: Duration,
        last_success: Duration,
    ) -> Result<(), PeerStorageError> {
        let peer_key = compute_peer_key(addr);
        let attempt_key = compute_last_attempt_time_key(last_attempt, Some(addr));
        let success_key = compute_last_success_time_key(last_success, Some(addr));
        let batch = WriteBatch::new();
        batch.delete_u8(&peer_key);
        batch.delete_u8(&attempt_key);
        batch.delete_u8(&success_key);

        self.db
            .write(&WriteOptions::new(), &batch)
            .map_err(|err| PeerStorageError::Db(DbError::Write(err)))
    }

    /// Helper to return a copy of the connected set
    fn get_connected_peers(&self) -> HashMap<SocketAddr, bool> {
        // copy the set of connected peers
        let mut connected_peers = HashMap::new();
        for (addr, _) in self.connected_peers.lock().unwrap().iter() {
            connected_peers.insert(*addr, true);
        }

        connected_peers
    }
}

impl PeerStorage for PeerStorageDisk {
    /// Stores a peer address. Returns true if the peer was newly added to storage.
    fn store(&self, addr: SocketAddr) -> Result<bool, PeerStorageError> {
        // do we know about it already?
        if Self::get_peer_info(addr, &self.db)?.is_some() {
            // we've seen it
            return Ok(false);
        };

        // insert new peers at the head of the list to try next but put them in a random position
        // relative to other new peers
        let mut rng = rand::rng();
        let info = PeerInfo {
            first_seen: now_as_duration(),
            last_success: Duration::ZERO,
            last_attempt: Duration::from_secs(rng.random_range(0..NEW_PEER_LAST_ATTEMPT_MAX)),
        };

        let batch = WriteBatch::new();
        info.write_to_batch(addr, &batch)?;

        // compute last attempt by time db key
        let attempt_key = compute_last_attempt_time_key(info.last_attempt, Some(addr));
        batch.put_u8(&attempt_key, &[0x1]);

        // write the batch
        self.db
            .write(&WriteOptions::new(), &batch)
            .map_err(DbError::Write)?;

        Ok(true)
    }

    /// Returns some peers for us to attempt to connect to.
    fn get(&self, count: usize) -> Result<Vec<SocketAddr>, PeerStorageError> {
        let start_key = compute_last_attempt_time_key(Duration::ZERO, None);
        let end_key = compute_last_attempt_time_key(now_as_duration(), None);
        let mut addrs = Vec::new();

        let connected_peers = self.get_connected_peers();

        // try finding peers
        let snapshot = self.db.snapshot();
        let iter = snapshot
            .keys_iter(&ReadOptions::new())
            .from(&start_key)
            .to(&end_key);

        for key in iter {
            let (_when, addr) = decode_last_attempt_time_key(&key)?;
            if connected_peers.contains_key(&addr) {
                // already connected
                continue;
            }

            // is it time to retry this address?
            if let Some(info) = Self::get_peer_info(addr, &snapshot)? {
                if !info.should_retry() {
                    continue;
                }
            }

            // add it to the list
            addrs.push(addr);
            if addrs.len() == count {
                break;
            }
        }

        Ok(addrs)
    }

    /// Returns some peers to tell others about last active less than "when" ago.
    fn get_since(&self, count: usize, when: Duration) -> Result<Vec<SocketAddr>, PeerStorageError> {
        let start_key = compute_last_success_time_key(when, None);
        let end_key = compute_last_success_time_key(now_as_duration(), None);

        let mut addrs = Vec::new();

        // try finding peers
        let snapshot = self.db.snapshot();
        let iter = snapshot
            .keys_iter(&ReadOptions::new())
            .from(&start_key)
            .to(&end_key)
            .reverse();

        for key in iter {
            let (_when, addr) = decode_last_success_time_key(&key)?;
            // add it to the list
            addrs.push(addr);
            if addrs.len() == count {
                break;
            }
        }

        Ok(addrs)
    }

    /// Explicitly remove a peer address from storage.
    fn delete(&self, addr: SocketAddr) -> Result<(), PeerStorageError> {
        let Some(info) = Self::get_peer_info(addr, &self.db)? else {
            return Err(PeerStorageNotFoundError::PeerInfo(addr).into());
        };

        self.delete_peer(addr, info.last_attempt, info.last_success)
    }

    /// Called prior to attempting to connect to the peer.
    fn on_connect_attempt(&self, addr: SocketAddr) -> Result<(), PeerStorageError> {
        let Some(mut info) = Self::get_peer_info(addr, &self.db)? else {
            return Err(PeerStorageNotFoundError::PeerInfo(addr).into());
        };

        let batch = WriteBatch::new();

        // delete last attempt by time entry
        let attempt_key_old = compute_last_attempt_time_key(info.last_attempt, Some(addr));
        batch.delete_u8(&attempt_key_old);

        // update last attempt
        info.last_attempt = now_as_duration();
        info.write_to_batch(addr, &batch)?;

        // compute new last attempt by time db key
        let attempt_key_new = compute_last_attempt_time_key(info.last_attempt, Some(addr));
        batch.put(&attempt_key_new, &[0x1]);

        // write the batch
        self.db
            .write(&WriteOptions::new(), &batch)
            .map_err(|err| PeerStorageError::Db(DbError::WriteBatch(err)))
    }

    /// Called upon successful handshake with the peer.
    fn on_connect_success(&self, addr: SocketAddr) -> Result<(), PeerStorageError> {
        let Some(mut info) = Self::get_peer_info(addr, &self.db)? else {
            return Err(PeerStorageNotFoundError::PeerInfo(addr).into());
        };

        let batch = WriteBatch::new();

        // delete last success by time entry
        let success_key_old = compute_last_success_time_key(info.last_success, Some(addr));
        batch.delete_u8(&success_key_old);

        // update last success
        info.last_success = now_as_duration();
        info.write_to_batch(addr, &batch)?;

        // compute new success attempt by time db key
        let success_key_new = compute_last_success_time_key(info.last_success, Some(addr));
        batch.put_u8(&success_key_new, &[0x1]);

        // write the batch
        self.db
            .write(&WriteOptions::new(), &batch)
            .map_err(DbError::Write)?;

        // save the connected status in memory
        let mut connected_peers = self.connected_peers.lock().unwrap();
        connected_peers.insert(addr, true);
        Ok(())
    }

    /// Called upon connection failure.
    fn on_connect_failure(&self, addr: SocketAddr) -> Result<(), PeerStorageError> {
        let Some(info) = Self::get_peer_info(addr, &self.db)? else {
            return Err(PeerStorageNotFoundError::PeerInfo(addr).into());
        };

        if info.should_delete() {
            return self.delete_peer(addr, info.last_attempt, info.last_success);
        }
        Ok(())
    }

    /// Is called upon disconnection.
    fn on_disconnect(&self, addr: SocketAddr) -> Result<(), PeerStorageError> {
        let mut connected_peers = self.connected_peers.lock().unwrap();
        match connected_peers.remove(&addr) {
            Some(_) => Ok(()),
            None => Err(PeerStorageNotFoundError::Peer(addr).into()),
        }
    }
}

#[derive(Deserialize, Serialize)]
struct PeerInfo {
    first_seen: Duration,
    last_attempt: Duration,
    last_success: Duration,
}

impl PeerInfo {
    /// Should we retry this connection?
    pub fn should_retry(&self) -> bool {
        if self.last_attempt.as_secs() < NEW_PEER_LAST_ATTEMPT_MAX {
            // never been tried
            return true;
        }

        let last_seen = if self.last_success == Duration::ZERO {
            // never successfully connected, go by first seen
            self.first_seen
        } else {
            self.last_success
        };

        let now = now_as_duration();
        let hours_since_last_seen = (now - last_seen).as_secs() / (60 * 60);
        let minutes_since_last_attempt = (now - self.last_attempt).as_secs() / 60;
        let hours_since_last_attempt = minutes_since_last_attempt / 60;

        if hours_since_last_seen == 0 {
            return minutes_since_last_attempt > 10;
        }

        let retry_interval = (hours_since_last_seen as f64).sqrt().ceil() as u64;

        hours_since_last_attempt > retry_interval
    }

    /// Should we delete this peer?
    fn should_delete(&self) -> bool {
        if self.last_success == Duration::ZERO {
            // if we fail connecting on the first try delete it
            return true;
        }
        // has it been over a week since we connected to it?
        let week = Duration::from_secs(7 * 24 * 60 * 60);

        self.last_success > week
    }

    /// Helper to write the peer info to a batch
    fn write_to_batch(&self, addr: SocketAddr, batch: &WriteBatch) -> Result<(), PeerStorageError> {
        let key = compute_peer_key(addr);
        let encoded = encode_peer_info(self)?;
        batch.put_u8(&key, &encoded);
        Ok(())
    }
}

// leveldb schema

// p{addr}       -> serialized peerInfo
// a{time}{addr} -> 1 (time is of last attempt)
// s{time}{addr} -> 1 (time is of last success)

const PEER_PREFIX: u8 = b'p';
const PEER_LAST_ATTEMPT_TIME_PREFIX: u8 = b'a';
const PEER_LAST_SUCCESS_TIME_PREFIX: u8 = b's';

const PREFIX_LENGTH: usize = 1;

fn compute_peer_key(addr: SocketAddr) -> Vec<u8> {
    let mut key = Vec::new();
    key.push(PEER_PREFIX);
    key.extend_from_slice(addr.to_string().as_bytes());
    key
}

fn compute_last_attempt_time_key(when: Duration, addr: Option<SocketAddr>) -> Vec<u8> {
    let mut key = Vec::new();
    key.push(PEER_LAST_ATTEMPT_TIME_PREFIX);
    key.extend_from_slice(&(when.as_secs()).to_be_bytes());
    if let Some(addr) = addr {
        key.extend_from_slice(addr.to_string().as_bytes());
    }
    key
}

fn decode_last_attempt_time_key(key: &[u8]) -> Result<(u64, SocketAddr), PeerStorageError> {
    let when = u64::from_be_bytes(
        key[PREFIX_LENGTH..][..U64_LENGTH]
            .try_into()
            .map_err(DataError::U64)?,
    );
    let addr_str = from_utf8(&key[PREFIX_LENGTH + U64_LENGTH..]).map_err(DataError::String)?;
    let addr = SocketAddr::from_str(addr_str).map_err(ParsingError::IpAddress)?;
    Ok((when, addr))
}

fn compute_last_success_time_key(when: Duration, addr: Option<SocketAddr>) -> Vec<u8> {
    let mut key = Vec::new();
    key.push(PEER_LAST_SUCCESS_TIME_PREFIX);
    key.extend_from_slice(&(when.as_secs()).to_be_bytes());
    if let Some(addr) = addr {
        key.extend_from_slice(addr.to_string().as_bytes());
    }
    key
}

fn decode_last_success_time_key(key: &[u8]) -> Result<(Duration, SocketAddr), PeerStorageError> {
    let when = u64::from_be_bytes(
        key[PREFIX_LENGTH..][..U64_LENGTH]
            .try_into()
            .map_err(DataError::U64)?,
    );
    let who_str = from_utf8(&key[PREFIX_LENGTH + U64_LENGTH..]).map_err(DataError::String)?;
    let who = SocketAddr::from_str(who_str).map_err(ParsingError::IpAddress)?;
    Ok((Duration::from_secs(when), who))
}

fn encode_peer_info(info: &PeerInfo) -> Result<Vec<u8>, PeerStorageError> {
    let encode = bincode::serde::encode_to_vec(info, bincode::config::legacy())
        .map_err(|e| EncodingError::BincodeEncode(Box::new(e)))?;
    Ok(encode)
}

fn decode_peer_info(encoded: Vec<u8>) -> Result<PeerInfo, PeerStorageError> {
    let (decode, _) = bincode::serde::decode_from_slice::<PeerInfo, _>(
        &encoded,
        bincode::config::legacy(),
    )
    .map_err(|e| EncodingError::BincodeDecode(Box::new(e)))?;
    Ok(decode)
}

#[cfg(test)]
mod test {
    use faster_hex::hex_string;

    use super::*;
    use crate::peer::PEER_ADDR_SELF;

    #[test]
    fn test_compute_last_attempt_key() {
        let when = Duration::from_secs(123456789);
        let addr = PEER_ADDR_SELF;
        let key = compute_last_attempt_time_key(when, Some(addr));
        assert_eq!(key[0], PEER_LAST_ATTEMPT_TIME_PREFIX);
        assert_eq!(key[1..][..U64_LENGTH], when.as_secs().to_be_bytes());
        assert_eq!(key[1 + U64_LENGTH..], addr.to_string().as_bytes()[..]);
    }

    #[test]
    fn test_decode_last_attempt_time_key() {
        let when = Duration::from_secs(123456789);
        let addr = PEER_ADDR_SELF;
        let key = compute_last_attempt_time_key(when, Some(addr));
        let result = decode_last_attempt_time_key(&key).unwrap();
        assert_eq!(result.0, when.as_secs());
        assert_eq!(result.1, addr);
    }

    #[test]
    fn test_compute_last_attempt_time_key_start() {
        let key = compute_last_attempt_time_key(Duration::ZERO, None);
        assert_eq!(hex_string(&key), "610000000000000000");
    }

    #[test]
    fn test_compute_last_attempt_time_key_end() {
        let key = compute_last_attempt_time_key(Duration::MAX, None);
        assert_eq!(hex_string(&key), "61ffffffffffffffff");
    }

    #[test]
    fn test_compute_last_success_time_key() {
        let when = Duration::from_secs(123456789);
        let addr = PEER_ADDR_SELF;
        let key = compute_last_success_time_key(when, Some(addr));
        assert_eq!(key[0], PEER_LAST_SUCCESS_TIME_PREFIX);
        assert_eq!(key[1..][..U64_LENGTH], when.as_secs().to_be_bytes());
        assert_eq!(key[1 + U64_LENGTH..], addr.to_string().as_bytes()[..]);
    }

    #[test]
    fn test_decode_last_success_time_key() {
        let when = Duration::from_secs(123456789);
        let key = compute_last_success_time_key(when, Some(PEER_ADDR_SELF));
        let result = decode_last_success_time_key(&key).unwrap();
        assert_eq!(result.0, when);
        assert_eq!(result.1, PEER_ADDR_SELF);
    }

    #[test]
    fn test_compute_peer_key() {
        let addr = PEER_ADDR_SELF;
        let key = compute_peer_key(addr);
        assert_eq!(key[0], PEER_PREFIX);
        assert_eq!(key[1..], addr.to_string().as_bytes()[..]);
    }
}
