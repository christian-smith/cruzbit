use std::convert::AsRef;
use std::fmt::{self, Debug, Display};
use std::ops::{Deref, DerefMut};

use faster_hex::hex_encode;
use ibig::UBig;
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Sha3_256};
use thiserror::Error;

use crate::block_header_hasher::BlockHeaderHasher;
use crate::constants::{MAX_NUMBER, MAX_TRANSACTIONS_PER_BLOCK};
use crate::error::JsonError;
use crate::transaction::{Transaction, TransactionError, TransactionID};
use crate::utils::now_as_secs;

/// Represents a block in the block chain. It has a header and a list of transactions.
/// As blocks are connected their transactions affect the underlying ledger.
#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    #[serde(skip)]
    /// hash state used by miner. not marshaled
    hasher: Sha3_256,
}

impl Block {
    /// Creates and returns a new Block to be mined.
    pub fn new(
        previous: BlockID,
        height: u64,
        target: BlockID,
        chain_work: BlockID,
        transactions: Vec<Transaction>,
    ) -> Result<Self, BlockError> {
        // enforce the hard cap transaction limit
        if transactions.len() > MAX_TRANSACTIONS_PER_BLOCK as usize {
            return Err(BlockError::TransactionsSizeExceeded(
                transactions.len(),
                MAX_TRANSACTIONS_PER_BLOCK,
            ));
        }

        // compute the hash list root
        let mut hasher = Sha3_256::new();
        let hash_list_root = compute_hash_list_root(&mut hasher, &transactions)?;

        // create the header and block
        let block = Block {
            header: BlockHeader {
                previous,
                hash_list_root,
                // just use the system time
                time: now_as_secs(),
                target,
                chain_work: compute_chain_work(&target, &chain_work),
                nonce: rand::thread_rng().gen_range(0..=MAX_NUMBER),
                height,
                transaction_count: transactions.len() as u32,
            },
            transactions,
            // save this to use while mining
            hasher,
        };

        Ok(block)
    }

    /// Computes an ID for a given block.
    pub fn id(&self) -> Result<BlockID, BlockError> {
        self.header.id()
    }

    /// Verifies the block's proof-of-work satisfies the declared target.
    pub fn check_pow(&self, id: &BlockID) -> bool {
        id.as_big_int() <= self.header.target.as_big_int()
    }

    /// Adds a new transaction to the block. Called by miner when mining a new block.
    pub fn add_transaction(
        &mut self,
        id: TransactionID,
        tx: Transaction,
    ) -> Result<(), BlockError> {
        // hash the new transaction hash with the running state
        self.hasher.update(&id[..]);

        // update coinbase's fee
        self.transactions[0].amount += tx.fee.expect("transaction should have a fee");

        // update the hash list root to account for coinbase amount change
        self.header.hash_list_root =
            add_coinbase_to_hash_list_root(&mut self.hasher, &self.transactions[0])?;

        // append the new transaction to the list
        self.transactions.push(tx);
        self.header.transaction_count += 1;
        Ok(())
    }
}

pub fn compute_hash_list_root(
    hasher: &mut Sha3_256,
    transactions: &[Transaction],
) -> Result<TransactionID, BlockError> {
    // don't include coinbase in the first round
    for tx in transactions[1..].iter() {
        let id = tx.id()?;
        hasher.update(id);
    }

    // add the coinbase last
    add_coinbase_to_hash_list_root(hasher, &transactions[0])
}

/// Add the coinbase to the hash list root
fn add_coinbase_to_hash_list_root(
    hasher: &mut Sha3_256,
    coinbase: &Transaction,
) -> Result<TransactionID, BlockError> {
    // get the root of all of the non-coinbase transaction hashes
    let root_hash_without_coinbase = hasher.clone().finalize();

    // add the coinbase separately
    // this makes adding new transactions while mining more efficient since the coinbase
    // fee amount will change when adding new transactions to the block
    let id = coinbase.id()?;

    // hash the coinbase hash with the transaction list root hash
    let mut root_hash = Sha3_256::new();
    root_hash.update(id);
    root_hash.update(root_hash_without_coinbase);
    let hash = root_hash.finalize();

    // we end up with a sort of modified hash list root of the form:
    // HashListRoot = H(TXID[0] | H(TXID[1] | ... | TXID[N-1]))
    let hash_list_root = TransactionID::from(&hash[..]);
    Ok(hash_list_root)
}

/// Compute block work given its target
fn compute_block_work(target: &BlockID) -> UBig {
    let block_work_int = UBig::from(0u8);
    let mut target_int = target.as_big_int();

    if target_int <= block_work_int {
        return block_work_int;
    }

    // block work = 2**256 / (target+1)
    let max_int = UBig::from(2u8).pow(256);
    target_int += UBig::from(1u8);
    max_int / target_int
}

/// Compute cumulative chain work given a block's target and the previous chain work
pub fn compute_chain_work(target: &BlockID, chain_work: &BlockID) -> BlockID {
    let block_work_int = compute_block_work(target);
    let chain_work_int = chain_work.as_big_int();
    BlockID::from(chain_work_int + block_work_int)
}

/// Contains data used to determine block validity and its place in the block chain.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockHeader {
    pub previous: BlockID,
    pub hash_list_root: TransactionID,
    pub time: u64,
    pub target: BlockID,
    /// total cumulative chain work
    pub chain_work: BlockID,
    /// not used for crypto
    pub nonce: u64,
    pub height: u64,
    pub transaction_count: u32,
}

impl BlockHeader {
    /// Computes an ID for a given block header.
    pub fn id(&self) -> Result<BlockID, BlockError> {
        let json = serde_json::to_string(self).map_err(JsonError::Serialize)?;
        let hash = Sha3_256::digest(json.as_bytes());
        let block_id = BlockID::from(&hash[..]);
        Ok(block_id)
    }

    /// Computes an ID for a given block header when mining.
    pub fn id_fast(&mut self, miner_num: usize, hasher: &mut BlockHeaderHasher) {
        BlockHeaderHasher::update(miner_num, self, hasher);
    }

    /// Returns true if the header indicates it is a better chain than "their_header" up to both points.
    /// "this_when" is the timestamp of when we stored this block header.
    /// "their_when" is the timestamp of when we stored "their_header".
    pub fn compare(&self, their_header: &BlockHeader, this_when: u64, their_when: u64) -> bool {
        let this_work_int = self.chain_work.as_big_int();
        let their_work_int = their_header.chain_work.as_big_int();

        // most work wins
        if this_work_int > their_work_int {
            return true;
        }
        if this_work_int < their_work_int {
            return false;
        }

        // tie goes to the block we stored first
        if this_when < their_when {
            return true;
        }
        if this_when > their_when {
            return false;
        }

        // if we still need to break a tie go by the lesser id
        let this_id = self.id().unwrap_or_else(|err| panic!("{}", err));
        let their_id = their_header.id().unwrap_or_else(|err| panic!("{}", err));
        this_id.as_big_int() < their_id.as_big_int()
    }
}

impl PartialEq for BlockHeader {
    fn eq(&self, other: &Self) -> bool {
        self.previous == other.previous
    }
}

/// SHA3-256 hash
pub const BLOCK_ID_LENGTH: usize = 32;

/// A block's unique identifier.
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct BlockID([u8; BLOCK_ID_LENGTH]);

impl BlockID {
    pub fn new() -> BlockID {
        Default::default()
    }

    /// Returns BlockID as a hex string
    pub fn as_hex(&self) -> String {
        format!("{}", self)
    }

    /// Converts from BlockID to BigInt.
    pub fn as_big_int(&self) -> UBig {
        UBig::from_be_bytes(self)
    }
}

impl AsRef<[u8]> for BlockID {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for BlockID {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for BlockID {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Debug for BlockID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl Display for BlockID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; BLOCK_ID_LENGTH * 2];
        let _ = hex_encode(self, &mut buf);
        write!(f, "{}", String::from_utf8_lossy(&buf))
    }
}

impl From<UBig> for BlockID {
    /// Converts from BlockID to BigInt.
    fn from(value: UBig) -> Self {
        let mut block_id = BlockID::new();
        let int_bytes = value.to_be_bytes();

        if int_bytes.len() > 32 {
            panic!("Too much work")
        }

        block_id[32 - int_bytes.len()..].copy_from_slice(&int_bytes);
        block_id
    }
}

impl From<Vec<u8>> for BlockID {
    fn from(value: Vec<u8>) -> Self {
        BlockID(value.try_into().expect("incorrect bytes for block id"))
    }
}

impl From<&[u8]> for BlockID {
    fn from(value: &[u8]) -> Self {
        BlockID(value.try_into().expect("incorrect bytes for block id"))
    }
}

impl FromIterator<u8> for BlockID {
    fn from_iter<I: IntoIterator<Item = u8>>(iter: I) -> Self {
        iter.into_iter().collect::<Vec<u8>>().into()
    }
}

impl Serialize for BlockID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        faster_hex::nopfx_lowercase::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for BlockID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        faster_hex::nopfx_lowercase::deserialize(deserializer)
    }
}

#[derive(Error, Debug)]
pub enum BlockError {
    #[error("transaction list size exceeds limit per block, size: {0}, max {1}")]
    TransactionsSizeExceeded(usize, u32),

    #[error("json")]
    Json(#[from] JsonError),
    #[error("transaction")]
    Transaction(#[from] TransactionError),
}

#[cfg(test)]
pub mod test_utils {
    use ed25519_compact::{KeyPair, Seed};
    use faster_hex::hex_decode;

    use super::*;
    use crate::constants::{INITIAL_TARGET, MAX_MONEY, MIN_FEE_CRUZBITS};

    // create a deterministic test block
    pub fn make_test_block(num_tx: usize) -> Block {
        let mut txs = Vec::with_capacity(num_tx);
        let seed = 1.to_string().repeat(Seed::BYTES);
        let pub_key_coinbase =
            KeyPair::from_seed(Seed::new(seed.as_bytes().try_into().unwrap())).pk;
        // coinbase
        txs.push(Transaction::new(
            None,
            pub_key_coinbase,
            MIN_FEE_CRUZBITS,
            None,
            None,
            None,
            MAX_NUMBER,
            Some("こんにちは".to_owned()),
        ));

        // create txs
        for i in 1..num_tx {
            // create a sender
            let seed = (i % 10).to_string().repeat(Seed::BYTES);
            let keypair = KeyPair::from_seed(Seed::new(seed.as_bytes().try_into().unwrap()));
            let pub_key = keypair.pk;
            let priv_key = keypair.sk;

            // create a recipient
            let seed2 = ((i + 1) % 10).to_string().repeat(Seed::BYTES);
            let keypair2 = KeyPair::from_seed(Seed::new(seed2.as_bytes().try_into().unwrap()));
            let pub_key2 = keypair2.pk;

            let matures = MAX_NUMBER;
            let expires = MAX_NUMBER;
            let height = MAX_NUMBER;
            let amount = MAX_MONEY;
            let fee = MAX_MONEY;

            let mut tx = Transaction::new(
                Some(pub_key),
                pub_key2,
                amount,
                Some(fee),
                Some(matures),
                Some(expires),
                height,
                Some("こんにちは".to_owned()),
            );

            let memo = tx.memo.as_ref().unwrap();
            assert_eq!(
                memo.len(),
                15,
                "Expected memo length to be 15 but received {}",
                memo.len()
            );

            tx.nonce = 123456789 + i as u32;

            // sign the transaction
            tx.sign(priv_key).unwrap();
            txs.insert(i, tx);
        }

        // create the block
        let mut target = BlockID::new();
        hex_decode(INITIAL_TARGET.as_bytes(), &mut target).unwrap();
        Block::new(BlockID::new(), 0, target, BlockID::new(), txs).unwrap()
    }
}

#[cfg(test)]
mod test {
    use ed25519_compact::KeyPair;
    use faster_hex::hex_decode;

    use super::*;
    use crate::block::test_utils::make_test_block;

    #[test]
    fn test_id() {
        let block = make_test_block(1);
        assert!(block.id().is_ok(), "failed to hash block id");
    }

    #[test]
    fn test_id_fast() {
        let mut block = make_test_block(1);
        let mut hasher = BlockHeaderHasher::new();
        block.header.id_fast(0, &mut hasher);
        assert_eq!(hasher.result, block.id().unwrap().as_big_int());
    }

    #[test]
    fn test_compute_block_work() {
        let mut target = BlockID::new();
        hex_decode(
            "ffff000000000000000000000000000000000000000000000000000000000000".as_bytes(),
            &mut target,
        )
        .unwrap();
        let block_work = compute_block_work(&target);
        assert_eq!(block_work, UBig::from(1u8));

        hex_decode(
            "00000000ffff0000000000000000000000000000000000000000000000000000".as_bytes(),
            &mut target,
        )
        .unwrap();
        let block_work = compute_block_work(&target);
        assert_eq!(block_work, UBig::from(4295032833_u64))
    }

    #[test]
    fn test_add_transaction() {
        let mut block = make_test_block(0);
        let key_pair = KeyPair::generate();
        let tx1 = Transaction::new(None, key_pair.pk, 1, Some(1), None, None, 0, None);
        let tx2 = tx1.clone();
        block.add_transaction(tx1.id().unwrap(), tx1).unwrap();
        block.add_transaction(tx2.id().unwrap(), tx2).unwrap();
        let mut hasher = Sha3_256::new();
        let hlr = compute_hash_list_root(&mut hasher, &block.transactions).unwrap();
        assert_eq!(block.header.hash_list_root, hlr);
    }

    #[test]
    fn test_compute_hash_list_root() {
        let block = make_test_block(3);

        let mut hasher = Sha3_256::new();
        for tx in block.transactions[1..].iter() {
            hasher.update(tx.id().unwrap());
        }
        let without_coinbase_hash = hasher.finalize();

        let mut hasher = Sha3_256::new();
        hasher.update(block.transactions[0].id().unwrap());
        hasher.update(without_coinbase_hash);
        let hlr1 = TransactionID::from(&hasher.finalize()[..]);

        let mut hasher = Sha3_256::new();
        let hlr2 = compute_hash_list_root(&mut hasher, &block.transactions).unwrap();
        assert_eq!(hlr1, hlr2);
    }
}
