use base64ct::{Base64, Encoding};
use cuckoofilter::ExportedCuckooFilter;
use ed25519_compact::PublicKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{serde_as, skip_serializing_none, DefaultOnNull, DeserializeAs, SerializeAs};

use crate::block::{Block, BlockHeader, BlockID};
use crate::error::{DataError, EncodingError};
use crate::transaction::{AsBase64, Transaction, TransactionID};

/// The name of this version of the cruzbit peer protocol.
pub const PROTOCOL: &str = "cruzbit.1";

#[skip_serializing_none]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type", content = "body")]
/// A message frame for all messages in the cruzbit.1 protocol.
/// { "type": tag, "body": { content } }
pub enum Message {
    /// Send a public key's balance to a peer.
    Balance(BalanceMessage),

    /// Send a public key's balances to a peer.
    Balances(BalancesMessage),

    /// Send a peer a block's header.
    BlockHeader(Option<BlockHeaderMessage>),

    /// Send a peer a complete block.
    Block(Option<Box<BlockMessage>>),

    /// Request the addition of the given public keys to the current filter.
    /// The filter is created if it's not set.
    FilterAdd(FilterAddMessage),

    FilterBlockUndo(FilterBlockMessage),

    FilterBlock(FilterBlockMessage),

    /// Request that we load a filter which is used to filter transactions returned to the peer based on interest.
    FilterLoad(FilterLoadMessage),

    /// Indicates whether or not the filter request was successful.
    FilterResult(Option<FilterResultMessage>),

    /// Returns a pared down view of the unconfirmed transaction queue containing only transactions relevant to the peer given their filter.
    FilterTransactionQueue(FilterTransactionQueueMessage),

    /// Find a common ancestor with a peer.
    FindCommonAncestor(FindCommonAncestorMessage),

    /// Requests a public key's balance.
    GetBalance(GetBalanceMessage),

    /// Requests a set of public key balances.
    GetBalances(GetBalancesMessage),

    /// Request a block header by height.
    GetBlockHeaderByHeight(GetBlockHeaderByHeightMessage),

    /// Request a block header.
    GetBlockHeader(GetBlockHeaderMessage),

    /// Request a block for download by height.
    GetBlockByHeight(GetBlockByHeightMessage),

    /// Request a block for download.
    GetBlock(GetBlockMessage),

    GetFilterTransactionQueue,

    /// Request peer addresses.
    GetPeerAddresses,

    /// Requests transactions associated with a given public key over a given height range of the block chain.
    GetPublicKeyTransactions(GetPublicKeyTransactionsMessage),

    /// Used by a mining peer to request mining work.
    GetWork(GetWorkMessage),

    /// Request the tip header
    GetTipHeader,

    /// Request a confirmed transaction.
    GetTransaction(GetTransactionMessage),

    /// Sent in response to a PushTransactionMessage.
    GetTransactionResult(PushTransactionResultMessage),

    GetTransactionRelayPolicy,

    /// Communicates blocks available for download.
    InvBlock(InvBlockMessage),

    /// Communicate a list of potential peer addresses known by a peer.
    /// Sent in response to the empty GetPeerAddresses message type.
    PeerAddresses(PeerAddressesMessage),

    /// Requests transactions associated with a given public key over a given height range of the block chain.
    PublicKeyTransactions(PublicKeyTransactionsMessage),

    /// Push a newly processed unconfirmed transaction to peers.
    PushTransaction(PushTransactionMessage),

    /// Sent in response to a PushTransactionMessage.
    PushTransactionResult(PushTransactionResultMessage),

    SubmitWork(SubmitWorkMessage),

    /// Inform a mining peer of the result of its work.
    SubmitWorkResult(SubmitWorkResultMessage),

    /// Send a peer the header for the tip block in the block chain.
    /// It is sent in response to the empty GetTipHeader message type.
    TipHeader(Option<TipHeaderMessage>),

    /// Send a peer a confirmed transaction.
    Transaction(TransactionMessage),

    /// Communicate this node's current settings for min fee and min amount.
    /// Sent in response to the empty GetTransactionRelayPolicy message type.
    TransactionRelayPolicy(TransactionRelayPolicyMessage),

    /// Used by a client to send work to perform to a mining peer.
    /// The timestamp and nonce in the header can be manipulated by the mining peer.
    /// It is the mining peer's responsibility to ensure the timestamp is not set below
    /// the minimum timestamp and that the nonce does not exceed MAX_NUMBER (2^53-1).
    Work(WorkMessage),
}

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", std::mem::discriminant(self))
    }
}

/// Communicate blocks available for download.
/// MessageType: InvBlock
#[derive(Deserialize, Serialize)]
pub struct InvBlockMessage {
    pub block_ids: Vec<BlockID>,
}

/// Request a block for download.
/// MessageType: GetBlock
#[derive(Deserialize, Serialize)]
pub struct GetBlockMessage {
    pub block_id: BlockID,
}

/// Request a block for download by height.
/// MessageType: GetBlockByHeight
#[derive(Serialize, Deserialize)]
pub struct GetBlockByHeightMessage {
    pub height: u64,
}

/// Send a peer a complete block.
/// MessageType: Block
#[skip_serializing_none]
#[derive(Deserialize, Serialize)]
pub struct BlockMessage {
    pub block_id: BlockID,
    pub block: Option<Block>,
}

/// Request a block header.
/// Type: "get_block_header".
#[derive(Deserialize, Serialize)]
pub struct GetBlockHeaderMessage {
    pub block_id: BlockID,
}

/// Request a block header by height.
/// MessageType: GetBlockHeaderByHeight
#[derive(Deserialize, Serialize)]
pub struct GetBlockHeaderByHeightMessage {
    pub height: u64,
}

/// Send a peer a block's header.
/// MessageType: BlockHeader
#[skip_serializing_none]
#[derive(Deserialize, Serialize)]
pub struct BlockHeaderMessage {
    pub block_id: BlockID,
    #[serde(rename = "header")]
    pub block_header: Option<BlockHeader>,
}

/// Find a common ancestor with a peer.
/// MessageType::FindCommonAncestor
#[derive(Deserialize, Serialize)]
pub struct FindCommonAncestorMessage {
    pub block_ids: Vec<BlockID>,
}

/// Requests a public key's balance.
/// MessageType::GetBalance
#[serde_as]
#[derive(Deserialize, Serialize)]
pub struct GetBalanceMessage {
    #[serde_as(as = "PublicKeySerde")]
    pub public_key: PublicKey,
}

/// Send a public key's balance to a peer.
/// MessageType::Balance
#[serde_as]
#[skip_serializing_none]
#[derive(Deserialize, Serialize)]
pub struct BalanceMessage {
    pub block_id: Option<BlockID>,
    pub height: Option<u64>,
    #[serde_as(as = "Option<PublicKeySerde>")]
    pub public_key: Option<PublicKey>,
    pub balance: Option<u64>,
    pub error: Option<String>,
}

/// Requests a set of public key balances.
/// MessageType::GetBalances
#[serde_as]
#[derive(Deserialize, Serialize)]
pub struct GetBalancesMessage {
    #[serde_as(as = "Vec<PublicKeySerde>")]
    pub public_keys: Vec<PublicKey>,
}

/// Send a public key balances to a peer.
/// MessageType::Balances
#[skip_serializing_none]
#[derive(Deserialize, Serialize)]
pub struct BalancesMessage {
    pub block_id: Option<BlockID>,
    pub height: Option<u64>,
    pub balances: Option<Vec<PublicKeyBalance>>,
    pub error: Option<String>,
}

/// An entry in the BalancesMessage's Balances field.
#[serde_as]
#[derive(Deserialize, Serialize)]
pub struct PublicKeyBalance {
    #[serde_as(as = "PublicKeySerde")]
    pub public_key: PublicKey,
    pub balance: u64,
}

/// Request a confirmed transaction.
/// MessageType::GetTransaction
#[derive(Deserialize, Serialize)]
pub struct GetTransactionMessage {
    pub transaction_id: TransactionID,
}

/// Send a peer a confirmed transaction.
/// MessageType::Transaction
#[skip_serializing_none]
#[derive(Deserialize, Serialize)]
pub struct TransactionMessage {
    pub block_id: Option<BlockID>,
    pub height: Option<u64>,
    pub transaction_id: TransactionID,
    pub transaction: Option<Transaction>,
}

/// Used to send a peer the header for the tip block in the block chain.
/// MessageType::TipHeader It is sent in response to the empty GetTipHeader message type.
#[derive(Deserialize, Serialize)]
pub struct TipHeaderMessage {
    pub block_id: BlockID,
    #[serde(rename = "header")]
    pub block_header: BlockHeader,
    pub time_seen: u64,
}

/// PushTransactionMessage is used to push a newly processed unconfirmed transaction to peers.
/// MessageType::PushTransaction
#[derive(Deserialize, Serialize)]
pub struct PushTransactionMessage {
    pub transaction: Transaction,
}

/// Sent in response to a PushTransactionMessage.
/// Type: PushTransactionResult
#[skip_serializing_none]
#[derive(Deserialize, Serialize)]
pub struct PushTransactionResultMessage {
    pub transaction_id: Option<TransactionID>,
    pub error: Option<String>,
}

/// Used to request that we load a filter which is used to filter transactions returned to the peer based on interest.
/// MessageType: FilterLoad
#[serde_as]
#[derive(Deserialize, Serialize)]
pub struct FilterLoadMessage {
    pub r#type: String,
    #[serde_as(as = "ExportedCuckooFilterSerde")]
    pub filter: ExportedCuckooFilter,
}

/// Used to request the addition of the given public keys to the current filter. The filter is created if it's not set.
/// MessageType: FilterAdd
#[serde_as]
#[derive(Deserialize, Serialize)]
pub struct FilterAddMessage {
    #[serde_as(as = "Vec<PublicKeySerde>")]
    pub public_keys: Vec<PublicKey>,
}

/// Indicates whether or not the filter request was successful.
/// MessageType: FilterResult
#[derive(Deserialize, Serialize)]
pub struct FilterResultMessage {
    pub error: String,
}

/// Returns a pared down view of the unconfirmed transaction queue containing only transactions relevant to the peer given their filter.
/// MessageType::FilterTransactionQueue
#[skip_serializing_none]
#[derive(Deserialize, Serialize)]
pub struct FilterTransactionQueueMessage {
    pub transactions: Option<Vec<Transaction>>,
    pub error: Option<String>,
}

/// Requests transactions associated with a given public key over a given height range of the block chain.
/// MessageType::GetPublicKeyTransactions
#[serde_as]
#[derive(Deserialize, Serialize)]
pub struct GetPublicKeyTransactionsMessage {
    #[serde_as(as = "PublicKeySerde")]
    pub public_key: PublicKey,
    pub start_height: u64,
    pub start_index: u32,
    pub end_height: u64,
    pub limit: usize,
}

/// Used to return a list of block headers and the transactions relevant to the public key over a given height range of the block chain.
/// MessageType:PublicKeyTransactions
#[serde_as]
#[skip_serializing_none]
#[derive(Deserialize, Serialize)]
pub struct PublicKeyTransactionsMessage {
    #[serde_as(as = "Option<PublicKeySerde>")]
    pub public_key: Option<PublicKey>,
    pub start_height: Option<u64>,
    pub stop_height: Option<u64>,
    pub stop_index: Option<u32>,
    #[serde_as(as = "DefaultOnNull")]
    pub filter_blocks: Option<Vec<FilterBlockMessage>>,
    pub error: Option<String>,
}

/// Communicate a list of potential peer addresses known by a peer.
/// Type: "peer_addresses". Sent in response to the empty GetPeerAddresses message type.
#[derive(Deserialize, Serialize)]
pub struct PeerAddressesMessage {
    pub addresses: Vec<String>,
}

/// Communicate this node's current settings for min fee and min amount.
/// MessageType: TransactionRelayPolicy. Sent in response to the empty GetTransactionRelayPolicy message type.
#[derive(Deserialize, Serialize)]
pub struct TransactionRelayPolicyMessage {
    pub min_fee: u64,
    pub min_amount: u64,
}

/// Used by a mining peer to request mining work.
/// MessageType: GetWork
#[serde_as]
#[derive(Deserialize, Serialize)]
pub struct GetWorkMessage {
    #[serde_as(as = "Vec<PublicKeySerde>")]
    pub public_keys: Vec<PublicKey>,
    pub memo: String,
}

/// Used by a client to send work to perform to a mining peer.
/// The timestamp and nonce in the header can be manipulated by the mining peer.
/// It is the mining peer's responsibility to ensure the timestamp is not set below
/// the minimum timestamp and that the nonce does not exceed MAX_NUMBER (2^53-1).
/// MessageType::Work
#[skip_serializing_none]
#[derive(Deserialize, Serialize)]
pub struct WorkMessage {
    pub work_id: Option<u32>,
    pub header: Option<BlockHeader>,
    pub min_time: Option<u64>,
    pub error: Option<String>,
}

/// Used by a mining peer to submit a potential solution to the client.
/// MessageType: SubmitWork
#[derive(Deserialize, Serialize)]
pub struct SubmitWorkMessage {
    pub work_id: u32,
    pub header: BlockHeader,
}

/// Inform a mining peer of the result of its work.
/// MessageType: SubmitWorkResult
#[skip_serializing_none]
#[derive(Deserialize, Serialize)]
pub struct SubmitWorkResultMessage {
    pub work_id: u32,
    pub error: Option<String>,
}

/// Represents a pared down block containing only transactions relevant to the peer given their filter.
#[serde_as]
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct FilterBlockMessage {
    pub block_id: BlockID,
    pub header: BlockHeader,
    #[serde_as(as = "DefaultOnNull")]
    pub transactions: Vec<Transaction>,
}

/// Serializer / Deserialize for Public Key's
pub struct PublicKeySerde;

impl SerializeAs<PublicKey> for PublicKeySerde {
    fn serialize_as<S>(value: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self::serialize_public_key(*value, serializer)
    }
}

impl<'de> DeserializeAs<'de, PublicKey> for PublicKeySerde {
    fn deserialize_as<D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        self::deserialize_public_key(deserializer)
    }
}

pub fn serialize_public_key<S>(pub_key: PublicKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&pub_key.as_base64())
}

pub fn deserialize_public_key<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let encoded: String = Deserialize::deserialize(deserializer)?;
    let mut buf = [0u8; PublicKey::BYTES];
    let decoded = Base64::decode(&encoded, &mut buf)
        .map_err(EncodingError::Base64Decode)
        .map_err(serde::de::Error::custom)?;
    let pub_key = PublicKey::from_slice(decoded)
        .map_err(DataError::Ed25519)
        .map_err(serde::de::Error::custom)?;
    Ok(pub_key)
}

/// Serializer / Deserialize for the Cuckoo Filter
pub struct ExportedCuckooFilterSerde;

impl SerializeAs<ExportedCuckooFilter> for ExportedCuckooFilterSerde {
    fn serialize_as<S>(value: &ExportedCuckooFilter, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self::serialize_cuckoo_filter(value, serializer)
    }
}

impl<'de> DeserializeAs<'de, ExportedCuckooFilter> for ExportedCuckooFilterSerde {
    fn deserialize_as<D>(deserializer: D) -> Result<ExportedCuckooFilter, D::Error>
    where
        D: Deserializer<'de>,
    {
        self::deserialize_cuckoo_filter(deserializer)
    }
}

pub fn serialize_cuckoo_filter<S>(
    cuckoo_filter: &ExportedCuckooFilter,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&Base64::encode_string(&cuckoo_filter.values))
}

pub fn deserialize_cuckoo_filter<'de, D>(deserializer: D) -> Result<ExportedCuckooFilter, D::Error>
where
    D: Deserializer<'de>,
{
    let encoded: String = Deserialize::deserialize(deserializer)?;
    let values = Base64::decode_vec(encoded.as_str())
        .map_err(EncodingError::Base64Decode)
        .map_err(serde::de::Error::custom)?;
    let length = values.len();
    Ok(ExportedCuckooFilter { values, length })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::block::test_utils::make_test_block;

    #[test]
    fn test_serialize_find_common_ancestor() {
        let block = make_test_block(1);
        let block_id = block.id().unwrap();
        let block_ids = vec![block_id];
        let message = FindCommonAncestorMessage { block_ids };
        let serialized = serde_json::to_string(&message).unwrap();
        let json = format!(r#"{{"block_ids":["{block_id}"]}}"#);
        assert_eq!(serialized, json);
    }

    #[test]
    fn test_deserialize_inv_block_message() {
        let block = make_test_block(1);
        let block_id = block.id().unwrap();
        let block_ids = format!(r#"{{"block_ids":["{block_id}"]}}"#);
        let inv = serde_json::from_str::<InvBlockMessage>(&block_ids).unwrap();
        assert_eq!(inv.block_ids.len(), 1);
        assert_eq!(block_id, inv.block_ids[0]);
    }

    #[test]
    fn test_deserialize_block_message() {
        let block = make_test_block(1);
        let block_id = block.id().unwrap();
        let block_json = serde_json::to_string(&block).unwrap();
        let block_message_json = format!(r#"{{"block_id": "{block_id}", "block": {block_json} }}"#);
        let block_message = serde_json::from_str::<BlockMessage>(&block_message_json).unwrap();
        assert_eq!(block_id, block_message.block_id);
        assert_eq!(
            block.transactions[0].to,
            block_message.block.unwrap().transactions[0].to
        );
    }
}
