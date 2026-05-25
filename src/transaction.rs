use std::fmt::{self, Display};
use std::hash::Hash;
use std::ops::{Deref, DerefMut};

use base64ct::{Base64, Encoding};
use ed25519_compact::{PublicKey, SecretKey, Signature};
use faster_hex::hex_encode;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{DeserializeAs, SerializeAs, serde_as, skip_serializing_none};
use sha3::{Digest, Sha3_256};
use thiserror::Error;

use crate::constants::BLOCKS_UNTIL_NEW_SERIES;
use crate::error::{DataError, EncodingError, JsonError};
use crate::protocol::PublicKeySerde;
use crate::utils::{now_as_secs, rand_int31};

/// Represents a ledger transaction. It transfers value from one public key to another.
#[serde_as]
#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq)]
pub struct Transaction {
    pub time: u64,
    /// collision prevention. pseudorandom. not used for crypto
    pub nonce: u32,
    #[serde_as(as = "Option<PublicKeySerde>")]
    pub from: Option<PublicKey>,
    #[serde_as(as = "PublicKeySerde")]
    pub to: PublicKey,
    pub amount: u64,
    pub fee: Option<u64>,
    /// max 100 characters
    pub memo: Option<String>,
    /// block height. if set transaction can't be mined before
    pub matures: Option<u64>,
    /// block height. if set transaction can't be mined after
    pub expires: Option<u64>,
    /// +1 roughly once a week to allow for pruning history
    pub series: u64,
    #[serde_as(as = "Option<SignatureSerde>")]
    pub signature: Option<Signature>,
}

impl Transaction {
    /// Returns a new unsigned transaction.
    pub fn new(
        from: Option<PublicKey>,
        to: PublicKey,
        amount: u64,
        fee: Option<u64>,
        matures: Option<u64>,
        expires: Option<u64>,
        height: u64,
        memo: Option<String>,
    ) -> Self {
        Self {
            time: now_as_secs(),
            nonce: rand_int31(),
            from,
            to,
            amount,
            fee,
            memo,
            matures,
            expires,
            series: Self::compute_transaction_series(from.is_some(), height),
            signature: None,
        }
    }

    /// Computes an ID for a given transaction.
    pub fn id(&self) -> Result<TransactionID, TransactionError> {
        // never include the signature in the ID
        // this way we never have to think about signature malleability
        let mut hasher = Sha3_256::new();
        TransactionForId::from(self).write_go_json(HasherWrite(&mut hasher))?;
        Ok(TransactionID::from(&hasher.finalize()[..]))
    }

    /// Sign this transaction.
    pub fn sign(&mut self, priv_key: SecretKey) -> Result<(), TransactionError> {
        let id = self.id()?;
        self.signature = Some(priv_key.sign(id, None));
        Ok(())
    }

    /// Verify that the transaction is properly signed.
    pub fn verify(&self) -> Result<bool, TransactionError> {
        let id = self.id()?;
        let from = self.from.expect("transaction should have a sender");
        let signature = self.signature.expect("transaction should have a signature");
        match from.verify(id, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    /// Returns true if the transaction is a coinbase. A coinbase is the first transaction in every block
    /// used to reward the miner for mining the block.
    pub fn is_coinbase(&self) -> bool {
        self.from.is_none()
    }

    /// Returns true if the transaction is relevant to the given public key.
    pub fn contains(&self, pub_key: PublicKey) -> bool {
        if !self.is_coinbase() && pub_key == self.from.expect("transaction should have a sender") {
            return true;
        }

        pub_key == self.to
    }

    /// Returns true if the transaction can be mined at the given height.
    pub fn is_mature(&self, height: u64) -> bool {
        match self.matures {
            None | Some(0) => true,
            Some(matures) => matures >= height,
        }
    }

    /// Returns true if the transaction cannot be mined at the given height.
    pub fn is_expired(&self, height: u64) -> bool {
        match self.expires {
            None | Some(0) => false,
            Some(expires) => expires < height,
        }
    }

    /// Compute the series to use for a new transaction.
    fn compute_transaction_series(is_coinbase: bool, height: u64) -> u64 {
        if is_coinbase {
            // coinbases start using the new series right on time
            height / BLOCKS_UNTIL_NEW_SERIES + 1
        } else {
            // otherwise don't start using a new series until 100 blocks in to mitigate
            // potential reorg issues right around the switchover
            height.saturating_sub(100) / BLOCKS_UNTIL_NEW_SERIES + 1
        }
    }
}

/// Borrow-only view of Transaction for ID hashing. Reproduces Go's
/// json.Marshal(tx) byte-for-byte: the signature is never serialized,
/// Some(0) and Some("") are dropped to match Go's int64 / string
/// zero-value omitempty, field order matches the Go struct, and strings
/// go through GoHtmlFormatter to match Go's default HTML escaping.
#[serde_as]
#[derive(Serialize)]
struct TransactionForId<'a> {
    time: u64,
    nonce: u32,
    #[serde_as(as = "Option<PublicKeySerde>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<PublicKey>,
    #[serde_as(as = "PublicKeySerde")]
    to: PublicKey,
    amount: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    fee: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    memo: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    matures: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires: Option<u64>,
    series: u64,
}

impl<'a> From<&'a Transaction> for TransactionForId<'a> {
    fn from(tx: &'a Transaction) -> Self {
        Self {
            time: tx.time,
            nonce: tx.nonce,
            from: tx.from,
            to: tx.to,
            amount: tx.amount,
            fee: tx.fee.filter(|&v| v != 0),
            memo: tx.memo.as_deref().filter(|s| !s.is_empty()),
            matures: tx.matures.filter(|&v| v != 0),
            expires: tx.expires.filter(|&v| v != 0),
            series: tx.series,
        }
    }
}

impl TransactionForId<'_> {
    fn write_go_json<W: std::io::Write>(&self, writer: W) -> Result<(), TransactionError> {
        let mut ser = serde_json::Serializer::with_formatter(writer, GoHtmlFormatter);
        self.serialize(&mut ser).map_err(JsonError::Serialize)?;
        Ok(())
    }
}

/// io::Write adapter that feeds bytes straight into a Sha3_256. Lets the
/// serializer stream JSON into the hasher with no intermediate buffer.
struct HasherWrite<'a>(&'a mut Sha3_256);

impl std::io::Write for HasherWrite<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// serde_json formatter that adds Go's default JSON HTML escapes at the
/// string-fragment layer. This keeps serde_json responsible for normal JSON
/// escaping while matching Go's extra escaping for <, >, &, U+2028, and
/// U+2029.
struct GoHtmlFormatter;

impl serde_json::ser::Formatter for GoHtmlFormatter {
    fn write_string_fragment<W>(&mut self, writer: &mut W, fragment: &str) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        let mut start = 0;
        for (i, c) in fragment.char_indices() {
            let escape: &[u8] = match c {
                '&' => b"\\u0026",
                '<' => b"\\u003c",
                '>' => b"\\u003e",
                '\u{2028}' => b"\\u2028",
                '\u{2029}' => b"\\u2029",
                _ => continue,
            };
            writer.write_all(&fragment.as_bytes()[start..i])?;
            writer.write_all(escape)?;
            start = i + c.len_utf8();
        }
        writer.write_all(&fragment.as_bytes()[start..])
    }
}

#[derive(Error, Debug)]
pub enum TransactionError {
    #[error("json")]
    Json(#[from] JsonError),
}

/// SHA3-256 hash
pub const TRANSACTION_ID_LENGTH: usize = 32;

/// A transaction's unique identifier.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct TransactionID([u8; TRANSACTION_ID_LENGTH]);

impl TransactionID {
    pub fn new() -> Self {
        Default::default()
    }

    /// Returns TransactionID as a hex string
    pub fn as_hex(&self) -> String {
        format!("{self}")
    }
}

impl AsRef<[u8]> for TransactionID {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for TransactionID {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TransactionID {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Display for TransactionID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; TRANSACTION_ID_LENGTH * 2];
        let _ = hex_encode(self, &mut buf);
        write!(f, "{}", String::from_utf8_lossy(&buf))
    }
}

impl From<Vec<u8>> for TransactionID {
    fn from(value: Vec<u8>) -> Self {
        TransactionID(
            value
                .try_into()
                .expect("incorrect bytes for transaction id"),
        )
    }
}

impl From<&[u8]> for TransactionID {
    fn from(value: &[u8]) -> Self {
        TransactionID(
            value
                .try_into()
                .expect("incorrect bytes for transaction id"),
        )
    }
}

impl FromIterator<u8> for TransactionID {
    fn from_iter<I: IntoIterator<Item = u8>>(iter: I) -> Self {
        iter.into_iter().collect::<Vec<u8>>().into()
    }
}

impl Serialize for TransactionID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        faster_hex::nopfx_lowercase::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for TransactionID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        faster_hex::nopfx_lowercase::deserialize(deserializer)
    }
}

pub trait AsBase64 {
    fn as_base64(&self) -> String;
}

impl AsBase64 for PublicKey {
    fn as_base64(&self) -> String {
        // 4 * PublicKey::BYTES.div_ceil(3) = 44
        let mut buf = [0u8; 44];
        let encoded = Base64::encode(self.as_ref(), &mut buf)
            .map_err(EncodingError::Base64Encode)
            .unwrap();
        encoded.to_string()
    }
}

pub struct SignatureSerde;

impl SerializeAs<Signature> for SignatureSerde {
    fn serialize_as<S>(value: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self::serialize_signature(*value, serializer)
    }
}

impl<'de> DeserializeAs<'de, Signature> for SignatureSerde {
    fn deserialize_as<D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        self::deserialize_signature(deserializer)
    }
}

pub fn serialize_signature<S>(signature: Signature, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // 4 * Signature::BYTES.div_ceil(3) = 88
    let mut buf = [0u8; 88];
    serializer.serialize_str(
        Base64::encode(&signature[..], &mut buf)
            .map_err(EncodingError::Base64Encode)
            .map_err(serde::ser::Error::custom)?,
    )
}

pub fn deserialize_signature<'de, D>(deserializer: D) -> Result<Signature, D::Error>
where
    D: Deserializer<'de>,
{
    let encoded: String = Deserialize::deserialize(deserializer)?;
    let mut buf = [0u8; Signature::BYTES];
    let decoded = Base64::decode(&encoded, &mut buf)
        .map_err(EncodingError::Base64Decode)
        .map_err(serde::de::Error::custom)?;
    let signature = Signature::from_slice(decoded)
        .map_err(DataError::Ed25519)
        .map_err(serde::de::Error::custom)?;
    Ok(signature)
}

#[cfg(test)]
mod test {
    use ed25519_compact::KeyPair;

    use super::*;
    use crate::block::test_utils::make_test_block;
    use crate::constants::CRUZBITS_PER_CRUZ;

    #[test]
    fn test_id() {
        let block = make_test_block(1);
        let transaction_id = block.transactions[0].id();
        assert!(transaction_id.is_ok(), "failed to hash block id")
    }

    #[test]
    fn test_id_uses_go_omitempty_canonicalization() {
        let key_pair = KeyPair::generate();
        let pub_key = key_pair.pk;
        let mut coinbase_with_empty_fields = Transaction::new(
            None,
            pub_key,
            50 * CRUZBITS_PER_CRUZ,
            None,
            None,
            None,
            0,
            None,
        );
        coinbase_with_empty_fields.memo = Some(String::new());
        coinbase_with_empty_fields.matures = Some(0);
        coinbase_with_empty_fields.expires = Some(0);
        coinbase_with_empty_fields.fee = Some(0);

        let mut coinbase_without_empty_fields = coinbase_with_empty_fields.clone();
        coinbase_without_empty_fields.memo = None;
        coinbase_without_empty_fields.matures = None;
        coinbase_without_empty_fields.expires = None;
        coinbase_without_empty_fields.fee = None;

        assert_eq!(
            coinbase_with_empty_fields.id().unwrap(),
            coinbase_without_empty_fields.id().unwrap()
        );

        let sender = KeyPair::generate().pk;
        let mut tx_with_zero_fields = Transaction::new(
            Some(sender),
            pub_key,
            50 * CRUZBITS_PER_CRUZ,
            Some(0),
            Some(0),
            Some(0),
            0,
            Some(String::new()),
        );

        let mut tx_without_zero_fields = tx_with_zero_fields.clone();
        tx_without_zero_fields.fee = None;
        tx_without_zero_fields.matures = None;
        tx_without_zero_fields.expires = None;
        tx_without_zero_fields.memo = None;

        tx_with_zero_fields.signature = Some(key_pair.sk.sign([0; 32], None));
        tx_without_zero_fields.signature = Some(key_pair.sk.sign([1; 32], None));

        assert_eq!(
            tx_with_zero_fields.id().unwrap(),
            tx_without_zero_fields.id().unwrap()
        );
    }

    #[test]
    fn test_id_uses_go_json_html_escaping() {
        let key_pair = KeyPair::generate();
        let pub_key = key_pair.pk;
        let mut tx = Transaction::new(
            None,
            pub_key,
            50 * CRUZBITS_PER_CRUZ,
            None,
            None,
            None,
            0,
            Some("<>&\u{2028}\u{2029}".to_owned()),
        );
        tx.time = 1;
        tx.nonce = 2;
        tx.series = 3;

        let json = go_json_for_id(&tx).unwrap();
        assert_eq!(
            json,
            r#"{"time":1,"nonce":2,"to":""#.to_owned()
                + &pub_key.as_base64()
                + r#"","amount":5000000000,"memo":"\u003c\u003e\u0026\u2028\u2029","series":3}"#
        );
    }

    #[test]
    fn test_id_preserves_json_escapes_with_go_html_escaping() {
        let key_pair = KeyPair::generate();
        let pub_key = key_pair.pk;
        let mut tx = Transaction::new(
            None,
            pub_key,
            50 * CRUZBITS_PER_CRUZ,
            None,
            None,
            None,
            0,
            Some("quote:\" backslash:\\ newline:\n html:<&>\u{2028}\u{2029}".to_owned()),
        );
        tx.time = 1;
        tx.nonce = 2;
        tx.series = 3;

        let json = go_json_for_id(&tx).unwrap();
        assert_eq!(
            json,
            r#"{"time":1,"nonce":2,"to":""#.to_owned()
                + &pub_key.as_base64()
                + r#"","amount":5000000000,"memo":"quote:\" backslash:\\ newline:\n html:\u003c\u0026\u003e\u2028\u2029","series":3}"#
        );
    }

    #[test]
    fn test_transaction_maturity_expiration_match_go_zero_values() {
        let key_pair = KeyPair::generate();
        let pub_key = key_pair.pk;
        let mut tx = Transaction::new(
            None,
            pub_key,
            50 * CRUZBITS_PER_CRUZ,
            None,
            None,
            None,
            0,
            None,
        );

        assert!(tx.is_mature(100));
        assert!(!tx.is_expired(100));

        tx.matures = Some(0);
        tx.expires = Some(0);
        assert!(tx.is_mature(100));
        assert!(!tx.is_expired(100));

        tx.matures = Some(101);
        assert!(tx.is_mature(100));
        tx.matures = Some(99);
        assert!(!tx.is_mature(100));

        tx.expires = Some(99);
        assert!(tx.is_expired(100));
        tx.expires = Some(100);
        assert!(!tx.is_expired(100));
    }

    #[test]
    fn test_transaction() {
        // create a sender
        let key_pair = KeyPair::generate();
        let (pub_key, priv_key) = (key_pair.pk, key_pair.sk);
        // create a recipient
        let key_pair = KeyPair::generate();
        let (pub_key2, priv_key2) = (key_pair.pk, key_pair.sk);

        // create the unsigned transaction
        let mut tx = Transaction::new(
            Some(pub_key),
            pub_key2,
            50 * CRUZBITS_PER_CRUZ,
            None,
            None,
            None,
            0,
            Some("for lunch".to_owned()),
        );

        // sign the transaction
        tx.sign(priv_key).unwrap();

        // verify the transaction
        let ok = tx.verify().unwrap();
        assert!(ok, "Verification failed");
        // re-sign the transaction with the wrong private key
        tx.sign(priv_key2).unwrap();

        // verify the transaction (should fail)
        let ok = tx.verify().unwrap();
        assert!(!ok, "Expected verification failure");
    }

    #[test]
    fn test_transaction_test_vector1() {
        // create transaction for Test Vector 1
        let mut pub_key_bytes = [0u8; PublicKey::BYTES];
        Base64::decode(
            "80tvqyCax0UdXB+TPvAQwre7NxUHhISm/bsEOtbF+yI=",
            &mut pub_key_bytes,
        )
        .unwrap();
        let pub_key = PublicKey::from_slice(&pub_key_bytes).unwrap();

        let mut pub_key_bytes = [0u8; PublicKey::BYTES];
        Base64::decode(
            "YkJHRtoQDa1TIKhN7gKCx54bavXouJy4orHwcRntcZY=",
            &mut pub_key_bytes,
        )
        .unwrap();
        let pub_key2 = PublicKey::from_slice(&pub_key_bytes).unwrap();

        let mut tx = Transaction::new(
            Some(pub_key),
            pub_key2,
            50 * CRUZBITS_PER_CRUZ,
            Some(2 * CRUZBITS_PER_CRUZ),
            None,
            None,
            0,
            Some("for lunch".to_owned()),
        );
        tx.time = 1558565474;
        tx.nonce = 2019727887;

        // check JSON matches test vector
        let tx_json = serde_json::to_string(&tx).unwrap();
        assert_eq!(
            r#"{"time":1558565474,"nonce":2019727887,"from":"80tvqyCax0UdXB+TPvAQwre7NxUHhISm/bsEOtbF+yI=","to":"YkJHRtoQDa1TIKhN7gKCx54bavXouJy4orHwcRntcZY=","amount":5000000000,"fee":200000000,"memo":"for lunch","series":1}"#,
            tx_json,
            "JSON differs from test vector"
        );

        // check ID matches test vector
        let id = tx.id().unwrap();
        assert_eq!(
            id.as_hex().as_str(),
            "fc04870db147eb31823ce7c68ef366a7e94c2a719398322d746ddfd0f5c98776",
            "ID {id} differs from test vector"
        );

        // add signature from test vector
        let mut sig_bytes = [0u8; Signature::BYTES];
        Base64::decode("Fgb3q77evL5jZIXHMrpZ+wBOs2HZx07WYehi6EpHSlvnRv4wPvrP2sTTzAAmdvJZlkLrHXw1ensjXBiDosucCw==", &mut sig_bytes).unwrap();
        tx.signature = Some(Signature::from_slice(&sig_bytes).unwrap());

        // verify the transaction
        let ok = tx.verify().unwrap();
        assert!(ok, "Verification failed");

        // re-sign the transaction with private key from test vector
        let mut priv_key_bytes = [0u8; SecretKey::BYTES];
        Base64::decode("EBQtXb3/Ht6KFh8/+Lxk9aDv2Zrag5G8r+dhElbCe07zS2+rIJrHRR1cH5M+8BDCt7s3FQeEhKb9uwQ61sX7Ig==", &mut priv_key_bytes).unwrap();
        let priv_key = SecretKey::from_slice(&priv_key_bytes).unwrap();
        tx.sign(priv_key).unwrap();

        // verify the transaction
        let ok = tx.verify().unwrap();
        assert!(ok, "Verification failed");

        // re-sign the transaction with the wrong private key
        let priv_key2 = KeyPair::generate().sk;
        tx.sign(priv_key2).unwrap();

        // verify the transaction (should fail)
        let ok = tx.verify().unwrap();
        assert!(!ok, "Expected verification failure");
    }

    fn go_json_for_id(tx: &Transaction) -> Result<String, TransactionError> {
        let mut buf = Vec::with_capacity(256);
        TransactionForId::from(tx).write_go_json(&mut buf)?;
        Ok(String::from_utf8(buf).expect("serde_json output is valid utf-8"))
    }
}
