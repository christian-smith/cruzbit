use std::fmt::{self, Display};
use std::hash::Hash;
use std::ops::{Deref, DerefMut};

use base64ct::{Base64, Encoding};
use ed25519_compact::{PublicKey, SecretKey, Signature};
use faster_hex::hex_encode;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{serde_as, skip_serializing_none, DeserializeAs, SerializeAs};
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
        let json = if self.signature.is_some() {
            let mut tx = self.clone();
            tx.signature = None;
            serde_json::to_string(&tx).map_err(JsonError::Serialize)?
        } else {
            serde_json::to_string(self).map_err(JsonError::Serialize)?
        };

        let hash = TransactionID::from(&Sha3_256::digest(json.as_bytes())[..]);
        Ok(hash)
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
        if self.matures.is_none() {
            return true;
        }

        self.matures >= Some(height)
    }

    /// Returns true if the transaction cannot be mined at the given height.
    pub fn is_expired(&self, height: u64) -> bool {
        if self.expires.is_none() {
            return false;
        }

        self.expires < Some(height)
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
}
