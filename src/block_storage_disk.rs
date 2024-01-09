use std::fs;
use std::io::{self, Read, Write};
use std::mem;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use leveldb::database::Database;
use leveldb::options::{Options, ReadOptions, WriteOptions};
use lz4::{Decoder, EncoderBuilder};
use serde::Deserialize;

use crate::block::{Block, BlockHeader, BlockID};
use crate::block_storage::{BlockStorage, BlockStorageError, BlockStorageNotFoundError};
use crate::error::{DbError, EncodingError, FileError, JsonError};
use crate::transaction::Transaction;

/// An on-disk BlockStorage implementation using the filesystem for blocks
/// and LevelDB for block headers.
pub struct BlockStorageDisk {
    db: Database,
    dir_path: PathBuf,
    read_only: bool,
    compress: bool,
}

impl BlockStorageDisk {
    /// Returns a new instance of on-disk block storage.
    pub fn new(
        dir_path: PathBuf,
        db_path: PathBuf,
        read_only: bool,
        compress: bool,
    ) -> Result<Arc<Self>, BlockStorageError> {
        // create the blocks path if it doesn't exist
        if !read_only {
            if !dir_path.exists() {
                fs::create_dir_all(&dir_path)
                    .map_err(|err| FileError::Create(dir_path.clone(), err))?;
            } else {
                let md = fs::metadata(&dir_path)
                    .map_err(|err| FileError::Create(dir_path.clone(), err))?;
                if md.is_file() {
                    return Err(FileError::Create(
                        dir_path.clone(),
                        io::Error::new(io::ErrorKind::AlreadyExists, "Path is a file"),
                    )
                    .into());
                }
            }
        }

        // open the database
        // TODO: open database as read only when option is available
        let mut options = Options::new();
        options.create_if_missing = true;
        let db = Database::open(&db_path, &options).map_err(|err| DbError::Open(db_path, err))?;
        Ok(Arc::new(Self {
            db,
            dir_path,
            read_only,
            compress,
        }))
    }
}

impl BlockStorage for BlockStorageDisk {
    /// Is called to store all of the block's information.
    fn store(&self, id: &BlockID, block: &Block, now: u64) -> Result<(), BlockStorageError> {
        if self.read_only {
            return Err(BlockStorageError::ReadOnly);
        }

        let ext = if self.compress { "lz4" } else { "json" };
        let block_path = Path::new(&self.dir_path)
            .join(id.as_hex())
            .with_extension(ext);

        // save the complete block to the filesystem

        let block_bytes = if self.compress {
            // compress with lz4
            let mut zout = Vec::new();
            let mut encoder = EncoderBuilder::new()
                .build(&mut zout)
                .map_err(|err| FileError::Compress(block_path.clone(), err))?;
            let block_bytes = serde_json::to_vec(&block).map_err(JsonError::Serialize)?;
            io::copy(&mut &block_bytes[..], &mut encoder)
                .map_err(|err| FileError::Compress(block_path.clone(), err))?;
            let (_output, _result) = encoder.finish();
            zout
        } else {
            serde_json::to_vec(&block).map_err(JsonError::Serialize)?
        };

        // write the block and sync
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&block_path)
            .map_err(|err| FileError::Write(block_path.clone(), err))?;

        let n = f
            .write(&block_bytes)
            .map_err(|err| FileError::Write(block_path.clone(), err))?;

        f.sync_all()
            .map_err(|err| FileError::Write(block_path.clone(), err))?;

        if n < block_bytes.len() {
            return Err(FileError::Write(
                block_path,
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Bytes written are smaller than block bytes",
                ),
            )
            .into());
        }

        // save the header to leveldb
        let encoded_block_header = encode_block_header(&block.header, now)?;
        self.db
            .put_u8(&WriteOptions { sync: true }, id, &encoded_block_header)
            .map_err(DbError::Write)?;
        Ok(())
    }

    /// Returns the referenced block.
    fn get_block(&self, id: &BlockID) -> Result<Option<Block>, BlockStorageError> {
        let Some(block_json) = self.get_block_bytes(id)? else {
            return Ok(None);
        };

        // unmarshal
        let block =
            serde_json::from_slice::<Block>(&block_json[..]).map_err(JsonError::Deserialize)?;
        Ok(Some(block))
    }

    /// Returns the referenced block as a byte slice.
    fn get_block_bytes(&self, id: &BlockID) -> Result<Option<Vec<u8>>, BlockStorageError> {
        let ext = if self.compress {
            // order to try finding the block by extension
            ["lz4", "json"]
        } else {
            ["json", "lz4"]
        };

        let mut compressed = self.compress;

        let mut block_path = Path::new(&self.dir_path)
            .join(id.as_hex())
            .with_extension(ext[0]);
        if !block_path.exists() {
            compressed = !compressed;
            block_path = Path::new(&self.dir_path)
                .join(id.as_hex())
                .with_extension(ext[1]);

            if !block_path.exists() {
                // not found
                return Ok(None);
            }
        }

        // read it off disk
        let mut block_bytes =
            fs::read(&block_path).map_err(|err| FileError::Read(block_path.clone(), err))?;

        if compressed {
            // uncompress
            let mut out = Vec::new();
            let mut decoder = Decoder::new(&block_bytes[..])
                .map_err(|err| FileError::Decompress(block_path.clone(), err))?;
            decoder
                .read_to_end(&mut out)
                .map_err(|err| FileError::Decompress(block_path.clone(), err))?;
            block_bytes = out;
        }

        Ok(Some(block_bytes))
    }

    /// Returns the referenced block's header and the timestamp of when it was stored.
    fn get_block_header(
        &self,
        id: &BlockID,
    ) -> Result<Option<(BlockHeader, u64)>, BlockStorageError> {
        // fetch it
        let Some(encoded_header) = self
            .db
            .get_u8(&ReadOptions::new(), id)
            .map_err(DbError::Read)?
        else {
            return Ok(None);
        };

        // decode it
        let (block_header, when) = decode_block_header(&encoded_header)?;

        Ok(Some((block_header, when)))
    }

    /// Returns a transaction within a block and the block's header.
    fn get_transaction(
        &self,
        id: &BlockID,
        index: u32,
    ) -> Result<(Option<Transaction>, BlockHeader), BlockStorageError> {
        let Some(block_bytes) = self.get_block_bytes(id)? else {
            return Err(BlockStorageNotFoundError::BlockBytes(*id).into());
        };

        // pick out and unmarshal the transaction at the index
        let block_json = serde_json::from_slice::<serde_json::Value>(&block_bytes)
            .map_err(JsonError::Deserialize)?;
        let tx = match block_json["transactions"].get(index as usize) {
            Some(tx_json) => {
                Some(Transaction::deserialize(tx_json).map_err(JsonError::Deserialize)?)
            }
            None => None,
        };

        // pick out and unmarshal the header
        let header = match block_json.get("header") {
            Some(hdr_json) => BlockHeader::deserialize(hdr_json).map_err(JsonError::Deserialize)?,
            None => {
                return Err(BlockStorageNotFoundError::BlockHeader(*id).into());
            }
        };

        Ok((tx, header))
    }
}

// leveldb schema:
// {bid} -> {timestamp}{bincode encoded header}
// note: original implementation is with gob instead of bincode

const U64_LENGTH: usize = mem::size_of::<u64>();

fn encode_block_header(header: &BlockHeader, when: u64) -> Result<Vec<u8>, BlockStorageError> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&when.to_be_bytes());
    let encoded = bincode::serialize(&header).map_err(EncodingError::BincodeEncode)?;
    buf.extend_from_slice(&encoded);
    Ok(buf)
}

fn decode_block_header(encoded_header: &[u8]) -> Result<(BlockHeader, u64), BlockStorageError> {
    let mut when_bytes = [0u8; U64_LENGTH];
    when_bytes.copy_from_slice(&encoded_header[0..U64_LENGTH]);
    let when = u64::from_be_bytes(when_bytes);
    let header = bincode::deserialize::<BlockHeader>(&encoded_header[U64_LENGTH..])
        .map_err(EncodingError::BincodeDecode)?;
    Ok((header, when))
}

#[cfg(test)]
mod test {
    use ed25519_compact::KeyPair;
    use faster_hex::hex_decode;

    use super::*;
    use crate::constants::{INITIAL_COINBASE_REWARD, INITIAL_TARGET};

    #[test]
    fn test_encode_block_header() {
        let pub_key = KeyPair::generate().pk;

        // create a coinbase
        let tx = Transaction::new(
            None,
            pub_key,
            INITIAL_COINBASE_REWARD,
            None,
            None,
            None,
            0,
            Some("hello".to_owned()),
        );

        // create a block
        let mut target = BlockID::new();
        hex_decode(INITIAL_TARGET.as_bytes(), &mut target).unwrap();
        let block = Block::new(BlockID::new(), 0, target, BlockID::new(), vec![tx]).unwrap();

        // encode the header
        let encoded_header = encode_block_header(&block.header, 12345).unwrap();

        // decode the header
        let (header, when) = decode_block_header(&encoded_header).unwrap();

        // compare
        assert_eq!(
            header, block.header,
            "Decoded header doesn't match original"
        );
        assert_eq!(when, 12345, "Decoded timestamp doesn't match original");
    }
}
