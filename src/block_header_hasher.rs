use faster_hex::hex_encode;
use ibig::UBig;
use sha3::digest::generic_array::typenum::U32;
use sha3::digest::generic_array::GenericArray;
use sha3::{Digest, Sha3_256};

use crate::block::BlockHeader;
#[cfg(any(feature = "cuda", feature = "opencl"))]
use crate::gpu::{gpu_miner_mine, gpu_miner_update};
use crate::transaction::TransactionID;

#[derive(Clone, Default, Debug)]
pub struct BlockHeaderHasher {
    // these can change per attempt
    pub previous_hash_list_root: TransactionID,
    pub previous_time: u64,
    pub previous_nonce: u64,
    pub previous_transaction_count: u32,

    // used for tracking offsets of mutable fields in the buffer
    pub hash_list_root_offset: usize,
    pub time_offset: usize,
    pub nonce_offset: usize,
    pub transaction_count_offset: usize,

    // used for calculating a running offset
    pub time_len: usize,
    pub nonce_len: usize,
    pub tx_count_len: usize,

    // used for hashing
    pub initialized: bool,
    pub buf_len: usize,
    pub buffer: Vec<u8>,
    pub hasher: Sha3_256,
    pub result_buf: GenericArray<u8, U32>,
    pub result: UBig,
    pub hashes_per_attempt: u64,
}

/// Static fields
pub const HDR_PREVIOUS: &[u8] = br#"{"previous":""#;
pub const HDR_HASH_LIST_ROOT: &[u8] = br#"","hash_list_root":""#;
pub const HDR_TIME: &[u8] = br#"","time":"#;
pub const HDR_TARGET: &[u8] = br#","target":""#;
pub const HDR_CHAIN_WORK: &[u8] = br#"","chain_work":""#;
pub const HDR_NONCE: &[u8] = br#"","nonce":"#;
pub const HDR_HEIGHT: &[u8] = br#","height":"#;
pub const HDR_TRANSACTION_COUNT: &[u8] = br#","transaction_count":"#;
pub const HDR_END: &[u8] = br#"}"#;

// calculate the maximum buffer length needed
const BUF_LEN: usize = HDR_PREVIOUS.len()
    + 64 // previous
    + HDR_HASH_LIST_ROOT.len()
    + 64 // hash_list_root
    + HDR_TIME.len()
    + 19 // time
    + HDR_TARGET.len()
    + 64 // target
    + HDR_CHAIN_WORK.len()
    + 64 // chain work
    + HDR_NONCE.len()
    + 19 // nonce
    + HDR_HEIGHT.len()
    + 19 // height
    + HDR_TRANSACTION_COUNT.len()
    + 10 // transaction_count
    + HDR_END.len();

impl BlockHeaderHasher {
    /// Returns a newly initialized BlockHeaderHasher
    pub fn new() -> Self {
        // initialize the hasher
        Self {
            buffer: vec![0; BUF_LEN],
            hashes_per_attempt: 1,
            ..Default::default()
        }
    }

    /// Initialize the buffer to be hashed
    pub fn init_buffer(&mut self, header: &mut BlockHeader) {
        // lots of slice copying to array offsets.

        // previous
        self.buffer[..HDR_PREVIOUS.len()].copy_from_slice(HDR_PREVIOUS);
        let mut buf_len = HDR_PREVIOUS.len();
        let _ = hex_encode(
            &header.previous,
            &mut self.buffer[buf_len..][..header.previous.len() * 2],
        );
        buf_len += header.previous.len() * 2;

        // hash_list_root
        self.previous_hash_list_root = header.hash_list_root;
        self.buffer[buf_len..][..HDR_HASH_LIST_ROOT.len()].copy_from_slice(HDR_HASH_LIST_ROOT);
        buf_len += HDR_HASH_LIST_ROOT.len();
        self.hash_list_root_offset = buf_len;
        let _ = hex_encode(
            &header.hash_list_root,
            &mut self.buffer[buf_len..][..header.hash_list_root.len() * 2],
        );
        buf_len += header.hash_list_root.len() * 2;

        // time
        self.previous_time = header.time;
        self.buffer[buf_len..][..HDR_TIME.len()].copy_from_slice(HDR_TIME);
        buf_len += HDR_TIME.len();
        self.time_offset = buf_len;
        let time_bytes = header.time.to_string().into_bytes();
        self.buffer[buf_len..buf_len + time_bytes.len()].copy_from_slice(&time_bytes);
        self.time_len = time_bytes.len();
        buf_len += time_bytes.len();

        // target
        self.buffer[buf_len..][..HDR_TARGET.len()].copy_from_slice(HDR_TARGET);
        buf_len += HDR_TARGET.len();
        let _ = hex_encode(
            &header.target,
            &mut self.buffer[buf_len..][..header.target.len() * 2],
        );
        buf_len += header.target.len() * 2;

        // chain_work
        self.buffer[buf_len..][..HDR_CHAIN_WORK.len()].copy_from_slice(HDR_CHAIN_WORK);
        buf_len += HDR_CHAIN_WORK.len();

        let _ = hex_encode(
            &header.chain_work,
            &mut self.buffer[buf_len..buf_len + header.chain_work.len() * 2],
        );
        buf_len += header.chain_work.len() * 2;

        // nonce
        self.previous_nonce = header.nonce;
        self.buffer[buf_len..][..HDR_NONCE.len()].copy_from_slice(HDR_NONCE);
        buf_len += HDR_NONCE.len();
        self.nonce_offset = buf_len;
        let nonce_bytes = header.nonce.to_string().into_bytes();
        self.buffer[buf_len..][..nonce_bytes.len()].copy_from_slice(&nonce_bytes);
        self.nonce_len = nonce_bytes.len();
        buf_len += nonce_bytes.len();

        // height
        self.buffer[buf_len..][..HDR_HEIGHT.len()].copy_from_slice(HDR_HEIGHT);
        buf_len += HDR_HEIGHT.len();
        let height_bytes = header.height.to_string().into_bytes();
        self.buffer[buf_len..][..height_bytes.len()].copy_from_slice(&height_bytes);
        buf_len += height_bytes.len();

        // transaction_count
        self.previous_transaction_count = header.transaction_count;
        self.buffer[buf_len..][..HDR_TRANSACTION_COUNT.len()]
            .copy_from_slice(HDR_TRANSACTION_COUNT);
        buf_len += HDR_TRANSACTION_COUNT.len();
        self.transaction_count_offset = buf_len;
        let transaction_count_bytes = header.transaction_count.to_string().into_bytes();
        self.buffer[buf_len..][..transaction_count_bytes.len()]
            .copy_from_slice(&transaction_count_bytes);
        self.tx_count_len = transaction_count_bytes.len();
        buf_len += transaction_count_bytes.len();

        // end
        self.buffer[buf_len..][..HDR_END.len()].copy_from_slice(HDR_END);
        buf_len += HDR_END.len();
        self.buf_len = buf_len;

        self.initialized = true;
    }

    /// Is called every time the header is updated and the caller wants its new hash value/ID.
    pub fn update(_miner_num: usize, header: &mut BlockHeader, hasher: &mut BlockHeaderHasher) {
        let mut _buffer_changed = false;

        if !hasher.initialized {
            hasher.init_buffer(header);
            _buffer_changed = true;
        } else {
            // hash_list_root
            if hasher.previous_hash_list_root != header.hash_list_root {
                _buffer_changed = true;
                // write out the new value
                hasher.previous_hash_list_root = header.hash_list_root;
                let _ = hex_encode(
                    &header.hash_list_root,
                    &mut hasher.buffer[hasher.hash_list_root_offset..],
                );
            }

            let mut offset = 0;

            // time
            if hasher.previous_time != header.time {
                _buffer_changed = true;
                hasher.previous_time = header.time;

                // write out the new value
                let mut buf_len = hasher.time_offset;
                let time_bytes = header.time.to_string().into_bytes();
                hasher.buffer[buf_len..][..time_bytes.len()].copy_from_slice(&time_bytes);
                hasher.time_len = time_bytes.len();
                buf_len += time_bytes.len();

                // did time shrink or grow in length?
                offset = time_bytes.len() as isize - hasher.time_len as isize;

                if offset != 0 {
                    // shift everything below up or down

                    // target
                    hasher.buffer[buf_len..][..HDR_TARGET.len()].copy_from_slice(HDR_TARGET);
                    buf_len += HDR_TARGET.len();

                    let _ = hex_encode(
                        &header.target,
                        &mut hasher.buffer[buf_len..][..header.target.len() * 2],
                    );
                    buf_len += header.target.len() * 2;

                    // chain_work
                    hasher.buffer[buf_len..][..HDR_CHAIN_WORK.len()]
                        .copy_from_slice(HDR_CHAIN_WORK);
                    buf_len += HDR_CHAIN_WORK.len();
                    let _ = hex_encode(
                        &header.chain_work,
                        &mut hasher.buffer[buf_len..][..header.chain_work.len() * 2],
                    );
                    buf_len += header.chain_work.len() * 2; // hex bytes written

                    // start of nonce
                    hasher.buffer[buf_len..][..HDR_NONCE.len()].copy_from_slice(HDR_NONCE);
                }
            }

            // nonce
            let device_mining = cfg!(feature = "cuda") || cfg!(feature = "opencl");
            if offset != 0 || (!device_mining && hasher.previous_nonce != header.nonce) {
                _buffer_changed = true;
                hasher.previous_nonce = header.nonce;

                // write out the new value (or old value at a new location)
                if offset.is_positive() {
                    hasher.nonce_offset += offset as usize;
                } else {
                    hasher.nonce_offset -= offset.unsigned_abs()
                }

                let buf_len = hasher.nonce_offset;
                let nonce_bytes = header.nonce.to_string().into_bytes();
                hasher.buffer[buf_len..buf_len + nonce_bytes.len()].copy_from_slice(&nonce_bytes);

                let nonce_len = nonce_bytes.len();
                hasher.nonce_len = nonce_len;

                // did nonce shrink or grow in length?
                offset += nonce_len as isize - hasher.nonce_len as isize;

                if offset != 0 {
                    // shift everything below up or down

                    // height
                    hasher.buffer.extend_from_slice(HDR_HEIGHT);
                    hasher
                        .buffer
                        .extend_from_slice(&header.height.to_string().into_bytes());

                    // start of transaction_count
                    hasher.buffer.extend_from_slice(HDR_TRANSACTION_COUNT);
                }
            }

            // transaction_count
            if offset != 0 || hasher.previous_transaction_count != header.transaction_count {
                _buffer_changed = true;
                hasher.previous_transaction_count = header.transaction_count;

                // write out the new value (or old value at a new location)
                if offset.is_positive() {
                    hasher.transaction_count_offset += offset as usize;
                } else {
                    hasher.transaction_count_offset -= offset.unsigned_abs();
                }

                let buf_len = hasher.transaction_count_offset;
                let transaction_count_bytes = header.transaction_count.to_string().into_bytes();
                hasher.buffer[buf_len..][..transaction_count_bytes.len()]
                    .copy_from_slice(&transaction_count_bytes);

                // did count shrink or grow in length?
                offset += transaction_count_bytes.len() as isize - hasher.tx_count_len as isize;
                hasher.tx_count_len = transaction_count_bytes.len();

                if offset != 0 {
                    // shift the footer up or down
                    hasher.buffer[buf_len..][..HDR_END.len()].copy_from_slice(HDR_END);
                }
            }

            // it's possible (likely) we did a bunch of encoding with no net impact to the buffer length
            if offset.is_positive() {
                hasher.buf_len += offset as usize;
            } else {
                hasher.buf_len -= offset.unsigned_abs();
            }
        }

        #[cfg(any(feature = "cuda", feature = "opencl"))]
        {
            // devices don't return a hash just a solving nonce (if found)
            let nonce = hasher.update_device(_miner_num, header, _buffer_changed);
            if nonce == 0x7fffffff_ffffffff {
                // not found
                hasher.result = UBig::from_be_bytes(
                    // indirectly let miner.go know we failed
                    &[
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    ],
                );
            } else {
                log::info!(
                    "GPU miner {_miner_num} found a possible solution: {nonce}, double-checking it..."
                );
                // rebuild the buffer with the new nonce since we don't update it
                // per attempt when using CUDA/OpenCL.
                header.nonce = nonce;
                hasher.init_buffer(header);
            }
        }

        // hash it
        hasher.hasher.update(&hasher.buffer[..hasher.buf_len]);
        hasher.hasher.finalize_into_reset(&mut hasher.result_buf);
        hasher.result = UBig::from_be_bytes(&hasher.result_buf);
    }

    /// Handle mining with GPU devices
    #[cfg(any(feature = "cuda", feature = "opencl"))]
    pub fn update_device(
        &mut self,
        miner_num: usize,
        header: &BlockHeader,
        buffer_changed: bool,
    ) -> u64 {
        if buffer_changed {
            // update the device's copy of the buffer
            let last_offset = self.nonce_offset + self.nonce_len;
            self.hashes_per_attempt = gpu_miner_update(
                miner_num,
                &self.buffer,
                self.buf_len,
                self.nonce_offset,
                last_offset,
                &header.target,
            );
        }

        // try for a solution
        gpu_miner_mine(miner_num, header.nonce)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::block::test_utils::make_test_block;
    use crate::block::{Block, BlockID};

    #[test]
    fn test_block_header_hasher() {
        let mut block = make_test_block(10);
        assert!(compare_ids(&mut block), "ID mismatch 1");

        block.header.time = 1234;
        assert!(compare_ids(&mut block), "ID mismatch 2");

        block.header.nonce = 1234;
        assert!(compare_ids(&mut block), "ID mismatch 3");

        block.header.nonce = 1235;
        assert!(compare_ids(&mut block), "ID mismatch 4");

        block.header.nonce = 1236;
        block.header.time = 1234;
        assert!(compare_ids(&mut block), "ID mismatch 5");

        block.header.time = 123498;
        block.header.nonce = 12370910;
        let tx = &block.transactions[1];
        let tx_id = tx.id().unwrap();
        block.add_transaction(tx_id, tx.clone()).unwrap();
        assert!(compare_ids(&mut block), "ID mismatch 6");

        block.header.time = 987654321;
        assert!(compare_ids(&mut block), "ID mismatch 7");
    }

    fn compare_ids(block: &mut Block) -> bool {
        // compute header ID
        let id = block.id().unwrap();

        // use delta method
        let mut hasher = BlockHeaderHasher::new();
        block.header.id_fast(0, &mut hasher);
        let id2 = BlockID::from(hasher.result);
        id == id2
    }
}
