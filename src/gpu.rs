use std::ffi::{c_int, c_void};

use crate::block::BlockID;

type Int64T = i64;
type SizeT = usize;

extern "C" {
    #[cfg(feature = "cuda")]
    fn cuda_init() -> c_int;
    #[cfg(feature = "opencl")]
    fn ocl_init() -> c_int;
    fn miner_update(
        miner_num: c_int,
        first: *const c_void,
        first_len: SizeT,
        last: *const c_void,
        last_len: SizeT,
        target: *const c_void,
    ) -> c_int;
    fn miner_mine(miner_num: c_int, start_nonce: Int64T) -> Int64T;
}

/// Is called on startup.
pub fn gpu_miner_init() -> usize {
    unsafe {
        #[cfg(feature = "cuda")]
        return cuda_init() as usize;
        #[cfg(feature = "opencl")]
        return ocl_init() as usize;
    }
}

/// Is called when the underlying header changes.
pub fn gpu_miner_update(
    miner_num: usize,
    header_bytes: &Vec<u8>,
    header_bytes_len: usize,
    start_nonce_offset: usize,
    end_nonce_offset: usize,
    target: &BlockID,
) -> u64 {
    unsafe {
        miner_update(
            miner_num as c_int,
            header_bytes.as_ptr() as *const c_void,
            start_nonce_offset,
            header_bytes.as_ptr().add(end_nonce_offset) as *const c_void,
            header_bytes_len - end_nonce_offset,
            target.as_ptr() as *const c_void,
        ) as u64
    }
}

/// Is called on every solution attempt.
/// It will perform N hashing attempts where N is the maximum number of threads your device is capable of executing.
/// Returns a solving nonce; otherwise 0x7FFFFFFFFFFFFFFF.
pub fn gpu_miner_mine(miner_num: usize, start_nonce: u64) -> u64 {
    unsafe { miner_mine(miner_num as c_int, start_nonce as Int64T) as u64 }
}
