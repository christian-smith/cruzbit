use std::collections::HashMap;
use std::sync::OnceLock;

use thiserror::Error;

use crate::block::BlockID;

/// Can be disabled for testing.
pub const CHECKPOINTS_ENABLED: bool = true;

/// Used to determine if the client is synced.
pub const LATEST_CHECKPOINT_HEIGHT: u64 = 205780;

/// Checkpoints are known height and block ID pairs on the main chain.
static CHECKPOINTS: OnceLock<HashMap<u64, &str>> = OnceLock::new();

/// Returns an error if the passed height is a checkpoint and the
/// passed block ID does not match the given checkpoint block ID.
pub fn checkpoint_check(id: &BlockID, height: u64) -> Result<(), CheckpointError> {
    if !CHECKPOINTS_ENABLED {
        return Ok(());
    }

    match CHECKPOINTS
        .get_or_init(|| {
            HashMap::from([
                (
                    18144,
                    "000000000000b83e78ec29355d098256936389010d7450a288763ed4f191069e",
                ),
                (
                    36288,
                    "00000000000052bd43e85cf60f2ecd1c5016083e6a560b3ee57427c7f2dd64e8",
                ),
                (
                    54432,
                    "000000000001131d0597533737d7aadac0a5d4e132caa4c47c793c02e6d56063",
                ),
                (
                    72576,
                    "0000000000013873c9974f8468c7e03419e02f49aaf9761f4d6c19e233d0bb3d",
                ),
                (
                    90720,
                    "0000000000026254d69f914ff774ed8691d30003c8094d03e61aa8ed4c862c5f",
                ),
                (
                    108864,
                    "00000000001d7b35c09ac85a4e5b577dc62569f2782220723f1613ea268c66aa",
                ),
                (
                    127008,
                    "000000000013df027075d395d6f97e03cd8285db6c37b1575e66ede1c480d3de",
                ),
                (
                    145142,
                    "0000000006dcd69479a3f4f40a301d22e78b1f56de44e00c1fa3191967fd1425",
                ),
                (
                    205780,
                    "0000000089ad25388e0af7139383288203b46240da2d0651a89af0252e5fc4d3",
                ),
            ])
        })
        .get(&height)
    {
        Some(checkpoint_id) => {
            if id.as_hex() != *checkpoint_id {
                Err(CheckpointError::BlockMismatch(
                    *id,
                    height,
                    checkpoint_id.to_string(),
                ))
            } else {
                Ok(())
            }
        }
        None => Ok(()),
    }
}

#[derive(Error, Debug)]
pub enum CheckpointError {
    #[error("block {0} at height {1} does not match checkpoint ID {2}")]
    BlockMismatch(BlockID, u64, String),
}
