use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

use crate::block::BlockID;

/// If a block has been in the queue for more than 2 minutes it can be re-added with a new peer responsible for its download.
const MAX_QUEUE_WAIT: Duration = Duration::from_secs(2 * 60);

/// A queue of blocks to download.
pub struct BlockQueue {
    block_map: RwLock<HashMap<BlockID, BlockQueueEntry>>,
    block_queue: RwLock<VecDeque<BlockID>>,
}

struct BlockQueueEntry {
    who: SocketAddr,
    when: SystemTime,
}

impl BlockQueue {
    /// Returns a new instance of a BlockQueue
    pub fn new() -> Self {
        Self {
            block_map: RwLock::new(HashMap::new()),
            block_queue: RwLock::new(VecDeque::new()),
        }
    }

    /// Adds the block ID to the back of the queue and records the address of the peer who pushed it if it didn't exist in the queue.
    /// If it did exist and MAX_QUEUE_WAIT has elapsed, the block is left in its position but the peer responsible for download is updated.
    pub fn add(&self, id: &BlockID, who: &SocketAddr) -> bool {
        let mut block_map = self.block_map.write().unwrap();
        if let Some(block_queue_entry) = block_map.get_mut(id) {
            let elapsed = block_queue_entry
                .when
                .elapsed()
                .expect("couldn't get elapsed time from block queue entry");
            if elapsed < MAX_QUEUE_WAIT {
                // it's still pending download
                return false;
            }

            // it's expired. signal that it can be tried again and leave it in place
            block_queue_entry.when = SystemTime::now();
            // new peer owns its place in the queue
            block_queue_entry.who = *who;
            return true;
        }

        let block_queue_entry = BlockQueueEntry {
            who: *who,
            when: SystemTime::now(),
        };
        block_map.insert(*id, block_queue_entry);

        let mut block_queue = self.block_queue.write().unwrap();

        // add block id to the back of the queue
        block_queue.push_back(*id);

        true
    }

    /// Removes the block ID from the queue only if the requester is who is currently responsible for its download.
    pub fn remove(&self, id: &BlockID, who: &SocketAddr) -> bool {
        let mut block_map = self.block_map.write().unwrap();
        if let Some(block_queue_entry) = block_map.get(id) {
            if block_queue_entry.who == *who {
                let mut block_queue = self.block_queue.write().unwrap();
                if let Some(index) = block_queue.iter().position(|queue_id| queue_id == id) {
                    block_queue.remove(index);
                }
                block_map.remove(id);
                return true;
            }
        }

        false
    }

    /// Returns true if the block ID exists in the queue.
    pub fn exists(&self, id: &BlockID) -> bool {
        self.block_map.read().unwrap().contains_key(id)
    }

    /// Returns the ID of the block at the front of the queue.
    pub fn peek(&self) -> Option<BlockID> {
        let block_queue = self.block_queue.read().unwrap();
        if block_queue.is_empty() {
            None
        } else {
            block_queue.front().cloned()
        }
    }

    /// Returns the length of the queue.
    pub fn len(&self) -> usize {
        self.block_queue.read().unwrap().len()
    }

    /// Returns true if the queue has a length of 0.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for BlockQueue {
    fn default() -> Self {
        Self::new()
    }
}
