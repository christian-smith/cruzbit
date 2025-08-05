use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

use crate::block::BlockID;

/// If a block has been in the queue for more than 2 minutes it can be re-added with a new peer responsible for its download.
const MAX_QUEUE_WAIT: Duration = Duration::from_secs(2 * 60);

/// A queue of blocks to download.
pub struct BlockQueue {
    inner: RwLock<BlockQueueInner>,
}

struct BlockQueueInner {
    block_map: HashMap<BlockID, usize>,
    block_queue: VecDeque<BlockQueueEntry>,
}

#[derive(Clone)]
struct BlockQueueEntry {
    id: BlockID,
    who: SocketAddr,
    when: SystemTime,
}

impl BlockQueue {
    /// Returns a new instance of a BlockQueue
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(BlockQueueInner {
                block_map: HashMap::new(),
                block_queue: VecDeque::new(),
            }),
        }
    }

    /// Adds the block ID to the back of the queue and records the address of the peer who pushed it if it didn't exist in the queue.
    /// If it did exist and MAX_QUEUE_WAIT has elapsed, the block is left in its position but the peer responsible for download is updated.
    pub fn add(&self, id: &BlockID, who: &SocketAddr) -> bool {
        let mut inner = self.inner.write().unwrap();

        if let Some(&index) = inner.block_map.get(id) {
            let entry = &mut inner.block_queue[index];
            let elapsed = entry
                .when
                .elapsed()
                .expect("couldn't get elapsed time from block queue entry");
            if elapsed < MAX_QUEUE_WAIT {
                // it's still pending download
                return false;
            }

            // it's expired. signal that it can be tried again and leave it in place
            entry.when = SystemTime::now();
            // new peer owns its place in the queue
            entry.who = *who;
            return true;
        }

        // add to the back of the queue
        let entry = BlockQueueEntry {
            id: *id,
            who: *who,
            when: SystemTime::now(),
        };
        inner.block_queue.push_back(entry);
        let index = inner.block_queue.len() - 1;
        inner.block_map.insert(*id, index);

        true
    }

    /// Removes the block ID from the queue only if the requester is who is currently responsible for its download.
    pub fn remove(&self, id: &BlockID, who: &SocketAddr) -> bool {
        let mut inner = self.inner.write().unwrap();

        if let Some(&index) = inner.block_map.get(id) {
            if inner.block_queue[index].who == *who {
                inner.block_queue.remove(index);
                inner.block_map.remove(id);
                // update indices in map for all elements after the removed one
                for (_, idx) in inner.block_map.iter_mut() {
                    if *idx > index {
                        *idx -= 1;
                    }
                }

                return true;
            }
        }

        false
    }

    /// Returns true if the block ID exists in the queue.
    pub fn exists(&self, id: &BlockID) -> bool {
        self.inner.read().unwrap().block_map.contains_key(id)
    }

    /// Returns the ID of the block at the front of the queue.
    pub fn peek(&self) -> Option<BlockID> {
        let inner = self.inner.read().unwrap();
        inner.block_queue.front().map(|entry| entry.id)
    }

    /// Returns the length of the queue.
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().block_queue.len()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn make_test_id(n: u8) -> BlockID {
        BlockID::from(&[n; 32][..])
    }

    fn make_test_addr(port: u16) -> SocketAddr {
        SocketAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap()
    }

    #[test]
    fn test_add_remove() {
        let queue = BlockQueue::new();
        let id1 = make_test_id(1);
        let id2 = make_test_id(2);
        let addr1 = make_test_addr(8080);
        let addr2 = make_test_addr(8081);

        // add two blocks
        assert!(queue.add(&id1, &addr1));
        assert!(queue.add(&id2, &addr1));
        assert_eq!(queue.len(), 2);

        // try to add same block again (should fail)
        assert!(!queue.add(&id1, &addr2));
        assert_eq!(queue.len(), 2);

        // remove first block
        assert!(queue.remove(&id1, &addr1));
        assert_eq!(queue.len(), 1);

        // try to remove with wrong address (should fail)
        assert!(!queue.remove(&id2, &addr2));
        assert_eq!(queue.len(), 1);

        // remove second block
        assert!(queue.remove(&id2, &addr1));
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn test_peek_order() {
        let queue = BlockQueue::new();
        let id1 = make_test_id(1);
        let id2 = make_test_id(2);
        let id3 = make_test_id(3);
        let addr = make_test_addr(8080);

        // add three blocks
        queue.add(&id1, &addr);
        queue.add(&id2, &addr);
        queue.add(&id3, &addr);
        assert_eq!(queue.peek(), Some(id1));

        // remove middle block
        queue.remove(&id2, &addr);
        assert_eq!(queue.peek(), Some(id1));

        // remove first block
        queue.remove(&id1, &addr);
        assert_eq!(queue.peek(), Some(id3));
    }
}
