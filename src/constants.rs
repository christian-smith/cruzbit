// The below values affect ledger consensus and come directly from bitcoin.
// we could have played with these but we're introducing significant enough changes
// already IMO, so let's keep the scope of this experiment as small as we can

pub const CRUZBITS_PER_CRUZ: u64 = 100000000;

pub const INITIAL_COINBASE_REWARD: u64 = 50 * CRUZBITS_PER_CRUZ;

/// blocks
pub const COINBASE_MATURITY: u64 = 100;

pub const INITIAL_TARGET: &str = "00000000ffff0000000000000000000000000000000000000000000000000000";

/// 2 hours
pub const MAX_FUTURE_SECONDS: u64 = 2 * 60 * 60;

pub const MAX_MONEY: u64 = 21000000 * CRUZBITS_PER_CRUZ;

/// 2 weeks in blocks
pub const RETARGET_INTERVAL: u64 = 2016;

/// 2 weeks in seconds
pub const RETARGET_TIME: u64 = 1209600;

/// every 10 minutes
pub const TARGET_SPACING: u64 = 600;

pub const NUM_BLOCKS_FOR_MEDIAN_TIMESTAMP: u64 = 11;

/// 4 years in blocks
pub const BLOCKS_UNTIL_REWARD_HALVING: u64 = 210000;

// the below value affects ledger consensus and comes from bitcoin cash

/// 1 day in blocks
pub const RETARGET_SMA_WINDOW: u64 = 144;

// the below values affect ledger consensus and are new as of our ledger

/// 16.666... tx/sec, ~4 MBish in JSON
pub const INITIAL_MAX_TRANSACTIONS_PER_BLOCK: u32 = 10000;

/// 2 years in blocks
pub const BLOCKS_UNTIL_TRANSACTIONS_PER_BLOCK_DOUBLING: u64 = 105000;

pub const MAX_TRANSACTIONS_PER_BLOCK: u32 = (1 << 31) - 1;

/// pre-calculated
pub const MAX_TRANSACTIONS_PER_BLOCK_EXCEEDED_AT_HEIGHT: u64 = 1852032;

/// 1 week in blocks
pub const BLOCKS_UNTIL_NEW_SERIES: u64 = 1008;

/// bytes (ascii/utf8 only)
pub const MAX_MEMO_LENGTH: usize = 100;

/// given our JSON protocol we should respect Javascript's Number.MAX_SAFE_INTEGER value
pub const MAX_NUMBER: u64 = (1 << 53) - 1;

/// height at which we switch from bitcoin's difficulty adjustment algorithm to bitcoin cash's algorithm
pub const BITCOIN_CASH_RETARGET_ALGORITHM_HEIGHT: u64 = 28861;

// the below values only affect peering behavior and do not affect ledger consensus

pub const DEFAULT_CRUZBIT_PORT: u16 = 8831;

pub const MAX_OUTBOUND_PEER_CONNECTIONS: usize = 8;

pub const MAX_INBOUND_PEER_CONNECTIONS: usize = 128;

pub const MAX_INBOUND_PEER_CONNECTIONS_FROM_SAME_HOST: usize = 4;

pub const MAX_TIP_AGE: u64 = 24 * 60 * 60;

/// doesn't apply to blocks
pub const MAX_PROTOCOL_MESSAGE_LENGTH: usize = 2 * 1024 * 1024;

// the below values are mining policy and also do not affect ledger consensus
// if you change this it needs to be less than the maximum at the current height

pub const MAX_TRANSACTIONS_TO_INCLUDE_PER_BLOCK: u32 = INITIAL_MAX_TRANSACTIONS_PER_BLOCK;

pub const MAX_TRANSACTION_QUEUE_LENGTH: u32 = MAX_TRANSACTIONS_TO_INCLUDE_PER_BLOCK * 10;

/// 0.01 cruz
pub const MIN_FEE_CRUZBITS: u64 = 1000000;

/// 0.01 cruz
pub const MIN_AMOUNT_CRUZBITS: u64 = 1000000;
