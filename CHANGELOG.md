# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-06-07

### Added
- Added startup, shutdown, DNS seeder, and DNS query progress logging.
- Added Linux Mesa Rusticl OpenCL setup notes for AMD GPU mining.

### Changed
- Transaction queue locking now uses one shared lock for queue state and balance cache state.
- DNS peer discovery now uses the current active seeder.

### Fixed
- Consensus now matches Go transaction-series selection for coinbase and non-coinbase transactions.
- Consensus now matches Go retarget timespan handling, full block-header equality, and invalid chain-work handling.
- Ledger transaction history pagination now matches Go reverse-range cursor behavior.
- Ledger historical balance lookups now match Go coinbase maturity behavior at low chain heights.
- Mining now matches Go's initial nonce range.
- Protocol response messages now preserve Go zero-value fields for balance, pushed transaction, and public-key transaction responses.
- Transaction queue mining fetches now treat a zero limit as the full queue.
- Read-only block storage no longer creates missing databases, and LZ4 finalization errors are now propagated.
- Peers now reject empty block messages and respond gracefully to negative public-key transaction limits.
- Peer storage now handles backward clock skew without duration underflow.
- Client shutdown now stops miners while the hash-rate monitor can still receive final updates.
- IRC peer discovery now parses ports by stripping non-digit characters.

## [1.3.0] - 2026-05-31

### Added
- Added a checkpoint at height 230000 and advanced the latest checkpoint height.

### Changed
- Migrated the crate to Rust 2024 and raised the minimum supported Rust version to 1.88.0.
- Updated dependencies, including `rand` 0.10 and `sha3` 0.12.
- Split peer WebSocket reading and writing into separate async loops.

### Fixed
- Peer handling now preserves outbound dial errors while recording failed connection attempts.
- Peer shutdown now drains protocol messages, cancels deferred tasks, and ignores expected closed-write errors before closing.
- Peer connections now negotiate the WebSocket subprotocol consistently for outbound and inbound handshakes.
- Empty cuckoo filters are accepted when they decode successfully.
- Submitted work and pushed transaction error paths now match the reference behavior.
- Inbound peer handling now avoids reservation leaks during shutdown and failed handshakes.
- Peer retry fallback now attempts disconnected peers before reporting that no peer addresses are available.
- Boolean command-line flags now parse bare flags and explicit values correctly.
- IPv4-mapped IPv6 peer addresses are now checked against reserved IPv4 ranges.

## [1.2.0] - 2026-05-24

### Fixed
- Consensus now matches Go `json.Marshal` canonicalization for transaction IDs, including `omitempty` fields and HTML escaping.
- Consensus now treats `Some(0)` and `None` identically for transaction maturity and expiration, matching Go zero-value semantics.
- Transaction validation now matches Go for pays-to-self checks, zero amount, zero series, and fee, maturity, and expiration bounds.
- Ledger disconnect now returns transactions in original block order and uses original block indices for public-key index keys.
- Ledger branch-type wire values now match Go iota values (`Main=0`, `Side=1`, `Orphan=2`, `Unknown=3`).
- Ledger pruning now removes both sender and recipient public-key indices.
- Unknown public-key balances now return `0` instead of a `NotFound` error, matching Go.
- Fast header hashing now matches Go in-place shift semantics across integer length changes.
- GPU mining now preserves the device miss sentinel in the fast header hashing path.

### Changed
- Header integer fields are now formatted with `itoa` to remove per-attempt heap allocations while mining.
- Mining now compares hash bytes directly against the target instead of allocating `UBig`.
- CUDA and OpenCL wrappers are now statically linked into release binaries, with explicit native runtime linkage.

### Added
- GitHub Actions release workflow for CPU, CUDA, and OpenCL binaries on macOS, Linux, and Windows.

### Removed
- Removed the unused `num-bigint` dependency.

## [1.1.1] - 2025-08-10

### Fixed
- wallet: explicit lifetime for MutexGuard
- wallet: add WebSocket subprotocol header

## [1.1.0] - 2025-08-06

### Added
- Added feature list to README
- Added new checkpoint at height 210000

### Changed
- Updated dependencies to latest versions
- Bumped minimum supported Rust version (MSRV) from 1.70.0 to 1.85.0

### Fixed
- peer_manager: External IP parsing error handling
- block_queue: Race condition with consolidated locks
- processor: Variable shadowing in reorganization loop
- ledger: Balance cache panic on undo for unknown recipient
- peer_storage: Correct peer deletion time comparison
- peer_storage: Random last_attempt initialization for new peers
- peer: Integer underflow prevention in send_find_common_ancestor
- peer: IBD status update in pong handler
- peer: Last new block time update after block acceptance
- transaction_queue: Batch processing order

## [1.0.1] - 2024-01-10

### Changed
- Installation instructions now use `cargo install` instead of `cargo run`

### Fixed
- wallet: Handles an error case if launched from a non-interactive tty
- peer_manager: DNS seeder peers weren't being connected to

## [1.0.0] - 2024-01-09

- Initial release
