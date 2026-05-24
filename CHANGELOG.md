# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
