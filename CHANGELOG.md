# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
