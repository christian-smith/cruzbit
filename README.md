<p align="center">
  <img src="https://github.com/christian-smith/cruzbit/assets/768500/01e9b8c1-2f93-436e-b5ea-50bad0b0180f" alt="cruzbit fun image" width="600" />
</p>

<div align="center">
  <table>
    <tr>
      <td><a href="https://cruzb.it"> <img alt="Image1" src="https://user-images.githubusercontent.com/51346587/64493622-370ace00-d237-11e9-98c5-547641054e0f.png" alt="cruzbit logo" width="150" /></a></td>
      <td>+</td>
      <td><a href="https://www.rust-lang.org/"> <img alt="Image3" src="https://rustacean.net/assets/rustacean-orig-noshadow.svg" alt="rust ferris" width="150" /></a></td>
    </tr>
  </table>
</div>
<br>
<p align="center">
  <a href="https://cruzb.it"><img src="https://img.shields.io/badge/https-cruzb.it-blue"></a>
  <a href="https://discord.gg/MRrEHYw"><img src="https://img.shields.io/badge/chat-discord-%237289da"></a>
  <a href="https://www.rust-lang.org"><img alt="language" src="https://img.shields.io/badge/language-Rust-orange.svg" ></a>
  <a href="https://github.com/christian-smith/cruzbit/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</p>

## What is cruzbit?
[cruzbit](https://cruzb.it) is a simple decentralized peer-to-peer ledger implementation. cruzbit is very similar to [Bitcoin](https://www.bitcoin.com/bitcoin.pdf) with the following notable differences:

* **Newer crypto** - The [Ed25519 signature system](https://ed25519.cr.yp.to/) is used for signing transactions. This system has a number of nice properties to protect users from security risks present with naive usage of ECDSA. The 256-bit version of the [SHA-3 hashing algorithm](https://en.wikipedia.org/wiki/SHA-3) is used for all hashing operations in the application, including the proof-of-work function but excluding hashing performed internally by the signature system. It's reported to be
[blazing fast](https://keccak.team/2017/is_sha3_slow.html) when implemented in hardware. [NaCl Secretbox](https://nacl.cr.yp.to/secretbox.html) is used to encrypt wallet private keys (not part of the protocol.)
* **Simplified transaction format** - No inputs and outputs. Just public key sender and receiver with a time, amount, explicit fee, memo field, pseudo-random nonce, series and signature. The series is incremented network-wide roughly once a week based on block height to allow for pruning transaction history. Also included are 2 optional fields for specifying maturity and expiration, both at a given block height.
* **No UTXO set** - This is a consequence of the second point. It considerably simplifies ledger construction and management as well as requires a wallet to know only about its public key balances and the current block height. It also allows the ledger to map more directly to the well-understood concept of a [double-entry bookkeeping system](https://en.wikipedia.org/wiki/Double-entry_bookkeeping_system). In cruzbit, the sum of all public key balances must equal the issuance at the current block height. This isn't the first ledger to get rid of the UTXO set model but I think we do it in a uniquely simple way.
* **No scripting** - This is another consequence of the second point. Signatures are simply signatures and not tiny scripts. It's a bit simpler and arguably safer. It does limit functionality, e.g. there is no native notion of a multi-signature transaction, however, depending on your needs, you can come _close_ to accomplishing that using [mechanisms external to cruzbit](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing).
* **No fixed block size limit** - Since transactions in cruzbit are more-or-less fixed size we cap blocks by transaction count instead, with the initial limit being 10,000 transactions. This per-block transaction limit increases with "piecewise-linear-between-doublings growth." This means the limit doubles roughly every 2 years by block height and increases linearly between doublings up until a hard limit of 2,147,483,647. This was directly inspired by [BIP 101](https://github.com/bitcoin/bips/blob/master/bip-0101.mediawiki). We use block height instead of time since another change in cruzbit is that all block headers contain the height (as well as the total cumulative chain work.)
* **[Reference implementation](https://github.com/cruzbit/cruzbit) is in [Go](https://golang.org/)** - Perhaps more accessible than C++. Hopefully it makes blockchain programming a bit easier to understand and attracts a wider variety of developer interest.
* **Web-friendly peer protocol** - Peer communication is via secure [WebSockets](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API). And the peer protocol and all primitives are structured in [JSON](https://www.json.org/). This should make working with the protocol easy for just about every modern development environment.

### Features
#### Core Design
- Account-based ledger with public key balances (no UTXO model)
- Ed25519 signatures for enhanced security and side-channel attack resistance
- SHA-3/Keccak-256 hashing for all operations including proof-of-work
- Simplified transaction format: sender, recipient, amount, explicit fee, memo, series, and nonce
- Roughly fixed-size transactions enabling predictable block capacity
- Optional transaction maturity and expiration fields (block height based)
- No scripting - signatures are just signatures, not scripts
- Transaction series increment every 1008 blocks (~1 week) enabling historical pruning
- Dynamic block limit following BIP 101 growth (doubles every ~2 years, starting at 10,000 transactions)
- 100-block maturity requirement for mining rewards
- 21 million coin limit with halving schedule every 210,000 blocks (~4 years)

#### Node Implementation
- Full blockchain validation with Bitcoin-like consensus rules
- LevelDB storage with optional LZ4 compression
- 10-minute target block time with 2016-block difficulty adjustment
- Bitcoin Cash's 144-block Simple Moving Average difficulty algorithm after height 28,861
- Time Warp Attack protection in difficulty adjustment
- Checkpoints for additional consensus validation
- Median Time Past (MTP) validation requiring blocks newer than median of last 11 blocks

#### Mining
- CPU mining with multi-threading support (--numminers flag)
- GPU mining via CUDA and OpenCL
- Multi-key mining with automatic rotation from keyfile
- Built-in hashrate monitoring and reporting
- External miner support via getwork/submit_work protocol

#### Network & Protocol
- WebSocket protocol with JSON-structured messages
- TLS-encrypted peer connections
- Peer discovery via DNS seeders and IRC channels
- UPnP automatic port forwarding for inbound connections
- Ban list management for malicious peers
- IPv4 and IPv6 support
- Peer storage and management with connection limits

#### Wallet
- Ed25519 key generation and management
- Encrypted storage using NaCl Secretbox with Argon2 key derivation
- Interactive console interface
- Multi-key support with batch transaction capabilities
- Transaction status tracking and confirmation monitoring
- Immature block rewards tracking (100-block maturity)

## Getting Started
### 1. Rust needs to be installed

- MacOS / Linux (from https://www.rust-lang.org/learn/get-started)

   * ```curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh```

- Windows:
  - https://www.petergirnus.com/blog/how-to-install-rust-on-windows
  - https://forge.rust-lang.org/infra/other-installation-methods.html

### 2. cmake needs to be installed
- macOS
  - ```brew install cmake```

- Debian Linux:
  - ```apt install cmake```

- Windows
  - ```winget install Kitware.CMake```

### 3. Install the client and wallet
Use ```cargo install cruzbit``` to install the 'client' and 'wallet' executables

- CPU mining:
```cargo install cruzbit```

- GPU CUDA mining:
```cargo install cruzbit --features cuda```

- GPU OpenCL mining:
```cargo install cruzbit --features opencl```

## Mining
Like Bitcoin, any blocks you mine will need to have an additional 100 blocks mined on top of them prior to the new cruzbits being applied to your balance. This is to mitigate a potentially poor user experience in the case of honest blockchain reorganizations.

#### Mining with multiple keys
```client --datadir datadir --numminers 1 --keyfile keys.txt```

Instead of mining with a single public key, you can use the wallet to generate many keys and dump the public keys to a text file which the client will accept as a `--keyfile` argument. The wallet commands to do this are `genkeys` and `dumpkeys`.

#### Mining with a single key
```client --datadir datadir --numminers 1 --pubkey [pub key from wallet]```

#### Not interested in mining but want to play with cruzbit?
No problem! You can run the client with `--numminers 0` so that it can function as your wallet peer.

```client --datadir datadir --numminers 0```

## Wallet
```wallet --walletdb walletdata```

## Database compatibility with golang cruzbit
- client db data is not compatible
- wallet db data is compatible

## License
cruzbit is released under the terms of the MIT license. See [LICENSE](https://github.com/christian-smith/cruzbit/blob/master/LICENSE) for more information or see https://opensource.org/licenses/MIT.

## Join us on Discord
**[Cruzbit Discord](https://discord.gg/MRrEHYw)** for general chat as well as updates, including development status.
