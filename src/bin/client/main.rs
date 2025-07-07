use std::collections::HashMap;
use std::env::args;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{exit, ExitCode};
use std::sync::{Arc, OnceLock};

use base64ct::{Base64, Encoding};
use cruzbit::block::{Block, BlockID};
use cruzbit::block_storage::BlockStorageError;
use cruzbit::block_storage_disk::BlockStorageDisk;
use cruzbit::constants::{DEFAULT_CRUZBIT_PORT, MAX_INBOUND_PEER_CONNECTIONS};
use cruzbit::dns::DnsSeeder;
use cruzbit::error::{
    impl_debug_error_chain, DataError, EncodingError, ErrChain, FileError, JsonError, ParsingError,
};
use cruzbit::genesis::GENESIS_BLOCK_JSON;
use cruzbit::ledger::LedgerError;
use cruzbit::ledger_disk::LedgerDisk;
use cruzbit::miner::{HashrateMonitor, Miner};
use cruzbit::peer::PEER_ADDR_SELF;
use cruzbit::peer_manager::{
    determine_external_ip, have_local_ip_match, PeerManager, PeerManagerError,
};
use cruzbit::peer_storage::PeerStorageError;
use cruzbit::peer_storage_disk::PeerStorageDisk;
use cruzbit::processor::{ProcessBlockError, Processor};
use cruzbit::shutdown::{shutdown_channel, Shutdown};
use cruzbit::transaction_queue_memory::TransactionQueueMemory;
use cruzbit::utils::resolve_host;
use ed25519_compact::PublicKey;
use env_logger::{Builder, Env};
use getopts::Options;
use log::{error, info, Level};
use thiserror::Error;
use tokio::signal;
use tokio::sync::mpsc::channel;

static BAN_MAP: OnceLock<HashMap<String, bool>> = OnceLock::new();
static GENESIS_ID: OnceLock<BlockID> = OnceLock::new();
static MEMO: OnceLock<Option<String>> = OnceLock::new();
static PUB_KEYS: OnceLock<Vec<PublicKey>> = OnceLock::new();

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) => match err {
            ClientError::Args(err) => {
                println!("{}", err);
                ExitCode::SUCCESS
            }
            _ => {
                error!("{:?}", err);
                ExitCode::FAILURE
            }
        },
    }
}

async fn run() -> Result<(), ClientError> {
    init_logger();
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let args = args().collect::<Vec<_>>();
    let program = &args[0];

    let mut opts = Options::new();
    opts.long_only(true);
    opts.optopt(
        "",
        "banlist",
        "Path to a file containing a list of banned host addresses",
        "string",
    );
    opts.optflag("", "compress", "Compress blocks on disk with lz4");
    opts.optopt(
        "",
        "datadir",
        "Path to a directory to save block chain data",
        "string",
    );
    opts.optflag(
        "",
        "dnsseed",
        "Run a DNS server to allow others to find peers",
    );
    opts.optflag(
        "",
        "inlimit",
        "Limit for the number of inbound peer connections.",
    );
    opts.optopt(
        "",
        "keyfile",
        "Path to a file containing public keys to use when mining
",
        "string",
    );
    opts.optopt(
        "",
        "memo",
        "A memo to include in newly mined blocks",
        "string",
    );
    opts.optflag("", "noaccept", "Disable inbound peer connections");
    opts.optflag("", "noirc", "Disable use of IRC for peer discovery");
    opts.optopt("", "numminers", "Number of miners to run", "int");
    opts.optopt("", "peer", "Address of a peer to connect to", "string");
    opts.optopt(
        "",
        "port",
        "Port to listen for incoming peer connections",
        "int",
    );
    opts.optflag(
        "",
        "prune",
        "Prune transaction and public key transaction indices",
    );
    opts.optopt(
        "",
        "pubkey",
        "A public key which receives newly mined block rewards",
        "string",
    );
    opts.optopt(
        "",
        "tlscert",
        "Path to a file containing a PEM-encoded X.509 certificate to use with TLS",
        "string",
    );
    opts.optopt(
        "",
        "tlskey",
        "Path to a file containing a PEM-encoded private key to use with TLS",
        "string",
    );
    opts.optflag(
        "",
        "upnp",
        "Attempt to forward the cruzbit port on your router with UPnP",
    );

    let Ok(matches) = opts.parse(&args[1..]) else {
        print_usage(program, opts);
        return Ok(());
    };
    let ban_list = matches.opt_str("banlist").map(PathBuf::from);
    let compress = matches.opt_present("compress");
    let data_dir = match matches.opt_str("datadir") {
        Some(data_dir) => PathBuf::from(data_dir),
        None => {
            return Err("-datadir argument required".into());
        }
    };
    let dns_seed = matches.opt_present("dnsseed");
    let inbound_limit = matches
        .opt_get_default("inlimit", MAX_INBOUND_PEER_CONNECTIONS)
        .map_err(|_| "inlimit should be a number")?;
    let key_file = matches.opt_str("keyfile").map(PathBuf::from);
    let no_accept = !matches.opt_present("noaccept");
    let no_irc = matches.opt_present("noirc");
    let num_miners = matches
        .opt_get_default("numminers", 1)
        .map_err(|_| "numminers should be a number")?;
    let peer = match matches.opt_str("peer") {
        Some(mut peer) => {
            // add default port if one was not supplied
            if !peer.contains(':') {
                peer = format!("{}:{}", peer, DEFAULT_CRUZBIT_PORT);
            }
            // parse and resolve hostname to ip
            Some(resolve_host(&peer)?)
        }
        None => None,
    };
    let port = matches
        .opt_get_default("port", DEFAULT_CRUZBIT_PORT)
        .map_err(|_| "port should be a number")?;
    let prune = matches.opt_present("prune");
    let pub_key = matches.opt_str("pubkey");
    let cert_path = matches.opt_str("tlscert").map(PathBuf::from);
    let key_path = matches.opt_str("tlskey").map(PathBuf::from);
    let upnp = matches.opt_present("upnp");

    if num_miners > 0 {
        if pub_key.is_none() && key_file.is_none() {
            return Err(
                "-pubkey or -keyfile argument required to receive newly mined block rewards".into(),
            );
        }
        if pub_key.is_some() && key_file.is_some() {
            return Err("specify only one of -pubkey or -keyfile but not both".into());
        }
    }

    if cert_path.is_some() && key_path.is_none() {
        return Err("-tlskey argument missing".into());
    }
    if cert_path.is_none() && key_path.is_some() {
        return Err("-tlscert argument missing".into());
    }

    // initialize statics
    let ban_map = BAN_MAP.get_or_init(|| {
        if let Some(ban_list) = ban_list {
            load_ban_list(ban_list).unwrap_or_else(|err| {
                error!("{:?}", err);
                exit(1);
            })
        } else {
            HashMap::new()
        }
    });

    let genesis_block =
        serde_json::from_str::<Block>(GENESIS_BLOCK_JSON).map_err(JsonError::Deserialize)?;

    let genesis_id = GENESIS_ID.get_or_init(|| genesis_block.id().expect("genesis block id"));

    let memo = MEMO.get_or_init(|| matches.opt_str("memo"));

    let pub_keys = PUB_KEYS.get_or_init(|| {
        if num_miners > 0 {
            load_public_keys(pub_key, key_file).unwrap_or_else(|err| {
                error!("{:?}", err);
                exit(1);
            })
        } else {
            Vec::new()
        }
    });

    // initialize CUDA or OpenCL devices if enabled
    #[cfg(any(feature = "cuda", feature = "opencl"))]
    {
        if num_miners > 0 {
            let device_count = cruzbit::gpu::gpu_miner_init();
            let gpu = if cfg!(feature = "cuda") {
                "CUDA"
            } else {
                "OpenCL"
            };
            if device_count != num_miners {
                return Err(ClientError::Args(format!(
                    "{} enabled but -numminers is {} and supported devices is {}",
                    gpu, num_miners, device_count,
                )));
            }
            info!("{} initialized", gpu);
        }
    }

    info!("Starting up...");
    info!("Genesis block ID: {}", genesis_id);

    // instantiate the block storage
    let block_store = BlockStorageDisk::new(
        data_dir.join("blocks"),
        data_dir.join("headers.db"),
        false, // not read only
        compress,
    )?;

    // instantiate the ledger
    let ledger = LedgerDisk::new(data_dir.join("ledger.db"), Arc::clone(&block_store), prune)?;

    // instantiate peer storage
    let peer_store = PeerStorageDisk::new(data_dir.join("peers.db"))?;

    // instantiate the transaction queue
    let tx_queue = TransactionQueueMemory::new(Arc::clone(&ledger));

    let mut shutdowns = Vec::new();
    let (shutdown_chan_tx, shutdown_chan_rx) = shutdown_channel();

    // create and run the processor
    let processor = Processor::new(
        genesis_id,
        Arc::clone(&block_store),
        Arc::clone(&tx_queue),
        Arc::clone(&ledger),
        shutdown_chan_rx,
    );
    shutdowns.push(Shutdown::new(processor.spawn(), shutdown_chan_tx));

    // process the genesis block
    processor
        .process_candidate_block(*genesis_id, genesis_block, PEER_ADDR_SELF)
        .await?;

    if num_miners > 0 {
        let (hash_update_chan_tx, hash_update_chan_rx) = channel(num_miners);

        // create and run miners
        for i in 0..num_miners {
            let (shutdown_chan_tx, shutdown_chan_rx) = shutdown_channel();
            let miner = Miner::new(
                pub_keys,
                memo,
                Arc::clone(&block_store),
                Arc::clone(&tx_queue),
                Arc::clone(&ledger),
                Arc::clone(&processor),
                hash_update_chan_tx.clone(),
                i,
                shutdown_chan_rx,
            );

            shutdowns.push(Shutdown::new(miner.spawn(), shutdown_chan_tx));
        }

        // print hashrate updates
        let (shutdown_chan_tx, shutdown_chan_rx) = shutdown_channel();
        let hashrate_monitor =
            HashrateMonitor::new(num_miners, hash_update_chan_rx, shutdown_chan_rx);
        shutdowns.push(Shutdown::new(hashrate_monitor.spawn(), shutdown_chan_tx));
    } else {
        info!("Mining is currently disabled")
    }

    // determine external ip
    let my_external_ip = determine_external_ip().await;
    let mut my_external_ip_upnp = None;

    if upnp && !no_accept {
        info!("Enabling forwarding for port {}...", port);
        match igd::search_gateway(Default::default()) {
            Err(ref err) => info!("Failed to enable forwarding: {}", err),
            Ok(gateway) => match gateway.get_external_ip() {
                Err(ref err) => {
                    info!("Failed to enable port forwarding: {}", err);
                }
                Ok(ext_addr) => {
                    my_external_ip_upnp = Some(ext_addr);
                    info!("Successfully enabled port forwarding");
                }
            },
        }
    }

    // determine if we're open for connections
    let open = if let Some(my_external_ip_upnp) = my_external_ip_upnp {
        // if upnp enabled make sure the address returned matches the outside view
        my_external_ip
            .as_ref()
            .map_or(false, |ip| my_external_ip_upnp == *ip)
    } else {
        // if no upnp see if any local routable IP matches the outside view
        my_external_ip.as_ref().map_or(false, |ip| {
            have_local_ip_match(ip)
                .map_err(ClientError::from)
                .unwrap_or_else(|err| {
                    error!("{:?}", err);
                    false
                })
        })
    };

    // start a dns server
    if dns_seed {
        let (shutdown_chan_tx, shutdown_chan_rx) = shutdown_channel();
        let dns_seeder = DnsSeeder::new(
            Arc::clone(&peer_store),
            port,
            my_external_ip,
            shutdown_chan_rx,
        )
        .await;
        shutdowns.push(Shutdown::new(dns_seeder.spawn(), shutdown_chan_tx));
    }

    // manage peer connections
    let (shutdown_chan_tx, shutdown_chan_rx) = shutdown_channel();
    let peer_manager = PeerManager::new(
        genesis_id,
        peer_store,
        block_store,
        ledger,
        processor,
        tx_queue,
        data_dir,
        my_external_ip,
        peer,
        cert_path,
        key_path,
        port,
        inbound_limit,
        no_accept,
        ban_map,
        no_irc,
        dns_seed,
        open,
        shutdown_chan_rx,
    );
    shutdowns.push(Shutdown::new(peer_manager.spawn(), shutdown_chan_tx));
    let _ = signal::ctrl_c().await;
    for shutdown in shutdowns.into_iter().rev() {
        shutdown.send().await;
    }
    info!("Exiting");

    Ok(())
}

fn load_public_keys(
    pub_key_encoded: Option<String>,
    key_file: Option<PathBuf>,
) -> Result<Vec<PublicKey>, ClientError> {
    let mut pub_keys_encoded = Vec::new();
    let mut pub_keys = Vec::new();

    if let Some(pub_key_encoded) = pub_key_encoded {
        pub_keys_encoded.push(pub_key_encoded);
    } else {
        let filename = key_file.expect("expected a key file");
        let file = File::open(&filename).map_err(|err| FileError::Open(filename, err))?;
        let buf = BufReader::new(file);

        pub_keys_encoded = buf
            .lines()
            .map(|line| line.expect("failed to parse pubkey"))
            .collect();
    }

    for pub_key_encoded in pub_keys_encoded {
        let mut buf = [0u8; PublicKey::BYTES];
        let pub_key_bytes =
            Base64::decode(pub_key_encoded, &mut buf).map_err(EncodingError::Base64Decode)?;
        let pub_key = PublicKey::from_slice(pub_key_bytes).map_err(DataError::Ed25519)?;
        pub_keys.push(pub_key);
    }

    Ok(pub_keys)
}

fn load_ban_list(ban_list_file: PathBuf) -> Result<HashMap<String, bool>, ClientError> {
    let file = File::open(&ban_list_file).map_err(|err| FileError::Open(ban_list_file, err))?;
    let mut ban_map = HashMap::new();
    let lines = BufReader::new(file).lines();

    for ip in lines.map_while(Result::ok) {
        ban_map.insert(ip.trim().to_owned(), true);
    }

    Ok(ban_map)
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage of {}:", program);
    print!("{}", opts.usage(&brief));
}

fn init_logger() {
    // default to info level unless RUST_LOG is set
    Builder::from_env(Env::default().default_filter_or("info"))
        .format(|buf, record| {
            write!(buf, "{}", buf.timestamp())?;
            if record.level() != Level::Info {
                write!(buf, " {}", record.level())?;
            }
            writeln!(buf, " {}", record.args())
        })
        .init();
}

#[derive(Error)]
pub enum ClientError {
    #[error("{0}")]
    Args(String),

    #[error("block storage")]
    BlockStorage(#[from] BlockStorageError),
    #[error("data")]
    Data(#[from] DataError),
    #[error("encoding")]
    Encoding(#[from] EncodingError),
    #[error("file")]
    File(#[from] FileError),
    #[error("json")]
    Json(#[from] JsonError),
    #[error("ledger")]
    Ledger(#[from] LedgerError),
    #[error("parsing")]
    Parsing(#[from] ParsingError),
    #[error("peer manager")]
    PeerManager(#[from] PeerManagerError),
    #[error("peer storage")]
    PeerStorage(#[from] PeerStorageError),
    #[error("processing block")]
    ProcessBlock(#[from] ProcessBlockError),
}

impl_debug_error_chain!(ClientError, "client");

impl From<&str> for ClientError {
    fn from(s: &str) -> Self {
        ClientError::Args(s.to_owned())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_load_public_keys() {
        let pub_key_encoded = Some("2df37wYjh3t8OekRXD0qpRsj9dD9XpVyqkvxnsqNj/s=".to_owned());
        let key_file = None;
        let pub_keys = load_public_keys(pub_key_encoded, key_file);
        assert_eq!(1, pub_keys.unwrap().len());
    }
}
