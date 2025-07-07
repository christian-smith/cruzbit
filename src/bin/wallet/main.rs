use std::env::args;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use base64ct::{Base64, Encoding};
use console::style;
use cruzbit::block::{Block, BlockError, BlockID};
use cruzbit::constants::{
    COINBASE_MATURITY, CRUZBITS_PER_CRUZ, DEFAULT_CRUZBIT_PORT, MAX_MEMO_LENGTH,
};
use cruzbit::error::{DataError, EncodingError, ErrChain, FileError, JsonError, ParsingError};
use cruzbit::genesis::GENESIS_BLOCK_JSON;
use cruzbit::impl_debug_error_chain;
use cruzbit::protocol::{FilterBlockMessage, PushTransactionMessage};
use cruzbit::transaction::{Transaction, TransactionError, TransactionID, TRANSACTION_ID_LENGTH};
use cruzbit::utils::resolve_host;
use cruzbit::wallet::{FilterBlockCallback, TransactionCallback, Wallet, WalletError};
use dialoguer::theme::SimpleTheme;
use dialoguer::{Completion, Confirm, Input, Password};
use ed25519_compact::{PublicKey, SecretKey};
use env_logger::{Builder, Env};
use faster_hex::hex_decode;
use futures::Future;
use getopts::Options;
use humantime::format_rfc3339;
use log::{error, Level};
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;

/// This is a lightweight wallet client.
#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) => match err {
            WalletBinError::Args(err) => {
                println!("{err}");
                ExitCode::SUCCESS
            }
            _ => {
                error!("{err:?}");
                ExitCode::FAILURE
            }
        },
    }
}

async fn run() -> Result<(), WalletBinError> {
    init_logger();
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let args = args().collect::<Vec<_>>();
    let program = &args[0];

    let mut opts = Options::new();
    opts.long_only(true);
    opts.optopt("", "peer", "Address of a peer to connect to", "string");
    opts.optopt(
        "",
        "walletdb",
        "Path to a wallet database (created if it doesn't exist)",
        "walletdb",
    );
    opts.optflag(
        "",
        "tlsverify",
        "Verify the TLS certificate of the peer is signed by a recognized CA and the host matches the CN",
    );
    opts.optflag("", "recover", "Attempt to recover a corrupt walletdb");

    let Ok(matches) = opts.parse(&args[1..]) else {
        print_usage(program, opts);
        return Ok(());
    };
    let db_path = match matches.opt_str("walletdb") {
        Some(db_path) => PathBuf::from(db_path),
        None => return Err("path to wallet database required".into()),
    };
    let peer = match matches.opt_str("peer") {
        Some(mut peer) => {
            // add default port if one was not supplied
            if !peer.contains(':') {
                peer = format!("{peer}:{DEFAULT_CRUZBIT_PORT}");
            }
            // parse and resolve hostname to ip
            resolve_host(&peer)?
        }
        None => SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            DEFAULT_CRUZBIT_PORT,
        ),
    };
    let recover = matches.opt_present("recover");
    if recover {
        match Wallet::repair_db(db_path).map_err(WalletBinError::Wallet) {
            Ok(_) => {
                println!("Recovery completed without error");
                return Ok(());
            }
            Err(err) => return Err(err),
        }
    }
    let tls_verify = matches.opt_present("tlsverify");

    // load genesis block
    let genesis_block =
        serde_json::from_str::<Block>(GENESIS_BLOCK_JSON).map_err(JsonError::Deserialize)?;
    let genesis_id = genesis_block.id()?;

    println!("Starting up...");
    println!("Genesis block ID: {genesis_id}");

    if recover {
        println!("Attempting to recover wallet...");
    }

    // instantiate wallet
    let wallet = Wallet::new(db_path)?;

    loop {
        // load wallet passphrase
        let passphrase = prompt_for_passphrase()?;
        if wallet.set_passphrase(passphrase)? {
            break;
        }
        println!(
            "{}",
            style("Passphrase is not the one used to encrypt your most recent key.")
                .bold()
                .red()
        );
    }

    let new_txs = NewTxs::default();
    let new_confs = NewConfs::default();
    let cmd_lock = Arc::new(AsyncMutex::new(()));

    // handle new incoming transactions
    let transaction_cmd_lock = Arc::clone(&cmd_lock);
    let transaction_new_txs = Arc::clone(&new_txs);
    let transaction_callback: TransactionCallback =
        Box::new(move |wallet: &Arc<Wallet>, pt: PushTransactionMessage| {
            match transaction_is_relevant(wallet, &pt.transaction) {
                Ok(ok) => {
                    if !ok {
                        // false positive
                        return;
                    }
                }
                Err(err) => {
                    eprintln!("Error: {err:?}");
                    return;
                }
            };

            let mut new_txs = transaction_new_txs.lock().unwrap();
            let show_message = new_txs.is_empty();
            new_txs.push(pt.transaction);

            if show_message {
                let cmd_lock = Arc::clone(&transaction_cmd_lock);
                tokio::spawn(async move {
                    // don't interrupt a user during a command
                    let _cmd_guard = cmd_lock.lock().await;
                    print!("\n\nNew incoming transaction! ");
                    print!("Type {} to view it.\n\n", style("show").bold().green());
                });
            }
        });
    wallet.set_transaction_callback(transaction_callback);

    // handle new incoming filter blocks
    let filter_block_cmd = Arc::clone(&cmd_lock);
    let filter_block_new_confs = Arc::clone(&new_confs);
    let filter_block_callback: FilterBlockCallback =
        Box::new(move |wallet: &Arc<Wallet>, fb: FilterBlockMessage| {
            for tx in fb.transactions {
                match transaction_is_relevant(wallet, &tx) {
                    Ok(ok) => {
                        if !ok {
                            // false positive
                            continue;
                        }
                    }
                    Err(err) => {
                        eprintln!("Error: {err:?}");
                        continue;
                    }
                };

                let mut new_confs = filter_block_new_confs.lock().unwrap();
                let show_message = new_confs.is_empty();
                new_confs.push(TransactionWithHeight {
                    tx,
                    height: fb.header.height,
                });

                if show_message {
                    let cmd = Arc::clone(&filter_block_cmd);
                    tokio::spawn(async move {
                        // don't interrupt a user during a command
                        let _cmd_guard = cmd.lock().await;
                        print!("\n\nNew transaction confirmation! ");
                        print!("Type {} to view it.\n\n", style("conf").bold().green());
                    });
                }
            }
        });
    wallet.set_filter_block_callback(filter_block_callback);

    // setup prompt
    let completion = CmdCompletion::default();
    println!("Please select a command.");
    println!(
        "To connect to your wallet peer you need to issue a command requiring it, e.g. {}",
        style("balance").bold().green()
    );

    loop {
        // run interactive prompt
        let cmd = Input::<String>::with_theme(&SimpleTheme {})
            .with_prompt(">")
            .allow_empty(true)
            .completion_with(&completion)
            .interact_text()?;
        {
            let _cmd_guard = cmd_lock.lock().await;
            let connect = connect_wallet(&wallet, peer, &genesis_id, tls_verify);
            match handle_cmd(&completion, &cmd, &wallet, connect, &new_confs, &new_txs).await {
                Ok(ok) => {
                    if !ok {
                        break Ok(());
                    }
                }
                Err(err) => {
                    eprintln!("Error: {err:?}");
                }
            }
        }
    }
}

async fn handle_cmd(
    completion: &CmdCompletion,
    cmd: &str,
    wallet: &Arc<Wallet>,
    connect: impl Future<Output = Result<(), WalletBinError>>,
    new_confs: &NewConfs,
    new_txs: &NewTxs,
) -> Result<bool, WalletBinError> {
    match cmd {
        "balance" => {
            connect.await?;
            let pub_keys = wallet.get_keys()?;

            let mut total = 0;
            for (i, pub_key) in pub_keys.iter().enumerate() {
                let (balance, _height) = wallet.get_balance(pub_key).await?;
                let amount = round_float(balance as f64, 8) / CRUZBITS_PER_CRUZ as f64;
                let mut buf = [0u8; 44];
                let encoded = Base64::encode(pub_key.as_ref(), &mut buf)
                    .map_err(EncodingError::Base64Encode)?;
                println!("{:4}: {} {:16.8}", i + 1, encoded, amount);
                total += balance;
            }
            let amount = round_float(total as f64, 8) / CRUZBITS_PER_CRUZ as f64;
            println!("{}: {:.8}", style("Total").bold(), amount);
        }

        "clearconf" => {
            let mut new_confs = new_confs.lock().unwrap();
            new_confs.clear();
        }

        "clearnew" => {
            let mut new_txs = new_txs.lock().unwrap();
            new_txs.clear();
        }

        "conf" => {
            connect.await?;
            let (tx, left) = {
                let mut new_confs = new_confs.lock().unwrap();
                if new_confs.is_empty() {
                    (None, 0)
                } else {
                    let tx = new_confs.remove(0);
                    (Some(tx), new_confs.len())
                }
            };
            if let Some(tx) = tx {
                show_transaction(wallet, tx.tx, Some(tx.height)).await?;
                if left > 0 {
                    println!(
                        "\n{} new confirmations(s) left to display. Type {} to continue.",
                        left,
                        style("conf").bold().green()
                    );
                }
            } else {
                println!("No new confirmations to display")
            }
        }

        "dumpkeys" => {
            let pub_keys = wallet.get_keys()?;
            if pub_keys.is_empty() {
                println!("No public keys found");
                return Ok(true);
            }
            let name = "keys.txt";
            let mut file = File::create(name).map_err(|err| FileError::Create(name.into(), err))?;
            for pub_key in pub_keys.iter() {
                let mut buf = [0u8; 44];
                let _encoded = Base64::encode(pub_key.as_ref(), &mut buf)
                    .map_err(EncodingError::Base64Encode)?;
                file.write_all(&[&buf, &b"\n"[..]].concat())
                    .map_err(|err| FileError::Write(name.into(), err))?;
            }
            println!(
                "{} public keys saved to '{}'",
                pub_keys.len(),
                style(name).bold()
            );
        }

        "export" => {
            println!("{}: Anyone with access to a wallet's private key(s) has full control of the funds in the wallet.", style("WARNING").bold().red());
            let confirm = prompt_for_confirmation("Are you sure you wish to proceed?");
            if !confirm {
                println!("Aborting export");
                return Ok(true);
            }
            let pub_keys = wallet.get_keys()?;
            if pub_keys.is_empty() {
                println!("No private keys found");
                return Ok(true);
            }
            let filename: PathBuf = prompt_for_string("Filename", "export.txt").into();
            let mut file =
                File::create(&filename).map_err(|err| FileError::Open(filename.clone(), err))?;
            let mut count = 0;
            for pub_key in pub_keys {
                let priv_key = match wallet.get_private_key(pub_key) {
                    Ok(Some(v)) => v,
                    Ok(None) | Err(_) => {
                        let mut buf = [0u8; 44];
                        let encoded =
                            match Base64::encode(pub_key.as_ref(), &mut buf).map_err(|err| {
                                WalletBinError::Encoding(EncodingError::Base64Encode(err))
                            }) {
                                Ok(v) => v,
                                Err(err) => {
                                    eprintln!("Error: {err:?}");
                                    continue;
                                }
                            };
                        println!(
                            "Couldn't get private key for public key: {encoded}; omitting from export"
                        );
                        continue;
                    }
                };

                let mut buf = [0u8; 44];
                let encoded_pub_key = Base64::encode(pub_key.as_ref(), &mut buf)
                    .map_err(EncodingError::Base64Encode)?;
                let mut buf = [0u8; 88];
                let encoded_priv_key = Base64::encode(priv_key.as_ref(), &mut buf)
                    .map_err(EncodingError::Base64Encode)?;
                let pair = format!("{encoded_pub_key},{encoded_priv_key}\n",);

                if let Err(err) = file
                    .write(pair.as_bytes())
                    .map_err(|err| WalletBinError::File(FileError::Write(filename.clone(), err)))
                {
                    eprintln!("Error: {err:?}");
                }
                count += 1;
            }

            println!(
                "{} wallet key pairs saved to '{}'",
                count,
                style(&filename.display()).bold()
            );
        }

        "genkeys" => {
            let count = prompt_for_number("Count");
            let pub_keys = wallet.new_keys(count)?;
            println!("Generated {} new keys", pub_keys.len());
            if wallet.is_connected().await {
                // update our filter if online
                wallet.set_filter().await?
            }
        }

        "import" => {
            println!(
                "Files should have one address per line, in the format: {}",
                style("PUBLIC_KEY,PRIVATE_KEY").bold()
            );
            println!(
                "Files generated by the {} command are automatically formatted in this way.",
                style("export").bold()
            );

            let filename: PathBuf = prompt_for_string("Filename", "export.txt").into();
            let file = File::open(&filename).map_err(|err| FileError::Open(filename, err))?;

            let mut skipped = 0;
            let mut pub_keys = Vec::new();
            let reader = BufReader::new(file);

            for line in reader.lines() {
                let line = line.unwrap();
                let key = line.split(',').collect::<Vec<_>>();
                if key.len() != 2 {
                    eprintln!("Error found: incorrectly formatted line");
                    skipped += 1;
                    continue;
                }
                let mut buf = [0u8; PublicKey::BYTES];
                let pub_key_bytes =
                    match Base64::decode(key[0], &mut buf).map_err(EncodingError::Base64Decode) {
                        Ok(v) => v,
                        Err(err) => {
                            eprintln!("Error with public key: {err}");
                            skipped += 1;
                            continue;
                        }
                    };
                let pub_key = match PublicKey::from_slice(pub_key_bytes).map_err(DataError::Ed25519)
                {
                    Ok(v) => v,
                    Err(err) => {
                        eprintln!("Error: {err}");
                        continue;
                    }
                };

                let mut buf = [0u8; SecretKey::BYTES];
                let priv_key_bytes =
                    match Base64::decode(key[1], &mut buf).map_err(EncodingError::Base64Decode) {
                        Ok(v) => v,
                        Err(err) => {
                            eprintln!("Error with private key: {err}");
                            skipped += 1;
                            continue;
                        }
                    };

                let priv_key = SecretKey::from_slice(priv_key_bytes).unwrap();
                // add key to database
                if let Err(err) = wallet.add_key(pub_key, priv_key) {
                    eprintln!("Error adding key pair to database: {err:?}");
                    skipped += 1;
                    continue;
                }
                pub_keys.push(pub_key);
            }
            for (i, pub_key) in pub_keys.iter().enumerate() {
                let mut buf = [0u8; 44];
                let encoded = Base64::encode(pub_key.as_ref(), &mut buf)
                    .map_err(EncodingError::Base64Encode)?;

                println!("{:4}: {}", i + 1, encoded);
            }
            println!(
                "Successfully added {} key(s); {} line(s) skipped.",
                pub_keys.len(),
                skipped
            );
        }

        "listkeys" => {
            let pub_keys = wallet.get_keys()?;
            for (i, pub_key) in pub_keys.iter().enumerate() {
                let mut buf = [0u8; 44];
                let encoded = Base64::encode(pub_key.as_ref(), &mut buf)
                    .map_err(EncodingError::Base64Encode)?;
                println!("{:4}: {}", i + 1, encoded);
            }
        }

        "newkey" => {
            let pub_keys = wallet.new_keys(1)?;
            let mut buf = [0u8; 44];
            let encoded = Base64::encode(pub_keys[0].as_ref(), &mut buf)
                .map_err(EncodingError::Base64Encode)?;
            println!("New key generated, public key: {}", style(encoded).bold());
            if wallet.is_connected().await {
                // update our filter if online
                wallet.set_filter().await?
            }
        }

        "quit" => {
            wallet.shutdown().await?;
            return Ok(false);
        }

        "rewards" => {
            connect.await?;
            let pub_keys = wallet.get_keys()?;
            let (_tip_id, tip_header) = wallet.get_tip_header().await?;
            let mut total = 0;

            'gpkt: for (i, pub_key) in pub_keys.into_iter().enumerate() {
                let mut rewards = 0;
                let mut start_height = tip_header.height.saturating_sub(COINBASE_MATURITY);
                let mut start_index = 0;

                loop {
                    let (_start_height, stop_height, stop_index, fbs) = match wallet
                        .get_public_key_transactions(
                            pub_key,
                            start_height,
                            tip_header.height + 1,
                            start_index,
                            32,
                        )
                        .await
                        .map_err(WalletBinError::Wallet)
                    {
                        Ok(v) => v,
                        Err(err) => {
                            eprintln!("Error: {err:?}");
                            break 'gpkt;
                        }
                    };
                    let mut num_tx = 0;
                    (start_height, start_index) = (stop_height, stop_index + 1);

                    if let Some(fbs) = fbs {
                        for fb in fbs {
                            for tx in fb.transactions {
                                num_tx += 1;
                                if tx.is_coinbase() {
                                    rewards += tx.amount;
                                }
                            }
                        }
                    }

                    if num_tx < 32 {
                        break;
                    }
                }

                let mut buf = [0u8; 44];
                let encoded = Base64::encode(pub_key.as_ref(), &mut buf)
                    .map_err(EncodingError::Base64Encode)?;
                let amount = round_float(rewards as f64, 8) / CRUZBITS_PER_CRUZ as f64;
                println!("{:4}: {} {:16.8}", i + 1, encoded, amount);
                total += rewards;
            }

            let amount = round_float(total as f64, 8) / CRUZBITS_PER_CRUZ as f64;
            println!("{}: {:.8}", style("Total").bold(), amount);
        }

        "send" => {
            connect.await?;
            let id = send_transaction(wallet).await?;
            println!("Transaction {id} sent");
        }

        "show" => {
            connect.await?;
            let (tx, left) = {
                let mut new_txs = new_txs.lock().unwrap();
                if new_txs.is_empty() {
                    (None, 0)
                } else {
                    let tx = new_txs.remove(0);
                    (Some(tx), new_txs.len())
                }
            };
            if let Some(tx) = tx {
                show_transaction(wallet, tx, None).await?;
                if left > 0 {
                    println!(
                        "\n{} new transaction(s) left to display. Type {} to continue.",
                        left,
                        style("show").green()
                    );
                }
            } else {
                println!("No new transactions to display")
            }
        }

        "txstatus" => {
            connect.await?;
            let tx_id = prompt_for_transaction_id("ID")?;
            println!();
            let (Some(tx), _block_id, Some(height)) = wallet.get_transaction(tx_id).await? else {
                println!(
                    "Transaction {tx_id} not found in the blockchain at this time."
                );
                println!("It may be waiting for confirmation.");
                return Ok(true);
            };
            show_transaction(wallet, tx, Some(height)).await?;
        }

        "verify" => {
            let pub_keys = wallet.get_keys()?;
            let mut verified = 0;
            let mut corrupt = 0;
            for (i, pub_key) in pub_keys.into_iter().enumerate() {
                match wallet.verify_key(pub_key) {
                    Ok(_) => {
                        verified += 1;
                        let mut buf = [0u8; 44];
                        let encoded = Base64::encode(pub_key.as_ref(), &mut buf)
                            .map_err(EncodingError::Base64Encode)?;
                        println!(
                            "{:4}: {} {}",
                            i + 1,
                            encoded,
                            style("Verified").bold().green()
                        );
                    }
                    Err(err) => {
                        corrupt += 1;
                        let mut buf = [0u8; 44];
                        let encoded = Base64::encode(pub_key.as_ref(), &mut buf)
                            .map_err(EncodingError::Base64Encode)?;
                        println!("{:4}: {} {:?}", i + 1, encoded, style(err).bold().red());
                    }
                };
            }
            println!(
                "{verified} key(s) verified and {corrupt} key(s) potentially corrupt"
            )
        }

        _ => {
            completion.help();
        }
    }

    println!();
    Ok(true)
}

/// Prompt for transaction details and request the wallet to send it
async fn send_transaction(wallet: &Wallet) -> Result<TransactionID, WalletBinError> {
    let (min_fee, min_amount) = wallet.get_transaction_relay_policy().await?;

    // prompt for from
    let from = prompt_for_public_key("From")?;

    // prompt for to
    let to = prompt_for_public_key("To")?;

    // prompt for amount
    let amount = prompt_for_value("Amount");
    if amount < min_amount {
        return Err(ValidationError::MinimumTransactionAmount(
            round_float(min_amount as f64, 8) / CRUZBITS_PER_CRUZ as f64,
        )
        .into());
    }

    // prompt for fee
    let fee = prompt_for_value("Fee");
    if fee < min_fee {
        return Err(ValidationError::MinimumTransactionFee(
            round_float(min_fee as f64, 8) / CRUZBITS_PER_CRUZ as f64,
        )
        .into());
    }

    // prompt for memo
    let memo = Input::<String>::new()
        .with_prompt("Memo")
        .allow_empty(true)
        .interact()?;
    if memo.len() > MAX_MEMO_LENGTH {
        return Err(ValidationError::MaximumMemoLengthExceeded(MAX_MEMO_LENGTH, memo.len()).into());
    }

    let memo = if memo.is_empty() { None } else { Some(memo) };

    // create and send send it. by default the transaction expires if not mined within 3 blocks from now
    let id = wallet
        .send(from, to, amount, fee, None, Some(3), memo)
        .await?;
    Ok(id)
}

fn prompt_for_public_key(prompt: &str) -> Result<PublicKey, WalletBinError> {
    let text = Input::<String>::new()
        .with_prompt(prompt)
        .allow_empty(true)
        .interact()
        .unwrap();

    if text.is_empty() || text.len() != 44 {
        return Err(ValidationError::PublicKeyInvalid.into());
    };

    let mut buf = [0u8; PublicKey::BYTES];
    Base64::decode(text.as_bytes(), &mut buf).map_err(EncodingError::Base64Decode)?;
    if buf.len() != PublicKey::BYTES {
        return Err(ValidationError::PublicKeyInvalid.into());
    }

    let pub_key = PublicKey::from_slice(&buf).map_err(DataError::Ed25519)?;
    Ok(pub_key)
}

fn prompt_for_value(prompt: &str) -> u64 {
    let value = Input::new().with_prompt(prompt).interact().unwrap();
    let value_float = round_float(value, 8) * CRUZBITS_PER_CRUZ as f64;
    round_to_6th(value_float) as u64
}

fn prompt_for_number(prompt: &'static str) -> usize {
    Input::new().with_prompt(prompt).interact().unwrap()
}

fn prompt_for_confirmation(prompt: &str) -> bool {
    Confirm::new()
        .with_prompt(prompt)
        .default(false)
        .interact()
        .unwrap()
}

fn prompt_for_string(prompt: &str, default_response: &str) -> String {
    Input::new()
        .with_prompt(prompt)
        .with_initial_text(default_response)
        .interact()
        .unwrap()
}

fn prompt_for_transaction_id(prompt: &str) -> Result<TransactionID, WalletBinError> {
    let text = Input::<String>::new().with_prompt(prompt).interact()?;
    if text.len() != TRANSACTION_ID_LENGTH * 2 {
        return Err(ValidationError::TransactionIDInvalid.into());
    }
    let mut tx_id = TransactionID::new();
    hex_decode(text.as_bytes(), &mut tx_id).map_err(EncodingError::HexDecode)?;

    Ok(tx_id)
}

async fn show_transaction(
    wallet: &Arc<Wallet>,
    tx: Transaction,
    height: Option<u64>,
) -> Result<(), WalletBinError> {
    let id = tx.id()?;
    println!("{:7}: {}", style("ID").bold(), id);
    println!("{:7}: {}", style("Series").bold(), tx.series);
    println!(
        "{:7}: {}",
        style("Time").bold(),
        format_rfc3339(UNIX_EPOCH + Duration::from_secs(tx.time))
    );

    if let Some(from) = tx.from {
        let mut buf = [0u8; 44];
        let encoded = Base64::encode(&from[..], &mut buf).map_err(EncodingError::Base64Encode)?;
        println!("{:7}: {}", style("From").bold(), encoded);
    }

    let mut buf = [0u8; 44];
    let encoded = Base64::encode(&tx.to[..], &mut buf).map_err(EncodingError::Base64Encode)?;

    println!("{:7}: {}", style("To").bold(), encoded);
    println!(
        "{:7}: {:.8}",
        style("Amount").bold(),
        round_float(tx.amount as f64, 8) / CRUZBITS_PER_CRUZ as f64
    );

    if let Some(fee) = tx.fee {
        println!(
            "{:7}: {:.8}",
            style("Fee").bold(),
            round_float(fee as f64, 8) / CRUZBITS_PER_CRUZ as f64
        );
    }

    if let Some(memo) = tx.memo {
        println!("{:7}: {}", style("Memo").bold(), memo);
    }

    let (_, header) = wallet.get_tip_header().await?;

    if let Some(height) = height {
        println!(
            "{:7}: confirmed at height {}, {} confirmation(s)",
            style("Status").bold(),
            height,
            (header.height - height) + 1
        );
    } else {
        if let Some(matures) = tx.matures {
            println!(
                "{:7}: cannot be mined until height: {}, current height: {}",
                style("Matures").bold(),
                matures,
                header.height
            );
        }
        if let Some(expires) = tx.expires {
            println!(
                "{:7}: cannot be mined after height: {}, current height: {}",
                style("Expires").bold(),
                expires,
                header.height
            );
        }
    }

    Ok(())
}

/// Catch filter false-positives
fn transaction_is_relevant(wallet: &Arc<Wallet>, tx: &Transaction) -> Result<bool, WalletBinError> {
    let pub_keys = wallet.get_keys()?;
    for pub_key in pub_keys {
        if tx.contains(pub_key) {
            return Ok(true);
        }
    }

    Ok(false)
}

// secure passphrase prompt helper
fn prompt_for_passphrase() -> Result<String, WalletBinError> {
    let password = Password::new()
        .with_prompt("\nEnter passphrase")
        .with_confirmation("Confirm passphrase", "Passphrase mismatch")
        .interact()?;
    Ok(password)
}

/// From: <https://groups.google.com/forum/#!topic/golang-nuts/ITZV08gAugI>
fn round_float(mut x: f64, prec: u32) -> f64 {
    let pow = 10_f64.powi(prec as i32);
    let mut intermed = x * pow;
    intermed = (intermed * 1e6).round() / 1e6; // round to 6th decimal
    let frac = intermed.fract();
    intermed += 0.5;
    x = 0.5;

    if frac < 0.0 {
        x = -0.5;
        intermed -= 1_f64;
    }
    let rounder = if frac >= x {
        intermed.ceil()
    } else {
        intermed.floor()
    };

    rounder / pow
}

fn round_to_6th(x: f64) -> f64 {
    (x * 1e6).round() / 1e6
}

/// Connect the wallet on-demand
async fn connect_wallet(
    wallet: &Arc<Wallet>,
    peer: SocketAddr,
    genesis_id: &BlockID,
    tls_verify: bool,
) -> Result<(), WalletBinError> {
    if wallet.is_connected().await {
        return Ok(());
    }
    wallet
        .connect(peer, genesis_id, tls_verify)
        .await
        .map_err(WalletBinError::Wallet)?;
    wallet.set_filter().await.map_err(WalletBinError::Wallet)
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage of {program}:");
    print!("{}", opts.usage(&brief));
}

fn init_logger() {
    // default to error level unless RUST_LOG is set
    Builder::from_env(Env::default().default_filter_or("error"))
        .format(|buf, record| {
            write!(buf, "{}", buf.timestamp())?;
            if record.level() != Level::Info {
                write!(buf, " {}", record.level())?;
            }
            writeln!(buf, " {}", record.args())
        })
        .init();
}

type NewTxs = Arc<Mutex<Vec<Transaction>>>;
type NewConfs = Arc<Mutex<Vec<TransactionWithHeight>>>;

struct TransactionWithHeight {
    tx: Transaction,
    height: u64,
}

struct CmdCompletion {
    options: Vec<&'static str>,
    items: Vec<(&'static str, &'static str)>,
}

impl CmdCompletion {
    pub fn new(items: Vec<(&'static str, &'static str)>) -> Self {
        let mut options = items.iter().map(|(cmd, _)| *cmd).collect::<Vec<_>>();
        options.push("help");
        Self { options, items }
    }

    pub fn help(&self) {
        for (text, description) in self.items.iter() {
            println!("{text} - {description}");
        }
    }
}

impl Completion for CmdCompletion {
    fn get(&self, input: &str) -> Option<String> {
        let matches = self
            .options
            .iter()
            .filter(|option| option.starts_with(input))
            .collect::<Vec<_>>();

        if matches.len() == 1 {
            Some(matches[0].to_string())
        } else {
            None
        }
    }
}

impl Default for CmdCompletion {
    fn default() -> Self {
        let items = vec![
		("balance",  "Retrieve the current balance of all public keys"),
		("clearconf",  "Clear all pending transaction confirmation notifications"),
		("clearnew",  "Clear all pending incoming transaction notifications"),
		("conf",  "Show new transaction confirmations"),
		("dumpkeys",  "Dump all of the wallet's public keys to a text file"),
		("export",  "Save all of the wallet's public-private key pairs to a text file"),
		("genkeys",  "Generate multiple keys at once"),
		("import",  "Import public-private key pairs from a text file"),
	        ("listkeys",  "List all known public keys"),
                ("newkey", "Generate and store a new private key"),
		("rewards",  "Show immature block rewards for all public keys"),
		("send",  "Send cruzbits to someone"),
		("show",  "Show new incoming transactions"),
		("txstatus",  "Show confirmed transaction information given a transaction ID"),
		("verify",  "Verify the private key is decryptable and intact for all public keys displayed with 'listkeys'"),
                ("quit",  "Quit this wallet session"),
             ];

        Self::new(items)
    }
}

#[derive(Error)]
pub enum WalletBinError {
    #[error("{0}")]
    Args(String),

    #[error("block")]
    Block(#[from] BlockError),
    #[error("data")]
    Data(#[from] DataError),
    #[error("encoding")]
    Encoding(#[from] EncodingError),
    #[error("block")]
    File(#[from] FileError),
    #[error("json")]
    Json(#[from] JsonError),
    #[error("parsing")]
    Parsing(#[from] ParsingError),
    #[error("transaction")]
    Transaction(#[from] TransactionError),
    #[error("validation")]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Wallet(#[from] WalletError),

    #[error(transparent)]
    Dialoguer(#[from] dialoguer::Error),
}

impl_debug_error_chain!(WalletBinError, "wallet");

impl From<&'static str> for WalletBinError {
    fn from(s: &'static str) -> Self {
        WalletBinError::Args(s.to_owned())
    }
}

#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("maximum memo length ({0}) exceeded ({0})")]
    MaximumMemoLengthExceeded(usize, usize),
    #[error("the peer's minimum amount to relay transactions is %.8f")]
    MinimumTransactionAmount(f64),
    #[error("the peer's minimum required fee to relay transactions is {0:8}")]
    MinimumTransactionFee(f64),
    #[error("public key is invalid")]
    PublicKeyInvalid,
    #[error("transaction id is invalid")]
    TransactionIDInvalid,
}

#[cfg(test)]
#[test]
fn test_round_float() {
    let amount = round_float(4.89_f64, 8) * CRUZBITS_PER_CRUZ as f64;
    assert_eq!(round_to_6th(amount), 489000000_f64);

    let f = round_float(amount, 8) / CRUZBITS_PER_CRUZ as f64;
    assert_eq!(f, 4.89);

    let amount = round_float(0.00000001, 8) * CRUZBITS_PER_CRUZ as f64;
    assert_eq!(round_to_6th(amount), 1_f64);

    let f = round_float(amount, 8) / CRUZBITS_PER_CRUZ as f64;
    assert_eq!(f, 0.00000001);

    let amount = round_float(1.00000001, 8) * CRUZBITS_PER_CRUZ as f64;
    assert_eq!(round_to_6th(amount), 100000001_f64);

    let f = round_float(amount, 8) / CRUZBITS_PER_CRUZ as f64;
    assert_eq!(f, 1.00000001);

    let amount = round_float(123_f64, 8) * CRUZBITS_PER_CRUZ as f64;
    assert_eq!(round_to_6th(amount), 12300000000_f64);

    let f = round_float(amount, 8) / CRUZBITS_PER_CRUZ as f64;
    assert_eq!(f, 123.0);
}
