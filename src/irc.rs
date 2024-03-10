use faster_hex::hex_string;
use futures::StreamExt;
use irc::client::data::Config;
use irc::client::Client;
use irc::proto::{Command, Prefix, Response};
use log::{error, info};
use rand::Rng;
use thiserror::Error;
use tokio::task::JoinHandle;

use crate::block::BlockID;
use crate::error::{impl_debug_error_chain, ChannelError, ErrChain, ParsingError};
use crate::peer_manager::AddrChanSender;
use crate::shutdown::{ShutdownChanReceiver, SpawnedError};

const SERVER: &str = "irc.libera.chat";
const PORT: u16 = 6697;

/// IRC can be used for bootstrapping the network.
/// It primarily exists as a backup to our current limited set of DNS seeders.
pub struct IRC {
    conn: Client,
    nick: String,
    genesis_id: &'static BlockID,
    addr_chan_tx: AddrChanSender,
    shutdown_chan_rx: ShutdownChanReceiver,
}

impl IRC {
    /// Connects the IRC bootstrapper to the IRC network.
    /// port is our local cruzbit port. If it's set to 0 we won't be used for inbound connections.
    pub async fn connect(
        port: u16,
        genesis_id: &'static BlockID,
        addr_chan_tx: AddrChanSender,
        shutdown_chan_rx: ShutdownChanReceiver,
    ) -> Result<Self, IrcError> {
        let nick = generate_random_nick();

        let config = Config {
            nickname: Some(nick.clone()),
            username: Some(port.to_string()),
            server: Some(SERVER.to_owned()),
            port: Some(PORT),
            use_tls: Some(true),
            ..Default::default()
        };

        let conn = Client::from_config(config).await?;
        conn.identify()?;

        Ok(IRC {
            conn,
            nick,
            genesis_id,
            addr_chan_tx,
            shutdown_chan_rx,
        })
    }

    /// Spawns IRC on it's own main loop.
    pub fn spawn(self) -> JoinHandle<Result<(), SpawnedError>> {
        tokio::spawn(async move { self.run().await.map_err(Into::into) })
    }

    /// Run IRC on it's own main loop.
    pub async fn run(mut self) -> Result<(), IrcError> {
        let mut stream = self.conn.stream()?;
        let sender = self.conn.sender();
        let n = rand::thread_rng().gen_range(0..10);
        let channel = generate_channel_name(self.genesis_id, &n);

        loop {
            tokio::select! {
                msg = stream.next() => {
                    let message = match msg {
                        Some(Ok(v)) => v,
                        Some(Err(err)) => {
                            let err = IrcError::from(err);
                            error!("{:?}", err);
                            continue;
                        },
                        None => {
                            break Err(IrcError::Connection);
                        }
                    };

                    match message.command {
                        Command::Response(Response::RPL_WELCOME, _) => {
                            info!("Joining channel {}", &channel);
                            sender.send_join(&channel)?;
                        }

                        Command::Response(Response::RPL_ENDOFNAMES, _) => {
                            info!("Joined channel {}", &channel);
                            sender.send(Command::WHO(Some(channel.clone()), None))?;
                        }

                        Command::Response(Response::RPL_WHOREPLY, ref args) => {
                            let (nickname, username, hostname) = (&args[1], &args[2], &args[3]);
                            if *nickname != self.nick {
                                self.handle_irc_peer(username, hostname).await;
                            }
                        }

                        Command::JOIN(_, _, _) => {
                            if let Some(Prefix::Nickname(nickname, username, hostname)) = &message.prefix {
                                if *nickname != self.nick {
                                    self.handle_irc_peer(username, hostname).await;
                                }
                            }
                        }

                        _ => {}
                    }
                }

                _ = &mut self.shutdown_chan_rx => {
                    info!("IRC shutting down");
                    break Ok(())
                }
            }
        }
    }

    async fn handle_irc_peer(&self, username: &str, hostname: &str) {
        if !username.is_empty() {
            // pop off the ~
            let username = username[1..].to_owned();
            match username
                .parse::<u16>()
                .map_err(|err| IrcError::Parsing(ParsingError::Integer(err)))
            {
                Ok(port) => {
                    if port != 0 {
                        let addr_str = format!("{}:{}", hostname, port);
                        if let Err(err) = self
                            .addr_chan_tx
                            .send(addr_str)
                            .await
                            .map_err(IrcError::from)
                        {
                            error!("{:?}", err);
                        }
                    }
                }
                Err(err) => {
                    error!("{:?}", err);
                }
            }
        }
    }
}

fn generate_random_nick() -> String {
    let nick_bytes = rand::thread_rng().gen::<[u8; 6]>();
    format!("cb{}", hex_string(&nick_bytes))
}

fn generate_channel_name(genesis_id: &BlockID, n: &usize) -> String {
    let g = genesis_id.as_hex();
    format!("#cruzbit-{}-{}", &g[g.len() - 8..], n)
}

#[derive(Error)]
pub enum IrcError {
    #[error("client connection error, closing")]
    Connection,

    #[error("parsing peer address")]
    Parsing(#[from] ParsingError),
    #[error("channel")]
    Channel(#[from] ChannelError),

    #[error(transparent)]
    Irc(#[from] irc::error::Error),
}

impl_debug_error_chain!(IrcError, "irc");

impl From<tokio::sync::mpsc::error::SendError<String>> for IrcError {
    fn from(err: tokio::sync::mpsc::error::SendError<String>) -> Self {
        Self::Channel(ChannelError::Send("addr", err.to_string()))
    }
}
