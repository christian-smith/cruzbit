use std::error::Error as StdError;

use log::error;
use thiserror::Error;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::error::{ChannelError, ErrChain};
use crate::impl_debug_error_chain;

pub type ShutdownChanSender = oneshot::Sender<()>;
pub type ShutdownChanReceiver = oneshot::Receiver<()>;
pub type ShutdownChan = (ShutdownChanSender, ShutdownChanReceiver);
pub type SpawnedError = Box<dyn StdError + Send + Sync>;
pub type SpawnedHandle = JoinHandle<Result<(), SpawnedError>>;

pub struct Shutdown {
    monitor_handle: JoinHandle<()>,
    shutdown_chan_tx: ShutdownChanSender,
}

impl Shutdown {
    pub fn new(spawned_handle: SpawnedHandle, shutdown_chan_tx: ShutdownChanSender) -> Self {
        let monitor = ShutdownMonitor::new(spawned_handle);
        let monitor_handle = monitor.spawn();

        Self {
            monitor_handle,
            shutdown_chan_tx,
        }
    }

    pub async fn send(self) {
        if let Err(err) = self.shutdown_chan_tx.send(()) {
            error!("{:?}", ShutdownError::from(err));
        }

        if let Err(err) = self.monitor_handle.await {
            error!("{:?}", ShutdownError::Join(err));
        }
    }

    pub fn is_finished(&self) -> bool {
        self.monitor_handle.is_finished()
    }
}

pub struct ShutdownMonitor {
    spawned_handle: SpawnedHandle,
}

impl ShutdownMonitor {
    fn new(spawned_handle: SpawnedHandle) -> Self {
        Self { spawned_handle }
    }

    fn spawn(self) -> JoinHandle<()> {
        tokio::spawn(self.run())
    }

    /// Await and report on the JoinHandle result
    async fn run(self) {
        match self.spawned_handle.await {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => {
                error!("{:?}", ShutdownError::Spawned(err));
            }
            Err(err) => {
                error!("{:?}", ShutdownError::Join(err));
            }
        }
    }
}

/// Helper function to return a shutdown channel
pub fn shutdown_channel() -> ShutdownChan {
    oneshot::channel::<()>()
}

#[derive(Error)]
pub enum ShutdownError {
    #[error("channel")]
    Channel(#[from] ChannelError),
    #[error(transparent)]
    Spawned(#[from] SpawnedError),

    #[error("join")]
    Join(#[from] tokio::task::JoinError),
}

impl_debug_error_chain!(ShutdownError, "shutdown");

impl From<()> for ShutdownError {
    fn from(_err: ()) -> Self {
        Self::Channel(ChannelError::OneshotSend("shutdown"))
    }
}
