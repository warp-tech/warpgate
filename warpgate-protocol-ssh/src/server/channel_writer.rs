use russh::server::Handle;
use russh::{ChannelId, CryptoVec};
use tokio::sync::mpsc;

/// Sequences data writes and runs them in background to avoid lockups
pub struct ChannelWriter {
    tx: mpsc::UnboundedSender<(Handle, ChannelId, CryptoVec)>,
}

impl ChannelWriter {
    pub fn new() -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<(Handle, ChannelId, CryptoVec)>();
        tokio::spawn(async move {
            while let Some((handle, channel, data)) = rx.recv().await {
                let _ = handle.data(channel, data).await;
            }
        });
        ChannelWriter { tx }
    }

    pub fn write(&self, handle: Handle, channel: ChannelId, data: CryptoVec) {
        let _ = self.tx.send((handle, channel, data));
    }
}
