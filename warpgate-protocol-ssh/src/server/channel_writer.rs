use russh::server::Handle;
use russh::{ChannelId, CryptoVec};
use tokio::sync::mpsc;

#[derive(Debug)]
enum ChannelWriteOperation {
    Data(Handle, ChannelId, CryptoVec),
    ExtendedData(Handle, ChannelId, u32, CryptoVec),
}

/// Sequences data writes and runs them in background to avoid lockups
pub struct ChannelWriter {
    tx: mpsc::UnboundedSender<ChannelWriteOperation>,
}

impl ChannelWriter {
    pub fn new() -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<ChannelWriteOperation>();
        tokio::spawn(async move {
            while let Some(operation) = rx.recv().await {
                match operation {
                    ChannelWriteOperation::Data(handle, channel, data) => {
                        let _ = handle.data(channel, data).await;
                    }
                    ChannelWriteOperation::ExtendedData(handle, channel, ext, data) => {
                        let _ = handle.extended_data(channel, ext, data).await;
                    }
                }
            }
        });
        ChannelWriter { tx }
    }

    pub fn write(&self, handle: Handle, channel: ChannelId, data: CryptoVec) {
        let _ = self
            .tx
            .send(ChannelWriteOperation::Data(handle, channel, data));
    }

    pub fn write_extended(&self, handle: Handle, channel: ChannelId, ext: u32, data: CryptoVec) {
        let _ = self.tx.send(ChannelWriteOperation::ExtendedData(
            handle, channel, ext, data,
        ));
    }
}
