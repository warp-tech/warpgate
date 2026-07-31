use anyhow::{Result, anyhow};
use russh::ChannelId;
use russh::server::Handle;
use tokio::sync::mpsc;

const CHANNEL_WRITE_QUEUE_CAPACITY: usize = 64;

#[derive(Debug)]
enum ChannelWriteOperation {
    Data(Handle, ChannelId, Vec<u8>),
    ExtendedData(Handle, ChannelId, u32, Vec<u8>),
    Flush(tokio::sync::oneshot::Sender<()>),
}

/// Sequences data writes and runs them in background to avoid lockups
pub struct ChannelWriter {
    tx: mpsc::Sender<ChannelWriteOperation>,
}

impl ChannelWriter {
    pub fn new() -> Self {
        let (tx, mut rx) = mpsc::channel::<ChannelWriteOperation>(CHANNEL_WRITE_QUEUE_CAPACITY);
        tokio::spawn(async move {
            while let Some(operation) = rx.recv().await {
                match operation {
                    ChannelWriteOperation::Data(handle, channel, data) => {
                        let _ = handle.data(channel, data).await;
                    }
                    ChannelWriteOperation::ExtendedData(handle, channel, ext, data) => {
                        let _ = handle.extended_data(channel, ext, data).await;
                    }
                    ChannelWriteOperation::Flush(reply) => {
                        let _ = reply.send(());
                    }
                }
            }
        });
        Self { tx }
    }

    async fn enqueue(&self, operation: ChannelWriteOperation) -> Result<()> {
        self.tx
            .send(operation)
            .await
            .map_err(|_| anyhow!("ChannelWriter task has stopped"))
    }

    pub async fn write<D: Into<Vec<u8>>>(
        &self,
        handle: Handle,
        channel: ChannelId,
        data: D,
    ) -> Result<()> {
        self.enqueue(ChannelWriteOperation::Data(handle, channel, data.into()))
            .await
    }

    pub async fn write_extended<D: Into<Vec<u8>>>(
        &self,
        handle: Handle,
        channel: ChannelId,
        ext: u32,
        data: D,
    ) -> Result<()> {
        self.enqueue(ChannelWriteOperation::ExtendedData(
            handle,
            channel,
            ext,
            data.into(),
        ))
        .await
    }

    /// Flush all pending writes. Returns when all previously queued operations have completed.
    pub async fn flush(&self) -> Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.enqueue(ChannelWriteOperation::Flush(tx)).await?;
        rx.await
            .map_err(|_| anyhow!("ChannelWriter flush failed"))?;
        Ok(())
    }
}
