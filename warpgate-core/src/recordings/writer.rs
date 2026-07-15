use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait};
use serde::Serialize;
use time::OffsetDateTime;
use tokio::sync::{RwLock, broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::error;
use warpgate_common::try_block;
use warpgate_db_entities::Recording;

use super::storage::RecordingSink;
use super::{Error, LiveMap, Result};

pub(crate) struct WriterShutdown {
    pub token: CancellationToken,
    pub tracker: TaskTracker,
}

/// One item of a recording's primary data stream, broadcast to live viewers.
/// `offset` is the total bytes written through this item (its end position in
/// `data.ndjson`), so a viewer that loaded a snapshot covering the first `N`
/// bytes keeps only chunks with `offset > N` — splicing the live tail onto the
/// snapshot with neither a gap nor a duplicate. Both players use this: the
/// snapshot boundary is the `Content-Length` of the raw file they fetched.
#[derive(Clone, Debug)]
pub struct LiveChunk {
    pub offset: u64,
    pub data: Bytes,
}

#[derive(Clone)]
pub struct RawRecordingWriter {
    sender: mpsc::Sender<Bytes>,
    live_sender: broadcast::Sender<LiveChunk>,
    /// Running byte offset to hand out, shared across clones of this writer so
    /// the stream is numbered consistently regardless of which clone writes.
    offset: Arc<AtomicU64>,
    drop_signal: mpsc::Sender<()>,
}

impl RawRecordingWriter {
    pub(crate) async fn new(
        mut sink: RecordingSink,
        model: Recording::Model,
        db: DatabaseConnection,
        live: Option<LiveMap>,
        shutdown: WriterShutdown,
    ) -> Result<Self> {
        let (sender, mut receiver) = mpsc::channel::<Bytes>(1024);
        let (drop_signal, mut drop_receiver) = mpsc::channel(1);
        let WriterShutdown { token, tracker } = shutdown;

        // Register in the live-subscription map only when this file is the live stream
        // (see `RecordingWriterOpener::open`). Sidecars pass `None` so they don't clobber
        // the data writer's entry, which shares the same recording id.
        let live_sender = broadcast::channel(1024).0;
        if let Some(live) = live {
            {
                let mut live = live.lock().await;
                live.insert(model.id, live_sender.clone());
            }
            tokio::spawn({
                let id = model.id;
                async move {
                    let _ = drop_receiver.recv().await;
                    let mut live = live.lock().await;
                    live.remove(&id);
                }
            });
        }

        tracker.spawn(async move {
            try_block!(async {
                let mut last_flush = Instant::now();
                loop {
                    if last_flush.elapsed() > Duration::from_secs(5) {
                        last_flush = Instant::now();
                        sink.flush().await?;
                    }
                    tokio::select! {
                        data = receiver.recv() => match data {
                            Some(bytes) => {
                                sink.write_all(&bytes).await?;
                            }
                            None => break,
                        },
                        () = token.cancelled() => break,
                        () = tokio::time::sleep(Duration::from_millis(5000)) => ()
                    }
                }

                // Drain receiver in case writer was shut down
                while let Ok(bytes) = receiver.try_recv() {
                    sink.write_all(&bytes).await?;
                }
                Ok::<(), anyhow::Error>(())
            } catch (error: anyhow::Error) {
                error!(%error, "Failed to write recording");
            });

            // Complete the S3 object before the recording is marked ended, so a
            // reader that switches to S3 on `ended` always finds the object. On
            // failure the local scratch is kept (the recording is at least not lost).

            try_block!(async {
                use sea_orm::ActiveValue::Set;

                let cleanup_guard = sink.finalize().await?;

                let id = model.id;
                let db = &db;
                let recording = Recording::Entity::find_by_id(id)
                    .one(db)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("Recording not found"))?;
                let mut model: Recording::ActiveModel = recording.into();
                model.ended = Set(Some(OffsetDateTime::now_utc()));
                model.update(db).await?;

                drop(cleanup_guard);

                Ok::<(), anyhow::Error>(())
            } catch (error: anyhow::Error) {
                error!(%error, "Failed to write recording");
            });
        });

        Ok(Self {
            sender,
            live_sender,
            offset: Arc::new(AtomicU64::new(0)),
            drop_signal,
        })
    }

    pub async fn write(&self, data: &[u8]) -> Result<()> {
        let data = Bytes::from(data.to_vec());
        self.sender
            .send(data.clone())
            .await
            .map_err(|_| Error::Closed)?;
        // Tag with the end byte offset (bytes written through this item) after it
        // is durably queued, so a live viewer's offset matches the on-disk order.
        let offset = self.offset.fetch_add(data.len() as u64, Ordering::SeqCst) + data.len() as u64;
        let _ = self.live_sender.send(LiveChunk { offset, data });
        Ok(())
    }
}

impl Drop for RawRecordingWriter {
    fn drop(&mut self) {
        let signal = std::mem::replace(&mut self.drop_signal, mpsc::channel(1).0);
        tokio::spawn(async move { signal.send(()).await });
    }
}

pub struct NDJsonRecordingWriter {
    pub(crate) inner: RawRecordingWriter,
    buf: RwLock<Vec<u8>>,
}

impl Clone for NDJsonRecordingWriter {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            buf: RwLock::new(Vec::new()),
        }
    }
}

impl NDJsonRecordingWriter {
    pub(crate) fn new(inner: RawRecordingWriter) -> Self {
        Self {
            inner,
            buf: RwLock::new(Vec::new()),
        }
    }

    pub async fn write_json_line<I: Serialize>(&self, value: I) -> Result<usize> {
        let buf = &mut self.buf.write().await;
        buf.clear();
        serde_json::to_writer(&mut **buf, &value).map_err(Error::Serialization)?;
        buf.push(b'\n');
        self.inner.write(buf).await?;
        Ok(buf.len())
    }
}
