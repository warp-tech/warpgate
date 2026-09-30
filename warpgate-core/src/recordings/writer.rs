use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait};
use serde::Serialize;
use time::OffsetDateTime;
use tokio::sync::{Mutex, RwLock, broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::error;
use uuid::Uuid;
use warpgate_db_entities::Recording;

use super::storage::{RecordingSink, RecordingSinkCleanupGuard};
use super::{Error, LiveMap, Result};

pub struct WriterShutdown {
    pub token: CancellationToken,
    pub tracker: TaskTracker,
}

/// A recording's files (e.g. `data.ndjson` and `index.ndjson`) each finalize in
/// their own writer task, but `ended` is one flag for all of them and readers
/// switch to S3 on it. So only the last writer to finish may set it, and every
/// scratch copy has to outlive it.
#[derive(Default)]
pub struct RecordingCompletion {
    /// Writers still running, plus any recorder still opening its files: a
    /// recorder that fails half-way must not let its first file end the recording.
    open_writers: usize,
    failed: bool,
    cleanup: Vec<RecordingSinkCleanupGuard>,
}

impl RecordingCompletion {
    const fn hold(&mut self) {
        self.open_writers += 1;
    }
}

/// Keeps a recording from ending while its recorder opens its files. Only
/// [`Self::open`] gives the hold back: dropped any other way (the recorder
/// failed, its future was cancelled or panicked) the recording can never end,
/// so it stays unended with its scratch kept.
pub struct ConstructionHold(Arc<Mutex<RecordingCompletion>>);

impl ConstructionHold {
    pub async fn new(completion: Arc<Mutex<RecordingCompletion>>) -> Self {
        completion.lock().await.hold();
        Self(completion)
    }

    pub async fn open(self, db: &DatabaseConnection, id: Uuid) {
        release(&self.0, false, None, db, id).await;
    }
}

impl Drop for RecordingCompletion {
    /// A recording that never ended is read from its scratch, so keep it.
    fn drop(&mut self) {
        self.cleanup
            .drain(..)
            .for_each(RecordingSinkCleanupGuard::keep);
    }
}

/// Give up a [`RecordingCompletion::hold`]. The last one out marks the
/// recording ended, unless anything failed.
pub async fn release(
    completion: &Mutex<RecordingCompletion>,
    failed: bool,
    cleanup: Option<RecordingSinkCleanupGuard>,
    db: &DatabaseConnection,
    id: Uuid,
) {
    let mut completion = completion.lock().await;
    completion.open_writers = completion.open_writers.saturating_sub(1);
    completion.failed |= failed;
    completion.cleanup.extend(cleanup);
    if completion.open_writers > 0 || completion.failed {
        return;
    }

    let ended = async {
        use sea_orm::ActiveValue::Set;

        let recording = Recording::Entity::find_by_id(id)
            .one(db)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Recording not found"))?;
        let mut model: Recording::ActiveModel = recording.into();
        model.ended = Set(Some(OffsetDateTime::now_utc()));
        model.update(db).await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;

    match ended {
        Ok(()) => completion.cleanup.clear(),
        Err(error) => error!(%error, "Failed to write recording"),
    }
}

/// Capacity of both the disk-write queue and the live broadcast ring. They must
/// stay equal: the live-stream lag heal relies on any item dropped from the
/// broadcast ring already having left the disk queue (so it is on disk, or at
/// most one item is mid-write). That holds only because a producer blocks on the
/// full disk queue before it can broadcast, so the ring cannot outrun the queue
/// by more than its own capacity. Raising the ring above the queue breaks it.
const RECORDING_QUEUE_CAPACITY: usize = 1024;

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
    /// Running byte offset to hand out. Live viewers rely on this matching the
    /// on-disk byte order, which holds because every write to a recording is
    /// serialized by `NDJsonRecordingWriter`'s `buf` lock: that writer is not
    /// `Clone`, so tasks share the one instance (through an `Arc`) and its single
    /// lock, and the counter can't diverge from disk order.
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
        completion: Arc<Mutex<RecordingCompletion>>,
    ) -> Result<Self> {
        completion.lock().await.hold();
        let (sender, mut receiver) = mpsc::channel::<Bytes>(RECORDING_QUEUE_CAPACITY);
        let (drop_signal, mut drop_receiver) = mpsc::channel(1);
        let WriterShutdown { token, tracker } = shutdown;

        // Register in the live-subscription map only when this file is the live stream
        // (see `RecordingWriterOpener::open`). Sidecars pass `None` so they don't clobber
        // the data writer's entry, which shares the same recording id.
        let live_sender = broadcast::channel(RECORDING_QUEUE_CAPACITY).0;
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
            let written = async {
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
                Ok::<(), Error>(())
            }
            .await;
            if let Err(error) = &written {
                error!(%error, "Failed to write recording");
            }

            // Complete the S3 object before the recording is marked ended, so a
            // reader that switches to S3 on `ended` always finds the object. On
            // failure the local scratch is kept (the recording is at least not lost).
            let finalized = sink.finalize().await;
            if let Err(error) = &finalized {
                error!(%error, "Failed to write recording");
            }
            release(
                &completion,
                written.is_err() || finalized.is_err(),
                finalized.ok(),
                &db,
                model.id,
            )
            .await;
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
