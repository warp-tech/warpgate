use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use sea_orm::{ActiveModelTrait, DatabaseConnection, DbErr, EntityTrait};
use serde::Serialize;
use time::OffsetDateTime;
use tokio::sync::{Mutex, RwLock, broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::error;
use uuid::Uuid;
use warpgate_common::try_block;
use warpgate_db_entities::Recording;

use super::storage::{RecordingSink, RecordingSinkCleanupGuard};
use super::{Error, LiveMap, Result};

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
        live: Option<LiveMap>,
        shutdown: WriterShutdown,
        ticket: WriterTicket,
    ) -> Result<Self> {
        let recording_id = ticket.recording_id();
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
                live.insert(recording_id, live_sender.clone());
            }
            tokio::spawn({
                let id = recording_id;
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

            // On upload failure the local scratch is kept and `ended` is never set
            // (the recording is at least not lost).
            try_block!(async {
                let cleanup_guard = sink.finalize().await?;
                ticket.finished(cleanup_guard).await?;
                Ok::<(), Error>(())
            } catch (error: Error) {
                error!(%error, "Failed to finalize recording");
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

mod completion {
    use super::*;

    pub struct WriterShutdown {
        pub token: CancellationToken,
        pub tracker: TaskTracker,
    }

    /// One completion struct shared by multiple writers (index, data) of one recording
    /// Writers get completion tickets via register_writer and the last ticket to close finalizes the DB entry
    pub struct RecordingCompletion {
        db: DatabaseConnection,
        recording_id: Uuid,
        state: Mutex<CompletionState>,
    }

    #[derive(Default)]
    struct CompletionState {
        open_writers: usize,
        scratch_guards: Vec<RecordingSinkCleanupGuard>,
    }

    impl RecordingCompletion {
        pub fn new(db: DatabaseConnection, recording_id: Uuid) -> Arc<Self> {
            Arc::new(Self {
                db,
                recording_id,
                state: Mutex::default(),
            })
        }

        pub async fn register_writer(self: &Arc<Self>) -> WriterTicket {
            self.state.lock().await.open_writers += 1;
            WriterTicket {
                completion: self.clone(),
            }
        }
    }

    #[must_use]
    pub struct WriterTicket {
        completion: Arc<RecordingCompletion>,
    }

    impl WriterTicket {
        pub fn recording_id(&self) -> Uuid {
            self.completion.recording_id
        }

        /// Takes over the scratch guard and then drops them all together and finalizes recording
        /// once the last ticket is closed
        pub async fn finished(self, guard: RecordingSinkCleanupGuard) -> Result<()> {
            use sea_orm::ActiveValue::Set;

            let completion = &self.completion;
            let scratch_guards = {
                let mut state = completion.state.lock().await;
                state.scratch_guards.push(guard);
                state.open_writers = state.open_writers.saturating_sub(1);
                if state.open_writers > 0 {
                    return Ok(());
                }
                std::mem::take(&mut state.scratch_guards)
            };

            let recording = Recording::Entity::find_by_id(completion.recording_id)
                .one(&completion.db)
                .await?
                .ok_or_else(|| {
                    DbErr::RecordNotFound(format!("recording {}", completion.recording_id))
                })?;
            let mut model: Recording::ActiveModel = recording.into();
            model.ended = Set(Some(OffsetDateTime::now_utc()));
            model.update(&completion.db).await?;

            drop(scratch_guards);
            Ok(())
        }
    }
}

pub use completion::{RecordingCompletion, WriterShutdown, WriterTicket};
