use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use bytes::Bytes;
use futures::stream::{FuturesOrdered, StreamExt};
use tokio::sync::mpsc;
use tracing::{Instrument, debug, info_span, warn};
use warpgate_common::{TargetOptions, UserSessionId, WarpgateError};
use warpgate_core::recordings::{DesktopRecorder, DesktopRecordingMetadata};
use warpgate_core::{DesktopEvent, Services, State, TargetAuthorization, UserSessionStateInit};
use warpgate_db_entities::Target::TargetKind;
use warpgate_web_clients_common::{ClientManager, SessionRemover, WebSessionHandle};

use crate::dirty::DirtyTracker;
use crate::protocol::ServerMessage;
use crate::session::WebDesktopSession;

const MAX_SESSIONS_PER_USER: usize = 50;

#[derive(Default)]
pub struct WebDesktopClientManager(ClientManager<WebDesktopSession>);

impl std::ops::Deref for WebDesktopClientManager {
    type Target = ClientManager<WebDesktopSession>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl SessionRemover for WebDesktopClientManager {
    async fn remove_session(&self, id: UserSessionId) {
        self.0.remove_session(id).await;
    }
}

impl WebDesktopClientManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn create_session(
        &self,
        services: &Services,
        authorization: TargetAuthorization,
        remote_address: Option<SocketAddr>,
        size: Option<(u16, u16)>,
    ) -> Result<UserSessionId, WarpgateError> {
        let user_id = authorization.user_info().id;
        if self.count_for_user(user_id).await >= MAX_SESSIONS_PER_USER {
            return Err(WarpgateError::SessionLimitReached);
        }

        let username = authorization.user_info().username.clone();
        let target_name = authorization.target().name.clone();
        let target_kind = TargetKind::from(&authorization.target().options);
        let protocol_name = match &authorization.target().options {
            TargetOptions::Vnc(_) => warpgate_protocol_vnc::PROTOCOL_NAME,
            TargetOptions::Rdp(_) => warpgate_protocol_rdp::PROTOCOL_NAME,
            _ => return Err(WarpgateError::InvalidTarget),
        };

        let (handle_abort_tx, mut handle_abort_rx) = mpsc::unbounded_channel::<()>();
        let session_handle = WebSessionHandle::new(handle_abort_tx);

        let server_handle = State::register_node_local_user_session(
            &services.state,
            protocol_name,
            UserSessionStateInit {
                remote_address,
                handle: Box::new(session_handle),
            },
        )
        .await
        .context("registering web-desktop session")?;

        let (target_session_id, approved) = server_handle
            .lock()
            .await
            .start_target_session(authorization)
            .await
            .context("starting target session")?
            .admitted()?;

        let session_id = server_handle.lock().await.user_session_id();

        // Each backend exposes the same (event_rx, input_tx, abort_tx) handle shape
        // over the shared DesktopEvent/DesktopInput types. The trailing flag asks the
        // event loop to re-encode raw tiles as JPEG for the browser.
        let (event_rx, input_tx, abort_tx, encode_jpeg) = match target_kind {
            TargetKind::Vnc => {
                let h = warpgate_protocol_vnc::connect(approved.narrow()?)?;
                // Tight already picks JPEG for photographic tiles and keeps text and UI
                // lossless, so re-encoding what it deliberately sent as raw would only
                // degrade it.
                (h.event_rx, h.input_tx, h.abort_tx, false)
            }
            TargetKind::Rdp => {
                // Connect at the viewer's measured size when known, so the desktop fits the
                // browser from the first frame; the DVC resize path handles later changes.
                let h = warpgate_protocol_rdp::connect(
                    approved.narrow()?,
                    size.unwrap_or(warpgate_protocol_rdp::DEFAULT_SIZE),
                )?;
                // The RDP helper only ever emits raw RGBA.
                (h.event_rx, h.input_tx, h.abort_tx, true)
            }
            _ => return Err(WarpgateError::InvalidTarget),
        };

        // Start a desktop recording (no-op if recording is disabled in config). Shared
        // (Arc) between the session — which records viewer input — and the event loop,
        // which records framebuffer updates; the recording finalises when both drop.
        let recorder: Option<Arc<DesktopRecorder>> = match services
            .recordings
            .start::<DesktopRecorder, _>(&target_session_id, None, DesktopRecordingMetadata::Desktop)
            .await
        {
            Ok(recorder) => Some(Arc::new(recorder)),
            Err(warpgate_core::recordings::Error::Disabled) => None,
            Err(error) => {
                warn!(%error, "Failed to start desktop recording");
                None
            }
        };

        let session = Arc::new(WebDesktopSession::new(
            session_id,
            user_id,
            target_name.clone(),
            target_kind,
            server_handle,
            input_tx,
            abort_tx,
            recorder.clone(),
        ));

        // Admin-initiated close: stop the backend and mark the session dead. Holds a
        // Weak ref so this task never keeps the session — and thus its
        // WarpgateServerHandle — alive; otherwise the handle would never drop and the
        // session would never be marked closed (in the DB or the active-session list).
        tokio::spawn({
            let session = Arc::downgrade(&session);
            async move {
                if handle_abort_rx.recv().await.is_some()
                    && let Some(session) = session.upgrade()
                {
                    session.abort();
                    session.close();
                }
            }
        });

        self.insert(session.clone()).await;

        spawn_event_loop(
            session.clone(),
            event_rx,
            self.0.clone(),
            recorder,
            encode_jpeg,
        );

        debug!(session=%session_id, user=%username, target=%target_name, "Web-desktop session created");

        Ok(session_id)
    }
}

/// Record an event, then send it. Both the live stream and refinements go out this way, so
/// a recording plays back at the same progressive quality the viewer saw. `raw` carries a
/// re-encoded tile's original pixels, letting the recorder composite without a decode.
async fn emit(
    session: &WebDesktopSession,
    recorder: Option<&DesktopRecorder>,
    event: DesktopEvent,
    raw: Option<&Bytes>,
) {
    if let Some(recorder) = recorder {
        let result = match (&event, raw) {
            (DesktopEvent::JpegImage { rect, data }, Some(raw)) => {
                recorder.write_jpeg_with_raw(*rect, data, raw).await
            }
            _ => recorder.write_event(&event).await,
        };
        if let Err(error) = result {
            warn!(%error, "Failed to record desktop event");
        }
    }
    session.push(ServerMessage::from(event)).await;
}

/// How many events may sit between receipt and emission. Tiles inside this window JPEG-
/// encode concurrently on the blocking pool while emission stays in arrival order; past
/// it, receiving pauses so a slow encoder or recorder backpressures the backend.
const MAX_PIPELINED_EVENTS: usize = 8;

/// An event ready to emit, with the original pixels of a re-encoded tile (see [`emit`]).
type PreparedEvent = (DesktopEvent, Option<Bytes>);

fn prepare(
    event: DesktopEvent,
    encode_jpeg: bool,
) -> Pin<Box<dyn Future<Output = PreparedEvent> + Send>> {
    if encode_jpeg {
        Box::pin(crate::jpeg::encode_raw_images(event))
    } else {
        Box::pin(std::future::ready((event, None)))
    }
}

fn spawn_event_loop(
    session: Arc<WebDesktopSession>,
    mut event_rx: mpsc::Receiver<warpgate_core::DesktopEvent>,
    manager: ClientManager<WebDesktopSession>,
    recorder: Option<Arc<DesktopRecorder>>,
    encode_jpeg: bool,
) {
    let session_id = session.id();
    let span = info_span!("web-desktop", session=%session_id);
    tokio::spawn(
        async move {
            // Only the JPEG path loses detail, so only it has anything to refine.
            let mut dirty = DirtyTracker::new();
            // Events between receipt and emission. Composited immediately, JPEG-encoded
            // concurrently, emitted strictly in arrival order.
            let mut pipeline: FuturesOrdered<_> = FuturesOrdered::new();
            let mut backend_done = false;
            loop {
                if backend_done && pipeline.is_empty() {
                    break;
                }
                // No pending regions means nothing to wake up for; park on the far future
                // rather than spinning, and let an incoming event arm the timer.
                let next_due = dirty.next_due();
                let refine = async {
                    match next_due {
                        Some(due) => tokio::time::sleep_until(due.into()).await,
                        None => std::future::pending().await,
                    }
                };

                tokio::select! {
                    event = event_rx.recv(), if !backend_done && pipeline.len() < MAX_PIPELINED_EVENTS => {
                        let Some(event) = event else {
                            backend_done = true;
                            continue;
                        };
                        // Composite before any re-encoding, so this is a plain blit rather
                        // than a JPEG decode round-trip. Gives a viewer attaching later a
                        // base image, and is the source the refinement reads back from.
                        session.composite(&event).await;
                        // Ahead of the recorder, so recordings shrink along with the wire.
                        pipeline.push_back(prepare(event, encode_jpeg));
                    }
                    Some((event, raw)) = pipeline.next(), if !pipeline.is_empty() => {
                        match &event {
                            DesktopEvent::Resize { width, height } => {
                                dirty.resize(*width, *height);
                            }
                            DesktopEvent::JpegImage { rect, .. } if encode_jpeg => {
                                dirty.touch(*rect, Instant::now());
                            }
                            _ => {}
                        }
                        emit(&session, recorder.as_deref(), event, raw.as_ref()).await;
                    }
                    // Gated on an empty pipeline: a refinement snapshots the composited
                    // surface, which is ahead of anything still awaiting emission — sent
                    // sooner, its newer pixels would be overwritten by the older tiles
                    // behind it.
                    () = refine, if pipeline.is_empty() => {
                        for rect in dirty.take_settled(Instant::now()) {
                            match session.refinement(rect).await {
                                Some(event) => {
                                    debug!(?rect, "Refining settled region");
                                    emit(&session, recorder.as_deref(), event, None).await;
                                }
                                // The region left the surface (resize)
                                // or failed to encode
                                None => debug!(?rect, "Settled region no longer refinable"),
                            }
                        }
                    }
                }
            }
            // Backend ended; dropping `recorder` here finalises the recording.
            session.close();
            manager.remove_session(session_id).await;
        }
        .instrument(span),
    );
}
