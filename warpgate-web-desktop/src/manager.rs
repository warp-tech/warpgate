use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, anyhow};
use tokio::sync::{Mutex, mpsc};
use tracing::{Instrument, debug, info_span, warn};
use uuid::Uuid;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{Target, TargetOptions, WarpgateError};
use warpgate_core::recordings::{DesktopRecorder, DesktopRecordingMetadata};
use warpgate_core::{ConfigProvider, DesktopEvent, Services, SessionStateInit, State};
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
    async fn remove_session(&self, id: Uuid) {
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
        user_id: Uuid,
        username: &str,
        target_name: &str,
        remote_address: Option<SocketAddr>,
    ) -> Result<Uuid, WarpgateError> {
        if self.count_for_user(user_id).await >= MAX_SESSIONS_PER_USER {
            return Err(WarpgateError::SessionLimitReached);
        }

        let target: Target = {
            services
                .config_provider
                .get_target_by_name(target_name)
                .await?
                .ok_or_else(|| anyhow!("Desktop target {target_name:?} not found"))?
        };

        let protocol_name = match &target.options {
            TargetOptions::Vnc(_) => warpgate_protocol_vnc::PROTOCOL_NAME,
            TargetOptions::Rdp(_) => warpgate_protocol_rdp::PROTOCOL_NAME,
            _ => return Err(WarpgateError::InvalidTarget),
        };

        let (handle_abort_tx, mut handle_abort_rx) = mpsc::unbounded_channel::<()>();
        let session_handle = WebSessionHandle::new(handle_abort_tx);

        let server_handle = State::register_session(
            &services.state,
            &protocol_name,
            SessionStateInit {
                remote_address,
                handle: Box::new(session_handle),
            },
        )
        .await
        .context("registering web-desktop session")?;

        {
            let server_handle = server_handle.lock().await;
            server_handle
                .set_user_info(AuthStateUserInfo {
                    id: user_id,
                    username: username.to_owned(),
                })
                .await
                .context("setting user info on server handle")?;
            server_handle
                .set_target(&target)
                .await
                .context("setting target on server handle")?;
        }

        let session_id = server_handle.lock().await.id();
        let target_kind = TargetKind::from(&target.options);

        // Each backend exposes the same (event_rx, input_tx, abort_tx) handle shape
        // over the shared DesktopEvent/DesktopInput types. The trailing flag asks the
        // event loop to re-encode raw tiles as JPEG for the browser.
        let (event_rx, input_tx, abort_tx, encode_jpeg) = match target.options.clone() {
            TargetOptions::Vnc(options) => {
                let h = warpgate_protocol_vnc::connect(options);
                // Tight already picks JPEG for photographic tiles and keeps text and UI
                // lossless, so re-encoding what it deliberately sent as raw would only
                // degrade it.
                (h.event_rx, h.input_tx, h.abort_tx, false)
            }
            TargetOptions::Rdp(options) => {
                // The browser canvas follows whatever size the target reports, so ask for
                // the helper's default rather than dictating one.
                let h =
                    warpgate_protocol_rdp::connect(options, warpgate_protocol_rdp::DEFAULT_SIZE);
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
            .lock()
            .await
            .start::<DesktopRecorder, _>(&session_id, None, DesktopRecordingMetadata::Desktop)
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
            target_name.to_owned(),
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
            self.sessions(),
            recorder,
            encode_jpeg,
        );

        debug!(session=%session_id, user=%username, target=%target_name, "Web-desktop session created");

        Ok(session_id)
    }
}

/// Record an event, then send it. Both the live stream and refinements go out this way, so
/// a recording plays back at the same progressive quality the viewer saw.
async fn emit(
    session: &WebDesktopSession,
    recorder: Option<&DesktopRecorder>,
    event: DesktopEvent,
) {
    if let Some(recorder) = recorder
        && let Err(error) = recorder.write_event(&event).await
    {
        warn!(%error, "Failed to record desktop event");
    }
    session.push(ServerMessage::from(event)).await;
}

fn spawn_event_loop(
    session: Arc<WebDesktopSession>,
    mut event_rx: mpsc::Receiver<warpgate_core::DesktopEvent>,
    sessions: Arc<Mutex<HashMap<Uuid, Arc<WebDesktopSession>>>>,
    recorder: Option<Arc<DesktopRecorder>>,
    encode_jpeg: bool,
) {
    let session_id = session.id();
    let span = info_span!("web-desktop", session=%session_id);
    tokio::spawn(
        async move {
            // Only the JPEG path loses detail, so only it has anything to refine.
            let mut dirty = DirtyTracker::new();
            loop {
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
                    event = event_rx.recv() => {
                        let Some(event) = event else { break };
                        // Composite before any re-encoding, so this is a plain blit rather
                        // than a JPEG decode round-trip. Gives a viewer attaching later a
                        // base image, and is the source the refinement reads back from.
                        session.composite(&event).await;

                        // Ahead of the recorder, so recordings shrink along with the wire.
                        let event = if encode_jpeg {
                            crate::jpeg::encode_raw_images(event).await
                        } else {
                            event
                        };

                        match &event {
                            DesktopEvent::Resize { width, height } => {
                                dirty.resize(*width, *height);
                            }
                            DesktopEvent::JpegImage { rect, .. } if encode_jpeg => {
                                dirty.touch(*rect, Instant::now());
                            }
                            _ => {}
                        }
                        emit(&session, recorder.as_deref(), event).await;
                    }
                    () = refine => {
                        for rect in dirty.take_settled(Instant::now()) {
                            match session.refinement(rect).await {
                                Some(event) => {
                                    debug!(?rect, "Refining settled region");
                                    emit(&session, recorder.as_deref(), event).await;
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
            sessions.lock().await.remove(&session_id);
        }
        .instrument(span),
    );
}
