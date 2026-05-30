use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, anyhow};
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tracing::{Instrument, debug, info_span};
use uuid::Uuid;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{Target, TargetOptions, WarpgateError};
use warpgate_core::{ConfigProvider, Services, SessionStateInit, State};
use warpgate_db_entities::Target::TargetKind;

use crate::protocol::ServerMessage;
use crate::session::{WebDesktopSession, WebDesktopSessionHandle};

const MAX_SESSIONS_PER_USER: usize = 50;

#[derive(Default)]
pub struct WebDesktopClientManager {
    sessions: Arc<Mutex<HashMap<Uuid, Arc<WebDesktopSession>>>>,
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
        {
            let sessions = self.sessions.lock().await;
            let user_session_count = sessions.values().filter(|s| s.user_id() == user_id).count();
            if user_session_count >= MAX_SESSIONS_PER_USER {
                return Err(WarpgateError::SessionLimitReached);
            }
        }

        let target: Target = {
            let mut cp = services.config_provider.lock().await;
            cp.list_targets()
                .await?
                .into_iter()
                .find(|t| t.name == target_name)
                .ok_or_else(|| anyhow!("Desktop target {target_name:?} not found"))?
        };

        let protocol_name = match &target.options {
            TargetOptions::Vnc(_) => warpgate_protocol_vnc::PROTOCOL_NAME,
            TargetOptions::Rdp(_) => warpgate_protocol_rdp::PROTOCOL_NAME,
            _ => return Err(WarpgateError::InvalidTarget),
        };

        let (handle_abort_tx, mut handle_abort_rx) = mpsc::unbounded_channel::<()>();
        let session_handle = WebDesktopSessionHandle::new(handle_abort_tx);

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
        // over the shared DesktopEvent/DesktopInput types.
        let (event_rx, input_tx, abort_tx) = match target.options.clone() {
            TargetOptions::Vnc(options) => {
                let h = warpgate_protocol_vnc::connect(options);
                (h.event_rx, h.input_tx, h.abort_tx)
            }
            TargetOptions::Rdp(options) => {
                let h = warpgate_protocol_rdp::connect(options);
                (h.event_rx, h.input_tx, h.abort_tx)
            }
            _ => return Err(WarpgateError::InvalidTarget),
        };

        let session = Arc::new(WebDesktopSession::new(
            session_id,
            user_id,
            target_name.to_owned(),
            target_kind,
            server_handle,
            input_tx,
            abort_tx,
        ));

        // Admin-initiated close: stop the backend and mark the session dead.
        tokio::spawn({
            let session = session.clone();
            async move {
                if handle_abort_rx.recv().await.is_some() {
                    session.abort();
                    session.close();
                }
            }
        });

        self.sessions
            .lock()
            .await
            .insert(session_id, session.clone());

        spawn_event_loop(session.clone(), event_rx, self.sessions.clone());

        debug!(session=%session_id, user=%username, target=%target_name, "Web-desktop session created");

        Ok(session_id)
    }

    pub async fn get_session(&self, id: Uuid) -> Option<Arc<WebDesktopSession>> {
        self.sessions.lock().await.get(&id).cloned()
    }

    pub async fn remove_session(&self, id: Uuid) {
        if let Some(session) = self.sessions.lock().await.remove(&id) {
            session.abort();
            session.close();
        }
    }
}

fn spawn_event_loop(
    session: Arc<WebDesktopSession>,
    mut event_rx: mpsc::Receiver<warpgate_core::DesktopEvent>,
    sessions: Arc<Mutex<HashMap<Uuid, Arc<WebDesktopSession>>>>,
) {
    let session_id = session.id();
    let span = info_span!("web-desktop", session=%session_id);
    tokio::spawn(
        async move {
            while let Some(event) = event_rx.recv().await {
                session.push_event(ServerMessage::from(event)).await;
            }
            // Backend ended.
            session.close();
            sessions.lock().await.remove(&session_id);
        }
        .instrument(span),
    );
}
