use crate::common::SESSION_MAX_AGE;
use crate::session_handle::HttpSessionHandle;
use poem::session::Session;
use poem::web::{Data, RemoteAddr};
use poem::{FromRequest, Request};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use warpgate_common::{Services, SessionId, SessionState, WarpgateServerHandle};

pub struct SessionMiddleware {
    session_handles: HashMap<SessionId, Arc<Mutex<WarpgateServerHandle>>>,
    session_timestamps: HashMap<SessionId, Instant>,
}

static SESSION_ID_SESSION_KEY: &str = "session_id";

impl SessionMiddleware {
    pub fn new() -> Self {
        Self {
            session_handles: HashMap::new(),
            session_timestamps: HashMap::new(),
        }
    }

    pub async fn process_request(&mut self, req: Request) -> poem::Result<Request> {
        let services: Data<&Services> = <_>::from_request_without_body(&req).await?;
        let session: &Session = <_>::from_request_without_body(&req).await?;

        let session_id: SessionId =
            if let Some(session_id) = session.get::<SessionId>(SESSION_ID_SESSION_KEY) {
                session_id
            } else {
                let remote_address: &RemoteAddr = <_>::from_request_without_body(&req).await?;

                let (session_handle, session_handle_rx) = HttpSessionHandle::new();
                let session_state = Arc::new(Mutex::new(SessionState::new(
                    remote_address.0.as_socket_addr().cloned(),
                    Box::new(session_handle),
                )));

                let server_handle = services
                    .state
                    .lock()
                    .await
                    .register_session(&crate::PROTOCOL_NAME, &session_state)
                    .await?;

                let id = server_handle.lock().await.id();
                self.session_handles.insert(id, server_handle);

                session.set(SESSION_ID_SESSION_KEY, id);

                id
            };

        self.session_timestamps.insert(session_id, Instant::now());

        Ok(req)
    }

    pub fn handle_for(&self, session: &Session) -> Option<Arc<Mutex<WarpgateServerHandle>>> {
        session
            .get::<SessionId>(SESSION_ID_SESSION_KEY)
            .and_then(|id| self.session_handles.get(&id).cloned())
    }

    pub async fn vacuum(&mut self) {
        let now = Instant::now();
        let mut to_remove = vec![];
        for (id, timestamp) in self.session_timestamps.iter() {
            if now.duration_since(*timestamp) > SESSION_MAX_AGE {
                to_remove.push(*id);
            }
        }
        for id in to_remove {
            self.session_handles.remove(&id);
            self.session_timestamps.remove(&id);
        }
    }
}
