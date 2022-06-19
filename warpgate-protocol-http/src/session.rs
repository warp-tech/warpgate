use crate::session_handle::HttpSessionHandle;
use poem::session::Session;
use poem::web::{Data, RemoteAddr};
use poem::{FromRequest, Request};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use warpgate_common::{Services, SessionId, SessionState, WarpgateServerHandle};

pub struct SessionMiddleware {
    session_handles: HashMap<SessionId, WarpgateServerHandle>,
}

static SESSION_ID_SESSION_KEY: &str = "session_id";

impl SessionMiddleware {
    pub fn new() -> Self {
        Self {
            session_handles: HashMap::new(),
        }
    }

    pub async fn process_request(&mut self, req: Request) -> poem::Result<Request> {
        let services: Data<&Services> = <_>::from_request_without_body(&req).await?;
        let session: &Session = <_>::from_request_without_body(&req).await?;

        if let Some(session_id) = session.get::<Option<SessionId>>(SESSION_ID_SESSION_KEY) {
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
                .register_session(&session_state)
                .await?;

                let id = server_handle.id();
            self.session_handles.insert(id, server_handle);

            session.set(SESSION_ID_SESSION_KEY, id);
        }

        Ok(req)
    }

    pub fn handle_for(&self, session: &Session) -> Option<WarpgateServerHandle> {
        session
            .get::<SessionId>(SESSION_ID_SESSION_KEY)
            .and_then(|id| self.session_handles.get(&id).cloned())
    }
}
