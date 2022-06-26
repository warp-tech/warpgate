use crate::common::SESSION_MAX_AGE;
use crate::session_handle::{HttpSessionHandle, SessionHandleCommand};
use poem::session::{Session, SessionStorage};
use poem::web::{Data, RemoteAddr};
use poem::{FromRequest, Request};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use warpgate_common::{Services, SessionId, SessionState, WarpgateServerHandle};

#[derive(Clone)]
pub struct SharedSessionStorage(pub Arc<Mutex<Box<dyn SessionStorage>>>);

static POEM_SESSION_ID_SESSION_KEY: &str = "poem_session_id";

#[async_trait::async_trait]
impl SessionStorage for SharedSessionStorage {
    async fn load_session(
        &self,
        session_id: &str,
    ) -> poem::Result<Option<BTreeMap<String, Value>>> {
        self.0.lock().await.load_session(session_id).await.map(|o| {
            o.map(|mut s| {
                s.insert(
                    POEM_SESSION_ID_SESSION_KEY.to_string(),
                    session_id.to_string().into(),
                );
                s
            })
        })
    }

    async fn update_session(
        &self,
        session_id: &str,
        entries: &BTreeMap<String, Value>,
        expires: Option<Duration>,
    ) -> poem::Result<()> {
        self.0
            .lock()
            .await
            .update_session(session_id, entries, expires)
            .await
    }

    async fn remove_session(&self, session_id: &str) -> poem::Result<()> {
        self.0.lock().await.remove_session(session_id).await
    }
}

pub struct SessionMiddleware {
    session_handles: HashMap<SessionId, Arc<Mutex<WarpgateServerHandle>>>,
    session_timestamps: HashMap<SessionId, Instant>,
    this: Weak<Mutex<SessionMiddleware>>,
}

static SESSION_ID_SESSION_KEY: &str = "session_id";
static SESSION_ID_REQUEST_COUNTER: &str = "request_counter";

impl SessionMiddleware {
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new_cyclic(|me| {
            Mutex::new(Self {
                session_handles: HashMap::new(),
                session_timestamps: HashMap::new(),
                this: me.clone(),
            })
        })
    }

    pub async fn process_request(&mut self, req: Request) -> poem::Result<Request> {
        let services: Data<&Services> = <_>::from_request_without_body(&req).await?;
        let session: &Session = <_>::from_request_without_body(&req).await?;
        let session_storage: Data<&SharedSessionStorage> =
            <_>::from_request_without_body(&req).await?;

            let request_counter = session.get::<u64>(SESSION_ID_REQUEST_COUNTER).unwrap_or(0);
            session.set(SESSION_ID_REQUEST_COUNTER, request_counter + 1);

        if let Some(session_id) =
            session.get::<SessionId>(SESSION_ID_SESSION_KEY)
        {
            self.session_timestamps.insert(session_id, Instant::now());
        } else if request_counter > 1 {
            let remote_address: &RemoteAddr = <_>::from_request_without_body(&req).await?;

            let (session_handle, mut session_handle_rx) = HttpSessionHandle::new();
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

            let this = self.this.upgrade().unwrap();
            tokio::spawn({
                let session_storage = (*session_storage).clone();
                let poem_session_id: Option<String> = session.get(POEM_SESSION_ID_SESSION_KEY);
                let id = id.clone();
                async move {
                    while let Some(command) = session_handle_rx.recv().await {
                        match command {
                            SessionHandleCommand::Close => {
                                if let Some(ref poem_session_id) = poem_session_id {
                                    let _ = session_storage.remove_session(&poem_session_id).await;
                                }
                                this.lock().await.session_handles.remove(&id);
                            }
                        }
                    }
                    Ok::<_, anyhow::Error>(())
                }
            });

            self.session_timestamps.insert(id, Instant::now());
        };


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
